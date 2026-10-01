package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

// A failure after publication keeps the published output with its incomplete
// marker. A failure before it (including a raced destination, where the
// no-replace publish refused) removes this run's own staging directory, which
// holds a database snapshot, and touches nothing else (final audit M3).
func TestCreateFailureKeepsPublishedOutputAndRemovesStaging(t *testing.T) {
	wantPublished := map[string]bool{"no-space": false, "file-sync": false, "destination-race": false, "after-rename": true, "final-sync": true}
	for _, kind := range []string{"no-space", "file-sync", "after-rename", "destination-race", "final-sync"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			parentDir := t.TempDir()
			out := filepath.Join(parentDir, "backup")
			ops := nativeOperations()
			published := false
			switch kind {
			case "no-space":
				ops.copy = func(context.Context, string, io.Writer, io.Reader, int64) (int64, error) { return 0, syscall.ENOSPC }
			case "file-sync":
				ops.syncFile = func(*os.File) error { return syscall.EIO }
			case "after-rename":
				ops.publish = func(root *safefile.Root, a, b string) error {
					if err := root.PublishNoReplace(a, b); err != nil {
						return err
					}
					return safefile.ErrSync
				}
			case "destination-race":
				ops.publish = func(root *safefile.Root, a, b string) error {
					if err := os.Mkdir(out, 0700); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(out, "keep"), []byte("keep"), 0600); err != nil {
						return err
					}
					return root.PublishNoReplace(a, b)
				}
			case "final-sync":
				ops.publish = func(root *safefile.Root, a, b string) error {
					err := root.PublishNoReplace(a, b)
					published = err == nil
					return err
				}
				ops.syncDir = func(root *safefile.Root) error {
					if published {
						return safefile.ErrSync
					}
					return root.Sync()
				}
			}
			m, err := createWithOperations(context.Background(), CreateOptions{ConfigPath: f.Config, Output: out}, ops)
			if err == nil || m.Complete {
				t.Errorf("failed publication advertised completion: complete=%v error=%v", m.Complete, err)
			}
			if strings.Contains(err.Error(), f.Root) || strings.Contains(err.Error(), "never-send-fixture-value") {
				t.Fatal("private diagnostic leaked")
			}
			var failure *Failure
			if !errors.As(err, &failure) {
				t.Fatalf("not a Failure: %v", err)
			}
			entries, readErr := os.ReadDir(parentDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".incomplete") {
					t.Fatalf("staging directory %q left behind", e.Name())
				}
			}
			if !wantPublished[kind] {
				if failure.Staging != "" {
					t.Fatalf("removed staging still reported retained at %q", failure.Staging)
				}
				if kind == "destination-race" {
					if b, err := os.ReadFile(filepath.Join(out, "keep")); err != nil || string(b) != "keep" || len(entries) != 1 {
						t.Fatalf("raced destination touched (entries %d)", len(entries))
					}
				} else if len(entries) != 0 {
					t.Fatalf("output parent not left empty: %d entries", len(entries))
				}
				return
			}
			if failure.Staging != out {
				t.Fatalf("published output location lost: %q", failure.Staging)
			}
			if _, err := os.Stat(filepath.Join(failure.Staging, incompleteName)); err != nil {
				t.Fatalf("failure deleted recovery marker/material: %v", err)
			}
			if _, err := Verify(context.Background(), failure.Staging); err == nil {
				t.Fatal("incomplete output verified")
			}
		})
	}
}

func TestCreateSourcePrefixAndConcurrentChanges(t *testing.T) {
	for _, kind := range []string{"append", "truncate", "rotate", "replace-evidence", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(t.TempDir(), "backup")
			ops := nativeOperations()
			nativeCopy := ops.copy
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops.copy = func(ctx context.Context, role string, w io.Writer, r io.Reader, n int64) (int64, error) {
				done, err := nativeCopy(ctx, role, w, r, n)
				if err != nil {
					return done, err
				}
				if role == "cowrie-logs" {
					switch kind {
					case "append":
						file, err := os.OpenFile(f.SourceLog, os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							return done, err
						}
						_, err = file.WriteString("later inert suffix\n")
						file.Close()
						return done, err
					case "truncate":
						return done, os.Truncate(f.SourceLog, 1)
					case "rotate":
						if err := os.Rename(f.SourceLog, f.SourceLog+".rotated"); err != nil {
							return done, err
						}
						return done, os.WriteFile(f.SourceLog, []byte(inertLog), 0600)
					case "cancel":
						cancel()
					}
				}
				if role == "evidence" && kind == "replace-evidence" {
					name := filepath.Join(f.Evidence, "quarantine", fixtureHash())
					if err := os.Rename(name, name+".old"); err != nil {
						return done, err
					}
					return done, os.WriteFile(name, []byte(inertEvidence), 0600)
				}
				return done, nil
			}
			m, err := createWithOperations(ctx, CreateOptions{ConfigPath: f.Config, Output: out}, ops)
			if kind != "append" {
				if err == nil {
					t.Fatal("unstable source published")
				}
				if kind == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation identity lost: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range m.Entries {
				if e.Role == "cowrie-logs" {
					b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(e.Path)))
					if err != nil || string(b) != inertLog || e.PrefixBytes == nil || *e.PrefixBytes != int64(len(inertLog)) {
						t.Fatalf("incorrect declared log prefix: %v", err)
					}
				}
			}
			if _, err := Verify(context.Background(), out); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManifestLimitsBeforeMaterializingOrCopying(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(root, "manifest.json"), maxManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), root); !errors.Is(err, ErrManifestLimit) {
		t.Fatalf("oversized manifest not bounded: %v", err)
	}
	m := Manifest{FormatVersion: 1, Complete: true, Schema: store.LatestSnapshotSchema, CreatedAt: time.Now().UTC(), Entries: make([]Entry, maxManifestEntries+1)}
	if _, _, err := validateManifest(m); !errors.Is(err, ErrManifestLimit) {
		t.Fatalf("entry count not bounded: %v", err)
	}
}

func TestInventoryReservesJSONEscapedNames(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("\x01", 200)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := openSource(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.root.Close()
	catalog := inventory{names: map[string]int{}}
	if err := catalog.add(root, name, "files/evidence/"+name, "evidence", "", 0); err != nil {
		t.Fatal(err)
	}
	// Each U+0001 is six JSON bytes, not one byte of manifest capacity.
	if catalog.metadata < 1200 {
		t.Fatalf("escaped names bypass manifest allocation bound: reserved=%d", catalog.metadata)
	}
}
