package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/safefile"
)

func TestVerifyRejectsDuplicateEntryProperties(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(t.TempDir(), "backup")
	m, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `"path":"database/shardlure.db"`, `"path":"database/shardlure.db","path":"database/shardlure.db"`, 1)
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), out); err == nil {
		t.Fatal("ambiguous repeated entry property accepted")
	}
}

func TestVerifyInspectsTheDatabaseWhoseChecksumWasVerified(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: out}); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(out, "database", "shardlure.db")
	replacement := changedDatabaseFixture(t, database)
	ops := nativeOperations()
	opens := 0
	ops.openFile = func(root *safefile.Root, name string) (*os.File, error) {
		if name == "database/shardlure.db" {
			opens++
			if opens == 2 {
				if err := os.Rename(replacement, database); err != nil {
					return nil, err
				}
			}
		}
		return root.OpenRegular(name)
	}
	if _, err := verifyWithOperations(context.Background(), out, ops); err == nil {
		t.Fatal("inspected replacement database after hashing different bytes")
	}
}

func changedDatabaseFixture(t *testing.T, input string) string {
	t.Helper()
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement.db")
	if err := os.WriteFile(replacement, raw, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", replacement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE actors SET notes='changed during verification'"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return replacement
}

func TestVerifyRejectsCorruptAndAmbiguousBundles(t *testing.T) {
	for _, kind := range []string{"corrupt", "missing", "duplicate", "escape", "incomplete", "unknown-format", "unknown-schema", "unexpected", "symlink", "hardlink", "sidecar", "marker", "negative", "wrong-count"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(t.TempDir(), "backup")
			m, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: out})
			if err != nil {
				t.Fatal(err)
			}
			blob := filepath.Join(out, "files", "evidence", "quarantine", fixtureHash())
			switch kind {
			case "corrupt":
				if err := os.WriteFile(blob, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(blob); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				m.Entries = append(m.Entries, m.Entries[0])
			case "escape":
				m.Entries[0].Path = "../outside"
			case "incomplete":
				m.Complete = false
			case "unknown-format":
				m.FormatVersion = 999
			case "unknown-schema":
				m.Schema = 999
			case "unexpected":
				if err := os.WriteFile(filepath.Join(out, "extra"), []byte("inert"), 0600); err != nil {
					t.Fatal(err)
				}
			case "sidecar":
				if err := os.WriteFile(filepath.Join(out, "database", "shardlure.db-wal"), []byte("inert"), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				if err := os.WriteFile(filepath.Join(out, ".incomplete"), []byte("incomplete"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte(inertEvidence), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(blob); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(outside, blob)
				} else {
					err = os.Link(outside, blob)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "negative":
				m.Entries[0].Bytes = -1
			case "wrong-count":
				m.TableCounts["events"] = 999
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "manifest.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(context.Background(), out); err == nil {
				t.Fatal("invalid bundle verified")
			}
		})
	}
}

func TestVerifyDoesNotWriteReadOnlyBundle(t *testing.T) {
	f := newFixture(t)
	out := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: out}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0500)
		}
		return os.Chmod(path, 0400)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	if _, err := Verify(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("verification changed manifest")
	}
}
