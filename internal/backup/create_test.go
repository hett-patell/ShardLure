package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateVerifyProtectedBundle(t *testing.T) {
	fixture := newFixture(t)
	out := filepath.Join(t.TempDir(), "backup")
	manifest, err := Create(context.Background(), CreateOptions{ConfigPath: fixture.Config, Output: out, AppVersion: "test", AppCommit: "inert"})
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Complete || manifest.FormatVersion != 1 || manifest.Schema != 24 {
		t.Fatalf("unverified manifest: %+v", manifest)
	}
	report, err := Verify(context.Background(), out)
	if err != nil || report.TableCounts["events"] != 3 || report.TableCounts["artifacts"] != 2 {
		t.Fatalf("report=%+v %v", report, err)
	}
	blobs, logs := 0, 0
	for _, entry := range manifest.Entries {
		if entry.Role == "evidence" {
			blobs++
			if entry.SHA256 != fixtureHash() || entry.Bytes != int64(len(inertEvidence)) {
				t.Fatalf("evidence bytes differ: %+v", entry)
			}
		}
		if entry.Role == "cowrie-logs" {
			logs++
			if entry.PrefixBytes == nil || *entry.PrefixBytes != int64(len(inertLog)) || entry.ObservedAt.IsZero() {
				t.Fatal("source prefix provenance absent")
			}
		}
	}
	if blobs != 1 || logs != 1 {
		t.Fatalf("dedup/inventory blobs=%d logs=%d", blobs, logs)
	}
	if err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if d.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Errorf("unsafe bundle mode: %o", info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var events int
	events, err = fixture.Store.EventCount()
	if err != nil || events != 3 {
		t.Fatalf("source altered: %d %v", events, err)
	}
	if val, _, err := fixture.Store.GetAppSetting("fixture.key"); err != nil || val != "never-send-fixture-value" {
		t.Fatal("source setting changed")
	}
}

func TestCreateRefusesMissingEvidenceExistingTargetsAndOverlap(t *testing.T) {
	for _, kind := range []string{"missing-evidence", "existing", "overlap", "alias", "cancelled", "missing-config", "database-include"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(t.TempDir(), "backup")
			opts := CreateOptions{ConfigPath: f.Config, Output: out}
			ctx := context.Background()
			switch kind {
			case "missing-evidence":
				if err := os.Remove(filepath.Join(f.Evidence, "quarantine", fixtureHash())); err != nil {
					t.Fatal(err)
				}
			case "existing":
				if err := os.Mkdir(out, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(out, "keep"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "overlap":
				opts.Output = filepath.Join(f.Evidence, "nested-backup")
			case "alias":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(f.Evidence, alias); err != nil {
					t.Fatal(err)
				}
				opts.Output = filepath.Join(alias, "backup")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-config":
				opts.ConfigPath = filepath.Join(f.Root, "missing.yaml")
			case "database-include":
				opts.IncludeFiles = []string{filepath.Join(f.Root, "shardlure.db")}
			}
			_, err := Create(ctx, opts)
			if err == nil {
				t.Fatal("unsafe/incomplete creation succeeded")
			}
			if strings.Contains(err.Error(), "never-send-fixture-value") || strings.Contains(err.Error(), f.Root) {
				t.Fatalf("private diagnostic leaked: %v", err)
			}
			if kind == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			if kind == "existing" {
				if b, err := os.ReadFile(filepath.Join(out, "keep")); err != nil || string(b) != "keep" {
					t.Fatal("existing output changed")
				}
			}
		})
	}
}

func TestCreateAllowsSeparateDataBackupsAndLimitsCustomLogSelection(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.SourceLog), "unrelated-secret"), []byte("never-send-fixture-value"), 0600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(f.Root, "backups")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: filepath.Join(parent, "new")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if strings.Contains(e.Path, "unrelated-secret") {
			t.Fatal("copied unrelated administrative file")
		}
	}
}

// A database the store refuses to open must say why. The generic IO category
// hid "use a private directory owned by the service account" from an operator
// whose data directory was group-writable; that reason carries no path.
func TestCreateReportsUnsafeDatabaseReason(t *testing.T) {
	fixture := newFixture(t)
	dataDir := filepath.Dir(fixture.Config) // the fixture DB lives beside its config
	if err := os.Chmod(dataDir, 0770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dataDir, 0700) })
	_, err := Create(context.Background(), CreateOptions{ConfigPath: fixture.Config, Output: filepath.Join(t.TempDir(), "backup"), AppVersion: "test", AppCommit: "inert"})
	if err == nil {
		t.Fatal("backup of a group-writable database directory succeeded")
	}
	if !strings.Contains(err.Error(), "private directory owned by the service account") {
		t.Fatalf("error hides the reason: %v", err)
	}
	if strings.Contains(err.Error(), dataDir) {
		t.Fatalf("error leaks the path: %v", err)
	}
}
