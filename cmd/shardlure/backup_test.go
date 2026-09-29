package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/backup"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
	"gopkg.in/yaml.v3"
)

func cliBackupFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = root
	cfg.Capture.EvidenceDir = filepath.Join(root, "evidence")
	cfg.Cowrie.Home = filepath.Join(root, "cowrie")
	cfg.Cowrie.JSONLog = filepath.Join(cfg.Cowrie.Home, "var/log/cowrie/cowrie.json")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "shardlure.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindConnect}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	st.Close()
	out := filepath.Join(t.TempDir(), "backup")
	if _, err := backup.Create(context.Background(), backup.CreateOptions{ConfigPath: path, Output: out}); err != nil {
		t.Fatal(err)
	}
	return path, out
}

func TestBackupCLIParsingAndNoConfigForInspection(t *testing.T) {
	cfg, bundle := cliBackupFixture(t)
	for _, args := range [][]string{{}, {"bogus"}, {"verify"}, {"verify", "--input", bundle, "--timeout", "0s"}, {"verify", "--input", bundle, "extra"}, {"restore", "--input", bundle, "--to", "inert", "--force"}, {"create", "--output", "inert", "--unknown"}} {
		var out bytes.Buffer
		if err := runBackup(context.Background(), cfg, args, &out); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	var out bytes.Buffer
	if err := runBackup(context.Background(), "/inert/nonexistent", []string{"verify", "--input", bundle}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "verified") {
		t.Fatalf("missing result: %s", out.String())
	}
	to := filepath.Join(t.TempDir(), "dry-run")
	if err := runBackup(context.Background(), "/inert/nonexistent", []string{"restore", "--input", bundle, "--to", to, "--dry-run"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(to); !os.IsNotExist(err) {
		t.Fatal("CLI dry-run created target")
	}
}

func TestBackupCLIMainAvoidsConfigAndStoreInitialization(t *testing.T) {
	if os.Getenv("SHARDLURE_TEST_BACKUP_MAIN") == "1" {
		os.Args = []string{"shardlure", "backup", "verify", "--input", os.Getenv("SHARDLURE_TEST_BACKUP_INPUT")}
		flag.CommandLine = flag.NewFlagSet("shardlure", flag.ExitOnError)
		main()
		return
	}
	_, bundle := cliBackupFixture(t)
	invalid := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("invalid: [never-send-fixture-value"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBackupCLIMainAvoidsConfigAndStoreInitialization$")
	cmd.Env = append(os.Environ(), "SHARDLURE_TEST_BACKUP_MAIN=1", "SHARDLURE_TEST_BACKUP_INPUT="+bundle, "SHARDLURE_CONFIG="+invalid)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup went through normal startup: %v %s", err, out)
	}
	if !bytes.Contains(out, []byte("verified")) || bytes.Contains(out, []byte("never-send-fixture-value")) {
		t.Fatalf("unsafe or missing CLI result: %s", out)
	}
}

func TestBackupCLINamesRefusedPathReasonAndRemedy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission refusal test must run as a non-root user")
	}
	cfg, bundle := cliBackupFixture(t)
	shared := t.TempDir()
	if err := os.Chmod(shared, 0770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(shared, 0700) })
	for _, args := range [][]string{
		{"create", "--output", filepath.Join(shared, "NEW")},
		{"restore", "--input", bundle, "--to", filepath.Join(shared, "restored")},
	} {
		var out bytes.Buffer
		err := runBackup(context.Background(), cfg, args, &out)
		if err == nil {
			t.Fatalf("%v accepted a group-writable ancestor", args)
		}
		msg := err.Error()
		t.Logf("%s: %s", args[0], msg)
		for _, want := range []string{strconv.Quote(shared), "writable by group or others", "choose an output directory whose ancestors are all owned by root or by the running user"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("%v: error %q lacks %q", args[0], msg, want)
			}
		}
		if strings.Contains(msg, "filesystem or database operation failed") {
			t.Fatalf("%v: still the generic message: %q", args[0], msg)
		}
	}
}

// The remedy must match the check that failed and the side refused: ancestor
// ownership advice is wrong for a symlink, an unsupported filesystem or the
// --input bundle (review follow-up to 850e210).
func TestBackupCLIRemedyMatchesRefusal(t *testing.T) {
	cfg, bundle := cliBackupFixture(t)
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
		t.Fatal(err)
	}
	linkedBundle := filepath.Join(base, "real", "bundle")
	if err := os.Rename(bundle, linkedBundle); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(link, "bundle")
	const ownership = "whose ancestors are all owned by root"
	for _, tc := range []struct {
		name       string
		args       []string
		want, deny []string
	}{
		{"verify-symlink-input", []string{"verify", "--input", viaLink}, []string{"symlink", "choose a bundle path without symlinks"}, []string{ownership, "output directory"}},
		{"restore-symlink-input", []string{"restore", "--input", viaLink, "--to", filepath.Join(t.TempDir(), "r")}, []string{"choose a bundle path without symlinks"}, []string{ownership, "output directory"}},
		{"create-symlink-output", []string{"create", "--output", filepath.Join(link, "NEW")}, []string{"choose an output directory without symlinks"}, []string{ownership, "bundle path"}},
		{"restore-symlink-to", []string{"restore", "--input", linkedBundle, "--to", filepath.Join(link, "NEW")}, []string{strconv.Quote(link), "choose an output directory without symlinks"}, []string{ownership, "bundle path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runBackup(context.Background(), cfg, tc.args, &bytes.Buffer{})
			if err == nil {
				t.Fatal("symlinked path accepted")
			}
			msg := err.Error()
			t.Log(msg)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Fatalf("%q lacks %q", msg, w)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(msg, d) {
					t.Fatalf("%q wrongly contains %q", msg, d)
				}
			}
		})
	}
	// An unsupported filesystem cannot be staged portably in a test, so the
	// mapping is checked on a synthetic refusal of each side.
	unsupported := &safefile.PathRefusal{Kind: safefile.ErrUnsupported, Path: "/mnt/nfs/b", Reason: "filesystem is not ext4, xfs, btrfs, tmpfs or overlayfs"}
	for input, want := range map[string]string{"": "choose an output directory on a supported filesystem", "/mnt/nfs/b": "choose a bundle path on a supported filesystem"} {
		msg := explainRefusedPath(fmt.Errorf("wrapped: %w", unsupported), refusalSides{input: input}).Error()
		if !strings.Contains(msg, want) || !strings.Contains(msg, unsupported.Reason) || strings.Contains(msg, ownership) {
			t.Fatalf("input=%q: %q", input, msg)
		}
	}
	perm := &safefile.PathRefusal{Kind: safefile.ErrPermission, Path: "/srv", Reason: "directory owned by uid 1000, not root or the running user (uid 0)"}
	if msg := explainRefusedPath(perm, refusalSides{input: "/var/backups/b"}).Error(); !strings.Contains(msg, "choose an output directory "+ownership) {
		t.Fatalf("ownership refusal lost its advice: %q", msg)
	}
}

// TestBackupCLIRemedyNamesRefusedSource pins the source side of backup
// create: a config directory or an --include-file directory reached through a
// symlink is refused, and the remedy must point that source at the real
// directory, never tell the operator to choose a different output (audit I1).
func TestBackupCLIRemedyNamesRefusedSource(t *testing.T) {
	cfg, _ := cliBackupFixture(t)
	base := t.TempDir()
	cfgLink := filepath.Join(base, "cfglink")
	if err := os.Symlink(filepath.Dir(cfg), cfgLink); err != nil {
		t.Fatal(err)
	}
	incReal := filepath.Join(base, "increal")
	if err := os.Mkdir(incReal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incReal, "f"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	incLink := filepath.Join(base, "inclink")
	if err := os.Symlink(incReal, incLink); err != nil {
		t.Fatal(err)
	}
	// A data root named by the config (the evidence directory) reached
	// through a symlink is a source too.
	loaded, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	evReal := filepath.Join(base, "evreal")
	if err := os.Mkdir(evReal, 0700); err != nil {
		t.Fatal(err)
	}
	evLink := filepath.Join(base, "evlink")
	if err := os.Symlink(evReal, evLink); err != nil {
		t.Fatal(err)
	}
	loaded.Capture.EvidenceDir = evLink
	data, err := yaml.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	evCfg := filepath.Join(filepath.Dir(cfg), "evidence-link.yaml")
	if err := os.WriteFile(evCfg, data, 0600); err != nil {
		t.Fatal(err)
	}
	const ownership = "whose ancestors are all owned by root"
	for _, tc := range []struct {
		name, config string
		args         []string
		want         []string
	}{
		{"config-dir-symlink", filepath.Join(cfgLink, filepath.Base(cfg)), []string{"create", "--output", filepath.Join(t.TempDir(), "NEW")},
			[]string{strconv.Quote(cfgLink), "point the config", "real directory"}},
		{"include-file-symlink", cfg, []string{"create", "--output", filepath.Join(t.TempDir(), "NEW"), "--include-file", filepath.Join(incLink, "f")},
			[]string{strconv.Quote(incLink), "point --include-file", "real directory"}},
		{"evidence-root-symlink", evCfg, []string{"create", "--output", filepath.Join(t.TempDir(), "NEW")},
			[]string{strconv.Quote(evLink), "point the config", "evidence", "real directory"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runBackup(context.Background(), tc.config, tc.args, &bytes.Buffer{})
			if err == nil {
				t.Fatal("symlinked source accepted")
			}
			msg := err.Error()
			t.Log(msg)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Fatalf("%q lacks %q", msg, w)
				}
			}
			for _, d := range []string{"output directory", "bundle path", ownership} {
				if strings.Contains(msg, d) {
					t.Fatalf("%q wrongly contains %q", msg, d)
				}
			}
		})
	}
	// Unsupported filesystems cannot be staged portably: check the source
	// mapping on a synthetic refusal, for the config and --include-file sides.
	unsupported := &safefile.PathRefusal{Kind: safefile.ErrUnsupported, Path: "/mnt/nfs", Reason: "filesystem is not ext4, xfs, btrfs, tmpfs or overlayfs"}
	for sides, want := range map[*refusalSides]string{
		{create: true, config: "/mnt/nfs/etc/shardlure.yaml", output: "/var/backups/b"}:                               "point the config",
		{create: true, config: "/etc/shardlure.yaml", output: "/var/backups/b", includes: []string{"/mnt/nfs/k/key"}}: "point --include-file",
	} {
		msg := explainRefusedPath(unsupported, *sides).Error()
		if !strings.Contains(msg, want) || !strings.Contains(msg, "supported filesystem") || strings.Contains(msg, "output directory") {
			t.Fatalf("%+v: %q", *sides, msg)
		}
	}
}
