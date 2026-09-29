package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/backup"
	"github.com/networkshard/shardlure/internal/config"
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
