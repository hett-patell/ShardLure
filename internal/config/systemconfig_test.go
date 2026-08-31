package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCfg writes a minimal config naming a data_dir, so a test can tell which
// file Load actually read.
func writeCfg(t *testing.T, path, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("data_dir: "+dataDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The systemd unit passes SHARDLURE_CONFIG; an operator shell does not. Without
// a system fallback, `sudo shardlure share bazaar` resolved to
// ~/.local/share/shardlure and silently operated on an empty database while the
// real one sat in /var/lib/shardlure — every manual outbound run reported "no
// candidates", indistinguishable from a broken feature.
func TestLoadFallsBackToSystemConfigWhenUserHasNone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sys := filepath.Join(t.TempDir(), "shardlure.yaml")
	writeCfg(t, sys, "/var/lib/shardlure")
	systemConfigPaths = []string{sys}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/var/lib/shardlure" {
		t.Fatalf("DataDir = %q, want /var/lib/shardlure (system config ignored)", c.DataDir)
	}
}

// A user who has their own config keeps it: the fallback must never override an
// explicit local choice, or a developer's own data dir would be hijacked by a
// system install on the same box.
func TestLoadPrefersUserConfigOverSystemConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	userCfg := filepath.Join(home, ".local", "share", "shardlure", "shardlure.yaml")
	writeCfg(t, userCfg, "/home/dev/mydata")
	sys := filepath.Join(t.TempDir(), "shardlure.yaml")
	writeCfg(t, sys, "/var/lib/shardlure")
	systemConfigPaths = []string{sys}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/home/dev/mydata" {
		t.Fatalf("DataDir = %q, want /home/dev/mydata", c.DataDir)
	}
}

// An explicit -config / SHARDLURE_CONFIG path is authoritative — this is the
// path the systemd unit uses, so the fallback must not touch it.
func TestLoadExplicitPathIgnoresSystemFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	explicit := filepath.Join(t.TempDir(), "explicit.yaml")
	writeCfg(t, explicit, "/explicit/dir")
	sys := filepath.Join(t.TempDir(), "shardlure.yaml")
	writeCfg(t, sys, "/var/lib/shardlure")
	systemConfigPaths = []string{sys}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load(explicit)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/explicit/dir" {
		t.Fatalf("DataDir = %q, want /explicit/dir", c.DataDir)
	}
}

// No config anywhere is the fresh-laptop case and must keep the user data dir.
func TestLoadWithNoConfigAnywhereKeepsUserDataDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	systemConfigPaths = []string{filepath.Join(t.TempDir(), "absent.yaml")}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(home, ".local", "share", "shardlure")
	if c.DataDir != want {
		t.Fatalf("DataDir = %q, want %q", c.DataDir, want)
	}
}

// An unreadable system config (root-owned 0600 while running as a normal user)
// must be skipped, not turned into a fatal error — the CLI still has to work.
func TestLoadSkipsUnreadableSystemConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read 0000 files")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.yaml")
	writeCfg(t, locked, "/var/lib/shardlure")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	readable := filepath.Join(dir, "readable.yaml")
	writeCfg(t, readable, "/etc/fallback")
	systemConfigPaths = []string{locked, readable}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DataDir != "/etc/fallback" {
		t.Fatalf("DataDir = %q, want /etc/fallback (unreadable candidate not skipped)", c.DataDir)
	}
}

// A directory sitting at a candidate path must not be mistaken for a config.
func TestLoadSkipsDirectoryAtSystemConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	asDir := filepath.Join(dir, "shardlure.yaml")
	if err := os.MkdirAll(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	systemConfigPaths = []string{asDir}
	t.Cleanup(func() { systemConfigPaths = defaultSystemConfigPaths() })

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(home, ".local", "share", "shardlure")
	if c.DataDir != want {
		t.Fatalf("DataDir = %q, want %q", c.DataDir, want)
	}
}
