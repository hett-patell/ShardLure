package bazaar

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// truncatedXMRigELF is a real-shaped partial download: a statically linked
// x86-64 ELF whose program header table sits past 256 KiB, with an XMRig
// anchor near the top, cut off before that table. debug/elf reads the program
// headers eagerly, so the cut copy does not parse; the whole copy does.
func truncatedXMRigELF(t *testing.T) (whole, cut []byte) {
	t.Helper()
	whole = largeStaticELF64(elf.EM_X86_64)
	copy(whole[4096:], "...donate.v2.xmrig.com\x00...")
	cut = append([]byte(nil), whole[:280*1024]...)
	if _, err := elf.NewFile(bytes.NewReader(cut)); err == nil {
		t.Fatal("precondition: the truncated ELF must not parse")
	}
	if _, err := elf.NewFile(bytes.NewReader(whole)); err != nil {
		t.Fatalf("precondition: the whole ELF must parse: %v", err)
	}
	return whole, cut
}

func writeSample(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A malformed or truncated ELF gets its family from the 256 KiB head scan on
// the INTERNAL view (ClassifyFile), and on no outbound one (Classify).
//
// classifyELF used to return as soon as elf.NewFile failed, before
// matchELFFamily ran, so a partial download of a generic build (Cowrie does
// capture them) carried no family; the campaign worker's generic-build
// exclusion depends on that family, and the payload linked (campaign final
// audit M-1). Fixing that for the worker must not change what abuse.ch sees:
// a head-scan family on a file that does not even parse is a label main never
// shipped, and a wrong signature bans the shared account (premerge audit
// campaign M8). So Classify — the entry point of share bazaar, the ThreatFox
// family and every dashboard preview — returns exactly main's shape.
func TestClassifyTruncatedELFFamilyIsInternalOnly(t *testing.T) {
	whole, cut := truncatedXMRigELF(t)
	dir := t.TempDir()
	wholePath := writeSample(t, dir, "whole", whole)
	cutPath := writeSample(t, dir, "truncated", cut)

	if c, err := Classify(wholePath); err != nil || c.Family != "XMRig" || c.HeaderMalformed || !containsTag(c.Tags, "x86-64") || !containsTag(c.Tags, "static") {
		t.Fatalf("whole ELF: %+v, %v", c, err)
	}

	f, err := os.Open(cutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	internal, err := ClassifyFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if internal.Family != "XMRig" || !internal.HeaderMalformed {
		t.Fatalf("ClassifyFile on a truncated ELF: family %q malformed %v (want XMRig from the head scan, flagged)", internal.Family, internal.HeaderMalformed)
	}
	if !containsTag(internal.Tags, "elf") || containsTag(internal.Tags, "x86-64") || containsTag(internal.Tags, "static") {
		t.Fatalf("ClassifyFile: structural tags need a parsable header: %v", internal.Tags)
	}

	out, err := Classify(cutPath)
	if err != nil {
		t.Fatal(err)
	}
	if out.Family != "" || out.FileKind != "ELF" || strings.Join(out.Tags, ",") != "elf,linux" {
		t.Fatalf("Classify on a truncated ELF must be main's unlabelled shape {ELF [elf linux] no family}, got %+v", out)
	}
	if got := internal.Outbound(); got.Family != "" || strings.Join(got.Tags, ",") != "elf,linux" {
		t.Fatalf("Outbound() kept a label: %+v", got)
	}
}

// The share bazaar upload of a truncated ELF carries no signature: no
// "Suspected family" in the comment and no family or behaviour tags, while the
// complete file of the same sample does (control).
func TestShareUploadOfTruncatedELFCarriesNoFamily(t *testing.T) {
	whole, cut := truncatedXMRigELF(t)
	dir := t.TempDir()
	type upload struct {
		Tags    []string          `json:"tags"`
		Context map[string]string `json:"context"`
	}
	var got []upload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Error(err)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				return
			}
			if p.FormName() == "json_data" {
				var u upload
				if err := json.NewDecoder(p).Decode(&u); err != nil {
					t.Error(err)
				}
				got = append(got, u)
			}
		}
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	now := time.Now()
	cands := []Candidate{
		{SHA256: "11aa", LocalPath: writeSample(t, dir, "truncated", cut), SizeBytes: int64(len(cut)), CreatedAt: now, Origin: "cowrie_download", ObservedAt: now},
		{SHA256: "22bb", LocalPath: writeSample(t, dir, "whole", whole), SizeBytes: int64(len(whole)), CreatedAt: now, Origin: "cowrie_download", ObservedAt: now},
	}
	opts := Options{APIKey: "k", Endpoint: srv.URL, MaxBytes: 1 << 20, RateLimit: time.Millisecond}
	if uploaded, _, err := Share(context.Background(), newMemRecorder(), cands, opts); err != nil || uploaded != 2 {
		t.Fatalf("Share: uploaded %d, %v", uploaded, err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 uploads, got %d", len(got))
	}
	labelled := func(u upload) bool {
		return strings.Contains(u.Context["comment"], "Suspected family") || containsTag(u.Tags, "xmrig") || containsTag(u.Tags, "miner")
	}
	if labelled(got[0]) {
		t.Fatalf("truncated ELF uploaded with a family label: %+v", got[0])
	}
	if !labelled(got[1]) {
		t.Fatalf("control: the complete ELF should carry its family: %+v", got[1])
	}
}
