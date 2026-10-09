package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/threatfox"
	"github.com/networkshard/shardlure/internal/intel/urlhaus"
	"github.com/networkshard/shardlure/internal/store"
)

// End-to-end Phase C final-review tests: rows produced by the real store
// paths (harvest queue, capture completion, re-fetch completion) judged by
// the real dashboard builders and gates.

// captureURL queues url as a harvested URL of the given depth (0 = typed by
// the attacker, recorded like a command URL) and completes its capture with
// body, through the store calls the capture worker makes.
func captureURL(t *testing.T, s *Server, dir, url string, depth int, body []byte) string {
	t.Helper()
	now := time.Now().UTC()
	if depth == 0 {
		if err := s.st.UpsertArtifact(store.Artifact{URL: url, TS: now, Origin: "quarantine_fetch", Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	} else {
		src := store.HarvestSource{SHA256: "parent-script-sha", Depth: depth - 1}
		if n, err := s.st.QueueHarvestedURLs(context.Background(), src, []string{url}, now, 32); err != nil || n != 1 {
			t.Fatalf("queue harvested %s: %d %v", url, n, err)
		}
	}
	path, sha := writeFixture(t, dir, shaName(body), body)
	if err := s.st.ClaimArtifactCapture(url, now, now.Add(time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.st.CompleteArtifactCapture(url, 1, "fetched", "", path, sha, int64(len(body)), nil); err != nil {
		t.Fatal(err)
	}
	return sha
}

func shaName(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// benignELF is minimalFamilyELF with the XMRig anchor replaced by inert text
// of the same length: an ELF the classifier names no family for.
func benignELF(pad string) []byte {
	b := bytes.Replace(minimalFamilyELF(), []byte("donate.v2.xmrig.com"), []byte("inert.example.name."), 1)
	return append(b, pad...)
}

// I2: a harvested benign ELF is not MalwareBazaar-eligible (provenance no
// longer accepts at depth > 0), a harvested family-identified ELF still is,
// and a benign ELF the attacker fetched directly keeps its provenance accept.
// The panel shows Vet's reason.
func TestHarvestedSamplesAtTheBazaarGate(t *testing.T) {
	s := newIntelTestServer(t, nil)
	dir := t.TempDir()
	harvestedBenign := captureURL(t, s, dir, "https://busybox.net/downloads/binaries/busybox-x86_64", 1, benignELF("h"))
	harvestedFamily := captureURL(t, s, dir, "http://203.0.113.50/bins/xmr", 1, append(minimalFamilyELF(), 'h'))
	typedBenign := captureURL(t, s, dir, "http://203.0.113.50/bins/x86", 0, benignELF("t"))

	got := map[string]bazaarCandJSON{}
	out := getBazaar(t, s)
	for _, c := range out.Candidates {
		got[c.SHA256] = c
	}
	if c := got[harvestedBenign]; c.Eligible || c.Reason != bazaar.ReasonHarvestedNoSignal {
		t.Errorf("harvested benign ELF: eligible=%v reason=%q, want refused with %q", c.Eligible, c.Reason, bazaar.ReasonHarvestedNoSignal)
	}
	if c := got[harvestedFamily]; !c.Eligible {
		t.Errorf("harvested XMRig ELF must stay eligible on its family: reason=%q", c.Reason)
	}
	if c := got[typedBenign]; !c.Eligible {
		t.Errorf("an ELF the attacker fetched keeps the provenance accept: reason=%q", c.Reason)
	}
	if out.Stats.Pending != 2 {
		t.Errorf("pending=%d want 2", out.Stats.Pending)
	}
	// The upload builder judges the same depth.
	cand, err := s.bazaarShareCandidate(harvestedBenign)
	if err != nil || cand.Depth != 1 {
		t.Fatalf("upload candidate: %+v %v", cand, err)
	}
}

// I2: a harvested URL is never a URLhaus or ThreatFox accept, whatever the
// payload; the panels carry the reason. A typed URL with the same kind of
// payload is accepted, so the refusal is the depth and nothing else.
func TestHarvestedURLsAtTheURLhausAndThreatFoxGates(t *testing.T) {
	s := newIntelTestServer(t, nil)
	dir := t.TempDir()
	harvested := "http://evil.tld/bins/xmr-h"
	typed := "http://evil.tld/bins/xmr-t"
	captureURL(t, s, dir, harvested, 1, append(minimalFamilyELF(), 'h'))
	captureURL(t, s, dir, typed, 0, append(minimalFamilyELF(), 't'))

	w := httptest.NewRecorder()
	s.handleIntelURLhaus(w, httptest.NewRequest(http.MethodGet, "/api/intel/urlhaus", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("urlhaus: %d %s", w.Code, w.Body.String())
	}
	var uh urlhausResponse
	if err := json.Unmarshal(w.Body.Bytes(), &uh); err != nil {
		t.Fatal(err)
	}
	byURL := map[string]urlhausCandidateRow{}
	for _, c := range uh.Candidates {
		byURL[c.URL] = c
	}
	if c, ok := byURL[harvested]; !ok || c.Eligible || c.Reason != urlhaus.ReasonHarvestedURL {
		t.Errorf("urlhaus harvested: present=%v %+v", ok, c)
	}
	if c := byURL[typed]; !c.Eligible {
		t.Errorf("urlhaus typed must be eligible: %q", c.Reason)
	}
	cands, _, err := s.urlhausCandidates(3)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.URL == harvested {
			t.Fatal("a harvested URL is in the URLhaus submission set")
		}
	}

	tfCands, view, err := s.threatfoxCandidates(3)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tfCands {
		if c.URL == harvested {
			t.Fatal("a harvested URL is in the ThreatFox submission set")
		}
	}
	seen := map[string]threatfoxCandidateRow{}
	for _, v := range view {
		seen[v.URL] = v
	}
	if c, ok := seen[harvested]; !ok || c.Eligible || c.Reason != threatfox.ReasonHarvestedURL {
		t.Errorf("threatfox harvested: present=%v %+v", ok, c)
	}
	if c := seen[typed]; !c.Eligible {
		t.Errorf("threatfox typed must be eligible: %q", c.Reason)
	}
}
