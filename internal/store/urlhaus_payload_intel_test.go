package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, name string) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestURLhausSubmissionLedger(t *testing.T) {
	s := newTestStore(t, "urlhaus.db")

	if got, err := s.URLhausSubmitted("http://x.tld/a"); err != nil || got {
		t.Fatalf("fresh db should report not-submitted: %v %v", got, err)
	}
	if err := s.RecordURLhausSubmission("http://x.tld/a", "ok", time.Now()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if got, err := s.URLhausSubmitted("http://x.tld/a"); err != nil || !got {
		t.Fatalf("should now report submitted: %v %v", got, err)
	}
	// Re-recording the same URL must upsert, not duplicate (PK is the url).
	if err := s.RecordURLhausSubmission("http://x.tld/a", "ok2", time.Now()); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	rows, err := s.ListURLhausSubmissions(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (upsert, not insert)", len(rows))
	}
	if rows[0].Status != "ok2" {
		t.Errorf("status = %q, want ok2", rows[0].Status)
	}
	// Empty URL is a silent no-op, not an error or a junk row.
	if err := s.RecordURLhausSubmission("", "ok", time.Now()); err != nil {
		t.Errorf("empty url should no-op: %v", err)
	}
	if got, _ := s.URLhausSubmitted(""); got {
		t.Error("empty url should never report submitted")
	}
}

// The pending count must mirror the cheap structural half of urlhaus.Vet:
// only fetched quarantine_fetch http(s) URLs with a payload, inside the window,
// not already submitted.
func TestURLhausCandidatesAndPendingFilter(t *testing.T) {
	s := newTestStore(t, "urlhaus-cands.db")
	now := time.Now().UTC()

	add := func(url, origin, status, sha string, size int64, age time.Duration) {
		t.Helper()
		if err := s.RecordArtifact(Artifact{
			TS: now.Add(-age), URL: url, Origin: origin, Status: status,
			SHA256: sha, SizeBytes: size, LocalPath: "/tmp/x",
		}); err != nil {
			t.Fatalf("record %s: %v", url, err)
		}
	}

	add("http://evil.tld/good", "quarantine_fetch", "fetched", "aa", 5000, time.Hour)        // eligible
	add("https://evil.tld/good2", "quarantine_fetch", "fetched", "bb", 5000, time.Hour)      // eligible
	add("http://evil.tld/failed", "quarantine_fetch", "failed", "", 0, time.Hour)            // no payload
	add("http://evil.tld/tiny", "quarantine_fetch", "fetched", "cc", 8, time.Hour)           // too small
	add("cowrie-download:abc", "cowrie_download", "fetched", "dd", 5000, time.Hour)          // pseudo-key
	add("cowrie-event:12", "cowrie_file_download", "fetched", "ee", 5000, time.Hour)         // pseudo-key
	add("http://evil.tld/stale", "quarantine_fetch", "fetched", "ff", 5000, 30*24*time.Hour) // outside window

	cands, err := s.URLhausCandidates(3, 0)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	got := map[string]bool{}
	for _, c := range cands {
		got[c.URL] = true
	}
	want := []string{"http://evil.tld/good", "https://evil.tld/good2"}
	if len(cands) != len(want) {
		t.Fatalf("candidates = %d (%v), want %d", len(cands), got, len(want))
	}
	for _, u := range want {
		if !got[u] {
			t.Errorf("missing eligible candidate %s", u)
		}
	}

	stats, err := s.URLhausSubmissionStats(3)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Pending != 2 {
		t.Errorf("pending = %d, want 2", stats.Pending)
	}
	if stats.TotalSubmitted != 0 {
		t.Errorf("totalSubmitted = %d, want 0", stats.TotalSubmitted)
	}

	// Once submitted, it drops out of both candidates and pending.
	if err := s.RecordURLhausSubmission("http://evil.tld/good", "ok", time.Now()); err != nil {
		t.Fatalf("record: %v", err)
	}
	cands, _ = s.URLhausCandidates(3, 0)
	if len(cands) != 1 {
		t.Errorf("candidates after submit = %d, want 1", len(cands))
	}
	stats, _ = s.URLhausSubmissionStats(3)
	if stats.Pending != 1 || stats.TotalSubmitted != 1 {
		t.Errorf("pending=%d submitted=%d, want 1/1", stats.Pending, stats.TotalSubmitted)
	}
}

func TestPayloadIntelCache(t *testing.T) {
	s := newTestStore(t, "payload-intel.db")

	if _, found, err := s.GetPayloadIntel("aa", "virustotal"); err != nil || found {
		t.Fatalf("fresh db should miss: found=%v err=%v", found, err)
	}
	if err := s.PutPayloadIntel("aa", "virustotal", `{"verdict":"malicious"}`); err != nil {
		t.Fatalf("put: %v", err)
	}
	rec, found, err := s.GetPayloadIntel("aa", "virustotal")
	if err != nil || !found {
		t.Fatalf("should hit: found=%v err=%v", found, err)
	}
	if rec.Payload != `{"verdict":"malicious"}` {
		t.Errorf("payload = %q", rec.Payload)
	}
	if rec.FetchedAt.IsZero() {
		t.Error("fetchedAt should be set")
	}

	// Upsert replaces rather than duplicating.
	if err := s.PutPayloadIntel("aa", "virustotal", `{"verdict":"benign"}`); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rec, _, _ = s.GetPayloadIntel("aa", "virustotal")
	if rec.Payload != `{"verdict":"benign"}` {
		t.Errorf("upsert did not replace: %q", rec.Payload)
	}

	// Distinct sources for the same hash coexist (PK is the pair).
	if err := s.PutPayloadIntel("aa", "othersource", `{"x":1}`); err != nil {
		t.Fatalf("put other source: %v", err)
	}
	if rec, _, _ := s.GetPayloadIntel("aa", "virustotal"); rec.Payload != `{"verdict":"benign"}` {
		t.Error("a second source clobbered the first")
	}

	// Blank inputs are no-ops.
	if err := s.PutPayloadIntel("", "virustotal", "{}"); err != nil {
		t.Errorf("blank sha should no-op: %v", err)
	}
	if _, found, _ := s.GetPayloadIntel("", ""); found {
		t.Error("blank lookup should miss")
	}
}

func TestPayloadIntelBySourceBulk(t *testing.T) {
	s := newTestStore(t, "payload-intel-bulk.db")
	for _, sha := range []string{"aa", "bb", "cc"} {
		if err := s.PutPayloadIntel(sha, "virustotal", `{"sha256":"`+sha+`"}`); err != nil {
			t.Fatalf("put %s: %v", sha, err)
		}
	}
	_ = s.PutPayloadIntel("aa", "other", `{"nope":true}`)

	got, err := s.PayloadIntelBySource("virustotal", []string{"aa", "cc", "missing"})
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %v", len(got), got)
	}
	if _, ok := got["bb"]; ok {
		t.Error("bb was not requested but came back")
	}
	if got["aa"].Payload != `{"sha256":"aa"}` {
		t.Errorf("aa payload = %q (wrong source?)", got["aa"].Payload)
	}
	if empty, err := s.PayloadIntelBySource("virustotal", nil); err != nil || len(empty) != 0 {
		t.Errorf("empty request should return empty map: %v %v", empty, err)
	}
}

// payload_intel is a cache and must age out; the submission ledgers must NOT
// (purging them would cause duplicate upstream submissions).
func TestMaintenancePurgeAgesCacheButKeepsLedgers(t *testing.T) {
	s := newTestStore(t, "purge-intel.db")

	old := time.Now().UTC().AddDate(0, 0, -200)
	if err := s.PutPayloadIntel("aa", "virustotal", `{"v":1}`); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Backdate the cache row past the retention horizon.
	if _, err := s.execWrite(`UPDATE payload_intel SET fetched_at=? WHERE sha256='aa'`,
		old.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := s.RecordURLhausSubmission("http://x.tld/a", "ok", old); err != nil {
		t.Fatalf("record submission: %v", err)
	}
	if err := s.RecordBazaarUpload(BazaarUpload{
		SHA256: "aa", UploadedAt: old, ResponseStatus: "inserted",
	}); err != nil {
		t.Fatalf("record upload: %v", err)
	}

	if err := s.MaintenancePurge(90); err != nil {
		t.Fatalf("purge: %v", err)
	}

	if _, found, _ := s.GetPayloadIntel("aa", "virustotal"); found {
		t.Error("stale payload_intel cache row should have been purged")
	}
	if got, _ := s.URLhausSubmitted("http://x.tld/a"); !got {
		t.Error("urlhaus_submissions is a dedup ledger and must survive purge")
	}
	if got, _ := s.BazaarUploadRecorded("aa"); !got {
		t.Error("bazaar_uploads is a dedup ledger and must survive purge")
	}
}
