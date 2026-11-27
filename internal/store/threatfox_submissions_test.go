package store

import (
	"testing"
	"time"
)

// TestThreatFoxCandidatesMatchPendingStat pins that the candidate SELECT and
// the pending-count SQL describe the SAME population — the urlhaus drift lesson,
// where a diverged WHERE made the UI count disagree with the CLI list.
func TestThreatFoxCandidatesMatchPendingStat(t *testing.T) {
	st := newTestStore(t, "threatfox-cands.db")
	now := time.Now().UTC()

	seed := []struct {
		sha, origin, status, url string
		size                     int64
		age                      time.Duration
	}{
		{"tf01", "quarantine_fetch", "fetched", "http://45.155.205.10/a", 4096, time.Hour},           // candidate
		{"tf02", "quarantine_fetch", "fetched", "https://45.155.205.11/b", 4096, time.Hour},          // candidate
		{"tf03", "cowrie_download", "fetched", "http://45.155.205.12/c", 4096, time.Hour},            // NOT: wrong origin
		{"tf04", "quarantine_fetch", "failed", "http://45.155.205.13/d", 4096, time.Hour},            // NOT: not fetched
		{"tf05", "quarantine_fetch", "fetched", "http://45.155.205.14/e", 32, time.Hour},             // NOT: too small
		{"tf06", "quarantine_fetch", "fetched", "cowrie-event:99", 4096, time.Hour},                  // NOT: not http
		{"tf07", "quarantine_fetch", "fetched", "http://45.155.205.16/g", 4096, 30 * 24 * time.Hour}, // NOT: stale
		{"tf08", "quarantine_fetch", "fetched", "http://45.155.205.17/h", 4096, time.Hour},           // candidate, will be pre-submitted
	}
	for _, r := range seed {
		if err := st.RecordArtifact(Artifact{
			URL: r.url, SHA256: r.sha, SizeBytes: r.size, Origin: r.origin, Status: r.status,
			LocalPath: "/evidence/" + r.sha, TS: now.Add(-r.age),
		}); err != nil {
			t.Fatalf("seed %s: %v", r.sha, err)
		}
		if _, err := st.db.Exec(`UPDATE artifacts SET created_at=? WHERE sha256=?`,
			now.Add(-r.age).Format("2006-01-02T15:04:05.999999999Z"), r.sha); err != nil {
			t.Fatalf("backdate %s: %v", r.sha, err)
		}
	}
	// Pre-submit tf08's URL so it drops from both the candidate list and pending.
	if err := st.RecordThreatFoxSubmission("http://45.155.205.17/h", "url", "elf.mirai", "submitted", now); err != nil {
		t.Fatalf("record: %v", err)
	}

	cands, err := st.ThreatFoxCandidates(3, 0)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	stats, err := st.ThreatFoxSubmissionStats(3)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("candidates = %d, want 2 (tf01, tf02); got %+v", len(cands), cands)
	}
	if stats.Pending != len(cands) {
		t.Errorf("pending stat = %d but candidate list = %d — the two SQL queries drifted",
			stats.Pending, len(cands))
	}
	if stats.TotalSubmitted != 1 {
		t.Errorf("totalSubmitted = %d, want 1", stats.TotalSubmitted)
	}
}

// TestThreatFoxDedupLedger pins per-IOC dedup and that a recorded IOC is seen.
func TestThreatFoxDedupLedger(t *testing.T) {
	st := newTestStore(t, "threatfox-dedup.db")
	now := time.Now().UTC()

	if seen, _ := st.ThreatFoxSubmitted("45.155.205.10:80"); seen {
		t.Fatal("unsubmitted IOC reported as seen")
	}
	if err := st.RecordThreatFoxSubmission("45.155.205.10:80", "ip:port", "elf.mirai", "submitted", now); err != nil {
		t.Fatalf("record: %v", err)
	}
	if seen, _ := st.ThreatFoxSubmitted("45.155.205.10:80"); !seen {
		t.Error("submitted IOC not reported as seen")
	}
	// A different IOC value is independent.
	if seen, _ := st.ThreatFoxSubmitted("45.155.205.10:443"); seen {
		t.Error("a different ip:port must be independent in the ledger")
	}
}

func TestThreatFoxStatsExcludeAlreadyListed(t *testing.T) {
	st := newTestStore(t, "threatfox-duplicates.db")
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	submittedAt := now.Add(-time.Hour)
	const added, listed = "192.0.2.1:443", "192.0.2.2:443"
	for _, row := range []struct {
		ioc, status string
		at          time.Time
	}{
		{added, "submitted", submittedAt},
		{listed, "duplicate", now},
		{added, "duplicate", now},
	} {
		if err := st.RecordThreatFoxSubmission(row.ioc, "ip:port", "elf.mirai", row.status, row.at); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.ThreatFoxSubmissionStats(3)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalSubmitted != 1 || !stats.LastSubmittedAt.Equal(submittedAt) {
		t.Fatalf("stats = %+v, want one new IOC at %v", stats, submittedAt)
	}
	rows, err := st.ListThreatFoxSubmissions(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].IOC != listed || rows[0].Status != "duplicate" ||
		rows[1].IOC != added || rows[1].Status != "submitted" {
		t.Fatalf("history = %+v, want already-listed IOC and original submission", rows)
	}
	if seen, err := st.ThreatFoxSubmitted(listed); err != nil || !seen {
		t.Fatalf("already listed IOC dedup = %t, %v; want true, nil", seen, err)
	}
}
