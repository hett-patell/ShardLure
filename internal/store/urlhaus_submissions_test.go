package store

import (
	"testing"
	"time"
)

// The CLI and a dashboard button can both pass the dedup read and then write
// the ledger. A listing check that lands second must not downgrade a real
// submission — that row is the only record of a public contribution, and the
// funnel and the panel's submitted total read it.
func TestURLhausAlreadyListedNeverDowngradesASubmission(t *testing.T) {
	s := newTestStore(t, "urlhaus-ledger.db")
	const u = "http://evil.tld/a.sh"

	if err := s.RecordURLhausSubmission(u, "ok", time.Now()); err != nil {
		t.Fatalf("record ok: %v", err)
	}
	if err := s.RecordURLhausSubmission(u, URLhausStatusAlreadyListed, time.Now()); err != nil {
		t.Fatalf("record already_listed: %v", err)
	}
	rows, err := s.ListURLhausSubmissions(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != "ok" {
		t.Fatalf("rows = %+v, want the original ok row", rows)
	}

	// The guard must not stop new rows: an unseen URL is still recorded as
	// already_listed, and a later real submission may replace that note.
	if err := s.RecordURLhausSubmission("http://evil.tld/b.sh", URLhausStatusAlreadyListed, time.Now()); err != nil {
		t.Fatalf("record new already_listed: %v", err)
	}
	if err := s.RecordURLhausSubmission("http://evil.tld/b.sh", "ok", time.Now()); err != nil {
		t.Fatalf("record ok over note: %v", err)
	}
	if done, err := s.URLhausSubmitted("http://evil.tld/b.sh"); err != nil || !done {
		t.Fatalf("URLhausSubmitted = %v, %v", done, err)
	}
	rows, _ = s.ListURLhausSubmissions(10)
	for _, r := range rows {
		if r.URL == "http://evil.tld/b.sh" && r.Status != "ok" {
			t.Errorf("status = %q, want ok after a real submission", r.Status)
		}
	}
}
