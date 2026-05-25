package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestMaintenancePurgeFreshDB makes sure the very first purge call
// against a brand-new database does not blow up on lazily-created
// tables (ip_enrichment / cowrie_tty_index / artifacts). The earlier
// v1.1 cut hit "no such table: ip_enrichment" here and silently
// rolled back, defeating the retention loop.
func TestMaintenancePurgeFreshDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fresh.db")
	s, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.MaintenancePurge(30); err != nil {
		t.Fatalf("MaintenancePurge on fresh DB must succeed: %v", err)
	}
}

// TestMaintenancePurgeDeletesOldRows seeds rows on both sides of the
// retention cutoff across every purged table and verifies only the
// stale rows go away. Locks in the column names — a regression to the
// queried_at typo would surface here as a query error.
func TestMaintenancePurgeDeletesOldRows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "purge.db")
	s, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	oldTS := now.AddDate(0, 0, -90)
	freshTS := now.AddDate(0, 0, -1)

	// Seed events: one stale, one fresh.
	for _, ts := range []time.Time{oldTS, freshTS} {
		if err := s.InsertEvent(&models.Event{
			TS: ts, Source: "cowrie", Kind: "command",
			SrcIP: "1.2.3.4", Command: "id",
		}); err != nil {
			t.Fatalf("InsertEvent: %v", err)
		}
	}

	// Seed enrichment: PutEnrichment stamps "now" so we have to
	// backdate one row manually.
	if err := s.PutEnrichment("1.2.3.4", "abuseipdb", "{}"); err != nil {
		t.Fatalf("PutEnrichment fresh: %v", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO ip_enrichment (ip, source, payload, fetched_at) VALUES (?, ?, ?, ?)`,
		"5.6.7.8", "abuseipdb", "{}", oldTS.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("seed stale enrichment: %v", err)
	}

	// Seed cowrie TTY index: one stale, one fresh.
	if err := s.RecordCowrieTTYBinding(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sess-fresh", freshTS,
	); err != nil {
		t.Fatalf("RecordCowrieTTYBinding fresh: %v", err)
	}
	if err := s.RecordCowrieTTYBinding(
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"sess-old", oldTS,
	); err != nil {
		t.Fatalf("RecordCowrieTTYBinding old: %v", err)
	}

	// Seed artifacts: one stale, one fresh.
	for i, ts := range []time.Time{oldTS, freshTS} {
		if err := s.UpsertArtifact(Artifact{
			TS: ts, URL: "http://example/" + string(rune('a'+i)),
			Origin: "test", Status: "ok",
		}); err != nil {
			t.Fatalf("UpsertArtifact: %v", err)
		}
	}

	if err := s.MaintenancePurge(30); err != nil {
		t.Fatalf("MaintenancePurge: %v", err)
	}

	count := func(q string) int {
		var n int
		if err := s.db.QueryRow(q).Scan(&n); err != nil {
			t.Fatalf("count %q: %v", q, err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM events`); n != 1 {
		t.Errorf("events: want 1 row left, got %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM ip_enrichment`); n != 1 {
		t.Errorf("ip_enrichment: want 1 row left, got %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM cowrie_tty_index`); n != 1 {
		t.Errorf("cowrie_tty_index: want 1 row left, got %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM artifacts`); n != 1 {
		t.Errorf("artifacts: want 1 row left, got %d", n)
	}
}

// TestMaintenancePurgeZeroIsNoop confirms retentionDays<=0 short
// circuits without touching the DB or creating any tables.
func TestMaintenancePurgeZeroIsNoop(t *testing.T) {
	p := filepath.Join(t.TempDir(), "noop.db")
	s, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.MaintenancePurge(0); err != nil {
		t.Fatalf("zero retention should be a no-op, got: %v", err)
	}
	if err := s.MaintenancePurge(-5); err != nil {
		t.Fatalf("negative retention should be a no-op, got: %v", err)
	}
}
