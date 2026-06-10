package store

import (
	"os"
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

// TestMaintenancePurgeDeletesEvidenceFiles verifies the purge unlinks the
// on-disk evidence file (and its .txt transcript sibling) for expired
// artifacts, while leaving fresh artifacts' files intact. Without this the
// evidence dir grew without bound.
func TestMaintenancePurgeDeletesEvidenceFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "ev.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	oldTS := now.AddDate(0, 0, -90)
	freshTS := now.AddDate(0, 0, -1)

	mkfile := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	oldPath := mkfile("old-artifact")
	mkfile("old-artifact.txt") // transcript sibling
	freshPath := mkfile("fresh-artifact")

	if err := s.UpsertArtifact(Artifact{TS: oldTS, URL: "http://e/old", LocalPath: oldPath, Origin: "test", Status: "ok"}); err != nil {
		t.Fatalf("upsert old: %v", err)
	}
	if err := s.UpsertArtifact(Artifact{TS: freshTS, URL: "http://e/fresh", LocalPath: freshPath, Origin: "test", Status: "ok"}); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	if err := s.MaintenancePurge(30); err != nil {
		t.Fatalf("purge: %v", err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("expired artifact file should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(oldPath + ".txt"); !os.IsNotExist(err) {
		t.Errorf("expired transcript sibling should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("fresh artifact file must survive, got: %v", err)
	}
}

// TestMaintenancePurgeChunkedEvents seeds more than one purge chunk (5000) of
// stale events and confirms the chunked DELETE loop removes them all while
// keeping fresh rows.
func TestMaintenancePurgeChunkedEvents(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "chunk.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	oldTS := time.Now().UTC().AddDate(0, 0, -90)
	freshTS := time.Now().UTC().AddDate(0, 0, -1)
	for i := 0; i < 5200; i++ {
		if err := s.InsertEvent(&models.Event{TS: oldTS, Source: "cowrie", Kind: "connect", SrcIP: "1.1.1.1"}); err != nil {
			t.Fatalf("insert old %d: %v", i, err)
		}
	}
	if err := s.InsertEvent(&models.Event{TS: freshTS, Source: "cowrie", Kind: "connect", SrcIP: "2.2.2.2"}); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}

	if err := s.MaintenancePurge(30); err != nil {
		t.Fatalf("purge: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 fresh event left after chunked purge, got %d", n)
	}
}
