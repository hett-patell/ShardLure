package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// Regression (whole-branch review): the five cache tables were read in full,
// every timestamp parsed in Go, inside ONE transaction holding captureMu and
// writeMu, so each purge stalled ingest for the whole scan on a large DB. Rows
// that are certainly not expired (text at or beyond cutoff+15h, covering any
// UTC offset) must never be materialized.
func TestMaintenancePurgeDoesNotMaterializeFreshCacheRows(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "purge-bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureSessionMetaTable(); err != nil {
		t.Fatal(err)
	}
	fresh := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		if _, err := tx.Exec(`INSERT INTO cowrie_session_meta(session_id,observed_at) VALUES(?,?)`, fmt.Sprintf("s%06d", i), fresh); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := st.MaintenancePurge(30); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if n := after.Mallocs - before.Mallocs; n > 20000 {
		t.Fatalf("purge made %d allocations for 20,000 fresh cache rows; they were materialized", n)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM cowrie_session_meta`); got != 20000 {
		t.Fatalf("fresh rows=%d, want 20000", got)
	}
}

// Regression (whole-branch review): the live purge worker is joined before the
// store closes, but MaintenancePurge took no context, so a long first purge of
// an aged DB outlived systemd's stop timeout and was SIGKILLed mid-purge.
func TestMaintenancePurgeContextStopsOnCancellation(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "purge-cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	old := time.Now().UTC().AddDate(0, 0, -90)
	var events []*models.Event
	for i := 0; i < 12000; i++ {
		events = append(events, &models.Event{TS: old.Add(time.Duration(i) * time.Second), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "192.0.2.9", Username: "root"})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := st.MaintenancePurgeContext(ctx, 30); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled purge err=%v, want context.Canceled", err)
	}
	if n, err := st.EventCount(); err != nil || n != 12000 {
		t.Fatalf("cancelled purge deleted events: %d err=%v", n, err)
	}
}
