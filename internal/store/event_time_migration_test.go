package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestMigrationV20AddsEventUnixNanosAndNewWritesPopulate(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "event-time-v20.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	version, err := st.currentSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version < 20 {
		t.Fatalf("schema version=%d, want at least 20", version)
	}
	cols, err := tableColumns(st, "events")
	if err != nil {
		t.Fatal(err)
	}
	if !cols["ts_unix_ns"] {
		t.Fatal("events missing ts_unix_ns")
	}
	indexes, err := indexNames(st)
	if err != nil {
		t.Fatal(err)
	}
	if !indexes["idx_events_unix_ns"] {
		t.Fatal("events missing idx_events_unix_ns")
	}

	ts := time.Date(2026, 9, 18, 12, 34, 56, 123456789, time.FixedZone("offset", 5*60*60+30*60))
	e := &models.Event{TS: ts, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "8.8.8.8"}
	if err := st.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	var text string
	var unixNS int64
	if err := st.db.QueryRow(`SELECT ts,ts_unix_ns FROM events WHERE id=?`, e.ID).Scan(&text, &unixNS); err != nil {
		t.Fatal(err)
	}
	if text != formatFixedUTC(ts) || unixNS != ts.UnixNano() {
		t.Fatalf("stored time text=%q unix_ns=%d, want %q/%d", text, unixNS, formatFixedUTC(ts), ts.UnixNano())
	}
}

func TestBackfillEventTimesIsBoundedResumableAndSkipsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event-time-backfill.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := []string{
		"2026-01-01T01:00:00+02:00",
		"not-a-time",
		"2026-01-01T00:00:00.123456789Z",
	}
	for _, ts := range rows {
		if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind) VALUES(?,?,?)`,
			ts, models.SourceJournal, models.KindFailedPass); err != nil {
			t.Fatal(err)
		}
	}

	first, err := st.BackfillEventTimes(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Scanned != 2 || first.Updated != 1 || first.Invalid != 1 || first.Done {
		t.Fatalf("first batch=%+v, want scanned=2 updated=1 invalid=1 done=false", first)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	second, err := st.BackfillEventTimes(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.Scanned != 1 || second.Updated != 1 || second.Invalid != 0 || !second.Done {
		t.Fatalf("second batch=%+v, want scanned=1 updated=1 invalid=0 done=true", second)
	}

	var validCount int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM events WHERE ts_unix_ns IS NOT NULL`).Scan(&validCount); err != nil {
		t.Fatal(err)
	}
	if validCount != 2 {
		t.Fatalf("backfilled rows=%d, want 2", validCount)
	}
	var malformedNS sql.NullInt64
	var malformedText string
	if err := st.db.QueryRow(`SELECT ts,ts_unix_ns FROM events WHERE ts='not-a-time'`).Scan(&malformedText, &malformedNS); err != nil {
		t.Fatal(err)
	}
	if malformedText != "not-a-time" || malformedNS.Valid {
		t.Fatalf("malformed row changed: ts=%q unix=%+v", malformedText, malformedNS)
	}
	third, err := st.BackfillEventTimes(context.Background(), 2)
	if err != nil || !third.Done || third.Scanned != 0 {
		t.Fatalf("completed backfill rerun=%+v err=%v", third, err)
	}
}
