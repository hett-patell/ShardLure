package store

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestEventWindowUsesExactMixedTimestampsAndStableIDs(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "events-window-time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	texts := []string{
		"2026-01-01T13:59:59.900000000+14:00", // before cutoff
		"2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00.100000000Z",
		"2025-12-31T10:00:01-14:00", // one second after cutoff
		"2026-01-01T00:00:02Z",
		"2026-01-01T00:00:02.000000000Z",
	}
	var ids []int64
	for _, ts := range texts {
		res, err := st.db.Exec(`INSERT INTO events(ts,source,kind) VALUES(?,?,?)`,
			ts, "journal", "failed_password")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		ids = append(ids, id)
	}

	recent, err := st.EventsSince(since, 3)
	if err != nil {
		t.Fatal(err)
	}
	gotRecent := eventIDs(recent)
	wantRecent := []int64{ids[5], ids[4], ids[3]}
	if !reflect.DeepEqual(gotRecent, wantRecent) {
		t.Fatalf("recent IDs=%v, want %v", gotRecent, wantRecent)
	}

	capped, total, err := st.EventsSinceCapped(since, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || !reflect.DeepEqual(eventIDs(capped), wantRecent) {
		t.Fatalf("capped IDs=%v total=%d, want %v total=5", eventIDs(capped), total, wantRecent)
	}

	var asc []int64
	if err := st.IterateEventsSince(since, func(e *models.Event) error {
		asc = append(asc, e.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantAsc := []int64{ids[1], ids[2], ids[3], ids[4], ids[5]}
	if !reflect.DeepEqual(asc, wantAsc) {
		t.Fatalf("ascending IDs=%v, want %v", asc, wantAsc)
	}
}

func TestEventWindowRejectsMalformedCandidateTimestamp(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "events-window-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind) VALUES('zzzz','journal','failed_password')`); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.EventsSince(since, 10); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("EventsSince error=%v, want contextual timestamp error", err)
	}
	if _, _, err := st.EventsSinceCapped(since, 10); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("EventsSinceCapped error=%v, want contextual timestamp error", err)
	}
	if err := st.IterateEventsSince(since, func(*models.Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("IterateEventsSince error=%v, want contextual timestamp error", err)
	}
}

func eventIDs(events []*models.Event) []int64 {
	ids := make([]int64, len(events))
	for i, event := range events {
		ids[i] = event.ID
	}
	return ids
}
