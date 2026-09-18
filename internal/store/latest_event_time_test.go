package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLatestEventTimeUsesExactInstant(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "latest-event.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, ts := range []string{
		"2026-01-01T01:00:00+02:00",
		"2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00.100000000Z",
	} {
		if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind) VALUES(?,?,?)`,
			ts, "journal", "failed_password"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.LatestEventTime()
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 1, 1, 0, 0, 0, int(100*time.Millisecond), time.UTC)
	if !got.Equal(want) {
		t.Fatalf("latest=%v, want %v", got, want)
	}
}

func TestLatestEventTimeRejectsMalformedTimestamp(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "latest-event-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind) VALUES('zzzz','journal','failed_password')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LatestEventTime(); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("error=%v, want contextual timestamp failure", err)
	}
}
