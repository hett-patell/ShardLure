package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpsertActorIPComparesExactInstants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "actor-ip-time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := upsertActorIP(st.db, "actor:fractional", "8.8.8.8", base, base, 1); err != nil {
		t.Fatal(err)
	}
	later := base.Add(100 * time.Millisecond)
	if err := upsertActorIP(st.db, "actor:fractional", "8.8.8.8", later, later, 2); err != nil {
		t.Fatal(err)
	}
	assertActorIPTimes(t, st, "actor:fractional", "8.8.8.8", base, later)

	earlierOffset := "2026-01-01T01:00:00+02:00"
	if _, err := st.db.Exec(`INSERT INTO actor_ips(actor_id,ip,first_seen,last_seen,count) VALUES(?,?,?,?,1)`,
		"actor:offset", "1.1.1.1", earlierOffset, earlierOffset); err != nil {
		t.Fatal(err)
	}
	incoming := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)
	if err := upsertActorIP(st.db, "actor:offset", "1.1.1.1", incoming, incoming, 2); err != nil {
		t.Fatal(err)
	}
	wantFirst, _ := time.Parse(time.RFC3339Nano, earlierOffset)
	assertActorIPTimes(t, st, "actor:offset", "1.1.1.1", wantFirst, incoming)
}

func TestUpsertActorIPRejectsMalformedPersistedTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "actor-ip-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := st.db.Exec(`INSERT INTO actor_ips(actor_id,ip,first_seen,last_seen,count) VALUES(?,?,?,?,1)`,
		"actor:bad", "9.9.9.9", "not-a-time", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	err = upsertActorIP(st.db, "actor:bad", "9.9.9.9", time.Now(), time.Now(), 2)
	if err == nil {
		t.Fatal("malformed persisted timestamp must fail closed")
	}
	if !strings.Contains(err.Error(), "actor:bad") || !strings.Contains(err.Error(), "9.9.9.9") {
		t.Fatalf("error lacks row identity: %v", err)
	}
}

func assertActorIPTimes(t *testing.T, st *Store, actorID, ip string, wantFirst, wantLast time.Time) {
	t.Helper()
	var firstText, lastText string
	if err := st.db.QueryRow(`SELECT first_seen,last_seen FROM actor_ips WHERE actor_id=? AND ip=?`,
		actorID, ip).Scan(&firstText, &lastText); err != nil {
		t.Fatal(err)
	}
	first, err := time.Parse(time.RFC3339Nano, firstText)
	if err != nil {
		t.Fatal(err)
	}
	last, err := time.Parse(time.RFC3339Nano, lastText)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(wantFirst) || !last.Equal(wantLast) {
		t.Fatalf("first/last = %v/%v, want %v/%v", first, last, wantFirst, wantLast)
	}
}
