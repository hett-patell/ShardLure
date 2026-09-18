package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func countRows(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

func seedActor(t *testing.T, s *Store, id string, last time.Time, campaigns, notes string) {
	t.Helper()
	a := &models.Actor{
		ID: id, Source: models.SourceCowrie, PrimaryIP: "10.9.9.9",
		Playbook: "unknown", EventCount: 4, Campaigns: campaigns, Notes: notes,
		FirstSeen: last.Add(-time.Hour), LastSeen: last,
	}
	if err := s.UpsertActor(a); err != nil {
		t.Fatalf("upsert %s: %v", id, err)
	}
	if err := upsertActorIP(s.db, id, "10.9.9.9", last.Add(-time.Hour), last, 4); err != nil {
		t.Fatalf("upsert ip for %s: %v", id, err)
	}
	if err := upsertActorUser(s.db, id, "root", 4); err != nil {
		t.Fatalf("upsert user for %s: %v", id, err)
	}
}

// MaintenancePurge deleted events but left the actor rows derived from them.
// Those orphans kept a stale event_count, a playbook frozen at whatever the
// classifier said months ago (102 of 103 on prod read "unknown", which was the
// entire residual unknown population), and they inflated the dashboard's actor
// count with attackers whose evidence no longer exists.
func TestMaintenancePurgeDeletesOrphanActors(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "purge-orphans.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now().UTC()
	old := now.Add(-60 * 24 * time.Hour)

	seedActor(t, s, "cowrie:orphan", old, "", "")      // no events, aged out -> delete
	seedActor(t, s, "cowrie:fresh", now, "", "")       // recent, mid-ingest -> keep
	seedActor(t, s, "cowrie:hasevents", old, "", "")   // still has an event -> keep
	seedActor(t, s, "cowrie:tagged", old, "mirai", "") // operator campaign tag -> keep

	// `notes` is NOT an operator field: actor.builder regenerates it on every
	// rebuild ("2 events, 0 usernames"), so EVERY actor on a live deployment
	// has one — guarding on it made the sweep delete nothing at all (verified
	// against prod: 6,716 of 6,716 actors carried a generated note, so the
	// orphan count the sweep would have removed was 0 instead of 103).
	seedActor(t, s, "cowrie:machine-note", old, "", "2 events, 0 usernames")

	// One surviving event, timestamped inside the retention window, belonging
	// to cowrie:hasevents.
	if err := s.InsertEvent(&models.Event{
		TS: now.Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindFailedPass,
		SrcIP: "10.9.9.9", Username: "root", ActorID: "cowrie:hasevents",
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	if err := s.MaintenancePurge(30); err != nil {
		t.Fatalf("MaintenancePurge: %v", err)
	}

	for _, tc := range []struct {
		id   string
		want int
	}{
		{"cowrie:orphan", 0},
		{"cowrie:machine-note", 0},
		{"cowrie:tagged", 1},
		{"cowrie:fresh", 1},
		{"cowrie:hasevents", 1},
	} {
		if got := countRows(t, s, `SELECT COUNT(1) FROM actors WHERE id=?`, tc.id); got != tc.want {
			t.Errorf("actors[%s] = %d rows, want %d", tc.id, got, tc.want)
		}
	}

	// The orphan's child rows must go with it — otherwise actor_ips/actor_users
	// accumulate rows pointing at an actor that no longer exists.
	if got := countRows(t, s, `SELECT COUNT(1) FROM actor_ips WHERE actor_id=?`, "cowrie:orphan"); got != 0 {
		t.Errorf("actor_ips for deleted orphan = %d, want 0", got)
	}
	if got := countRows(t, s, `SELECT COUNT(1) FROM actor_users WHERE actor_id=?`, "cowrie:orphan"); got != 0 {
		t.Errorf("actor_users for deleted orphan = %d, want 0", got)
	}
	// The kept actors' children must survive.
	if got := countRows(t, s, `SELECT COUNT(1) FROM actor_ips WHERE actor_id=?`, "cowrie:tagged"); got != 1 {
		t.Errorf("actor_ips for campaign-tagged actor = %d, want 1", got)
	}
}

func TestMaintenancePurgeOrphanActorsUsesExactMixedTimes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "purge-orphan-time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cutoff := time.Now().UTC().AddDate(0, 0, -30)
	seedActor(t, st, "cowrie:fresh-offset", cutoff.Add(2*time.Hour), "", "")
	seedActor(t, st, "cowrie:old-offset", cutoff.Add(-2*time.Hour), "", "")
	freshText := cutoff.Add(2 * time.Hour).In(time.FixedZone("minus-14", -14*60*60)).Format(time.RFC3339Nano)
	oldText := cutoff.Add(-2 * time.Hour).In(time.FixedZone("plus-14", 14*60*60)).Format(time.RFC3339Nano)
	if _, err := st.db.Exec(`UPDATE actors SET first_seen=?,last_seen=? WHERE id='cowrie:fresh-offset'`, freshText, freshText); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE actors SET first_seen=?,last_seen=? WHERE id='cowrie:old-offset'`, oldText, oldText); err != nil {
		t.Fatal(err)
	}
	if err := st.MaintenancePurge(30); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM actors WHERE id='cowrie:fresh-offset'`); got != 1 {
		t.Fatalf("fresh offset actor rows=%d, want 1", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM actors WHERE id='cowrie:old-offset'`); got != 0 {
		t.Fatalf("old offset actor rows=%d, want 0", got)
	}
}

func TestMaintenancePurgeRejectsMalformedOrphanActorTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "purge-orphan-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedActor(t, st, "cowrie:bad-time", time.Now().Add(-90*24*time.Hour), "", "")
	if _, err := st.db.Exec(`UPDATE actors SET last_seen='not-a-time' WHERE id='cowrie:bad-time'`); err != nil {
		t.Fatal(err)
	}
	if err := st.MaintenancePurge(30); err == nil {
		t.Fatal("malformed orphan actor timestamp must stop retention")
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM actors WHERE id='cowrie:bad-time'`); got != 1 {
		t.Fatalf("malformed actor rows=%d, want 1", got)
	}
}

// Retention disabled must stay a complete no-op, including for actors.
func TestMaintenancePurgeZeroRetentionKeepsOrphans(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "purge-noop.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	seedActor(t, s, "cowrie:orphan", time.Now().UTC().Add(-400*24*time.Hour), "", "")
	if err := s.MaintenancePurge(0); err != nil {
		t.Fatalf("MaintenancePurge(0): %v", err)
	}
	if got := countRows(t, s, `SELECT COUNT(1) FROM actors WHERE id=?`, "cowrie:orphan"); got != 1 {
		t.Fatalf("retention disabled still deleted an actor (%d rows)", got)
	}
}
