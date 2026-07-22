package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestAppendJournalEventAtomicDeduplicatesRawLine(t *testing.T) {
	st := openJournalAtomicTestStore(t)
	ts := time.Date(2026, 7, 22, 8, 9, 10, 123456789, time.UTC)
	raw := "Jul 22 08:09:10 host sshd[123]: Failed password for root from 203.0.113.44 port 49200 ssh2"

	first, firstUpdate := journalAtomicFixture(ts, raw, 1)
	replay, replayUpdate := journalAtomicFixture(ts, raw, 99)

	inserted, err := st.AppendJournalEventAtomic(first, firstUpdate)
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	if !inserted {
		t.Fatal("first append reported duplicate")
	}
	if first.ID == 0 {
		t.Fatal("first append did not publish the generated event ID")
	}

	inserted, err = st.AppendJournalEventAtomic(replay, replayUpdate)
	if err != nil {
		t.Fatalf("replay append: %v", err)
	}
	if inserted {
		t.Fatal("exact replay was inserted")
	}
	if replay.ID != 0 {
		t.Fatalf("duplicate event ID = %d, want original 0", replay.ID)
	}

	assertJournalAtomicCounts(t, st, 1, 1, 1, 1, 1)

	// Raw is part of the identity: changing only the original journal line
	// must not collapse a distinct observation that shares the parsed fields.
	differentRaw, differentRawUpdate := journalAtomicFixture(ts, raw+" [repeat]", 2)
	inserted, err = st.AppendJournalEventAtomic(differentRaw, differentRawUpdate)
	if err != nil {
		t.Fatalf("different-raw append: %v", err)
	}
	if !inserted {
		t.Fatal("event differing only in Raw was treated as a duplicate")
	}
	if differentRaw.ID == 0 || differentRaw.ID == first.ID {
		t.Fatalf("different-raw event ID = %d, first ID = %d", differentRaw.ID, first.ID)
	}

	assertJournalAtomicCounts(t, st, 2, 1, 2, 2, 2)
}

func TestAppendJournalEventAtomicRollsBackEventOnActorFailure(t *testing.T) {
	st := openJournalAtomicTestStore(t)
	if _, err := st.execWrite(`
CREATE TRIGGER reject_journal_actor
BEFORE INSERT ON actors
BEGIN
  SELECT RAISE(ABORT, 'journal actor rejected');
END`); err != nil {
		t.Fatalf("create actor rejection trigger: %v", err)
	}

	ts := time.Date(2026, 7, 22, 9, 10, 11, 0, time.UTC)
	event, update := journalAtomicFixture(ts, "failed journal line", 1)
	event.ID = 4242

	inserted, err := st.AppendJournalEventAtomic(event, update)
	if err == nil {
		t.Fatal("append succeeded despite actor trigger failure")
	}
	if inserted {
		t.Fatal("append reported inserted after actor trigger failure")
	}
	if event.ID != 4242 {
		t.Fatalf("caller event ID = %d, want original 4242", event.ID)
	}
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM events`); got != 0 {
		t.Fatalf("events after actor failure = %d, want 0", got)
	}
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM actors`); got != 0 {
		t.Fatalf("actors after actor failure = %d, want 0", got)
	}
}

func TestAppendJournalAcceptedAtomicWithoutActor(t *testing.T) {
	st := openJournalAtomicTestStore(t)
	ts := time.Date(2026, 7, 22, 10, 11, 12, 987654321, time.UTC)
	makeEvent := func() *models.Event {
		return &models.Event{
			TS:       ts,
			Source:   models.SourceJournal,
			Kind:     models.KindAccepted,
			SrcIP:    "198.51.100.27",
			SrcPort:  58321,
			Username: "deploy",
			Raw:      "Jul 22 10:11:12 host sshd[456]: Accepted publickey for deploy from 198.51.100.27 port 58321 ssh2",
		}
	}

	accepted := makeEvent()
	inserted, err := st.AppendJournalEventAtomic(accepted, nil)
	if err != nil {
		t.Fatalf("accepted append: %v", err)
	}
	if !inserted {
		t.Fatal("accepted event was not inserted")
	}
	if accepted.ID == 0 {
		t.Fatal("accepted append did not publish the generated event ID")
	}

	replay := makeEvent()
	inserted, err = st.AppendJournalEventAtomic(replay, nil)
	if err != nil {
		t.Fatalf("accepted replay: %v", err)
	}
	if inserted {
		t.Fatal("accepted replay was inserted")
	}
	if replay.ID != 0 {
		t.Fatalf("accepted replay ID = %d, want original 0", replay.ID)
	}
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM events`); got != 1 {
		t.Fatalf("accepted event count = %d, want 1", got)
	}
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM actors`); got != 0 {
		t.Fatalf("accepted actor count = %d, want 0", got)
	}
}

func openJournalAtomicTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "journal-atomic.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return st
}

func journalAtomicFixture(ts time.Time, raw string, count int) (*models.Event, *JournalActorUpdate) {
	const ip = "203.0.113.44"
	const actorID = "journal:" + ip
	event := &models.Event{
		TS:       ts,
		Source:   models.SourceJournal,
		Kind:     models.KindFailedPass,
		SrcIP:    ip,
		SrcPort:  49200,
		Username: "root",
		Raw:      raw,
		ActorID:  actorID,
	}
	update := &JournalActorUpdate{
		Actor: &models.Actor{
			ID:              actorID,
			Source:          models.SourceJournal,
			PrimaryIP:       ip,
			Playbook:        "service_account_enum",
			Intent:          "unknown",
			Confidence:      60,
			FirstSeen:       ts,
			LastSeen:        ts,
			EventCount:      count,
			UniqueUsers:     1,
			AttemptsPerHour: float64(count),
			ProbeScore:      55,
		},
		IPFirst:   ts,
		IPLast:    ts,
		IPCount:   count,
		Username:  "root",
		UserCount: count,
	}
	return event, update
}

func assertJournalAtomicCounts(t *testing.T, st *Store, events, actors, actorEvents, ipCount, userCount int) {
	t.Helper()
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM events`); got != events {
		t.Fatalf("event count = %d, want %d", got, events)
	}
	if got := journalAtomicScalar(t, st, `SELECT COUNT(*) FROM actors`); got != actors {
		t.Fatalf("actor count = %d, want %d", got, actors)
	}
	if got := journalAtomicScalar(t, st, `SELECT event_count FROM actors WHERE id = ?`, "journal:203.0.113.44"); got != actorEvents {
		t.Fatalf("actor event_count = %d, want %d", got, actorEvents)
	}
	if got := journalAtomicScalar(t, st, `SELECT count FROM actor_ips WHERE actor_id = ? AND ip = ?`, "journal:203.0.113.44", "203.0.113.44"); got != ipCount {
		t.Fatalf("actor IP count = %d, want %d", got, ipCount)
	}
	if got := journalAtomicScalar(t, st, `SELECT count FROM actor_users WHERE actor_id = ? AND username = ?`, "journal:203.0.113.44", "root"); got != userCount {
		t.Fatalf("actor user count = %d, want %d", got, userCount)
	}
}

func journalAtomicScalar(t *testing.T, st *Store, query string, args ...any) int {
	t.Helper()
	var got int
	if err := st.db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("query scalar: %v", err)
	}
	return got
}
