package cowrie

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestLateHASSHTwoSessionsPersistCanonicalFingerprint(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:01Z","src_ip":"1.2.3.4","username":"root","session":"first"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T11:00:02Z","session":"first","hassh":"shared"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T12:00:01Z","src_ip":"5.6.7.8","username":"admin","session":"second"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T12:00:02Z","session":"second","hassh":"shared"}`)
	for i := 0; i < 2; i++ {
		if _, err := IngestFileAppend(st, path, nil); err != nil {
			t.Fatal(err)
		}
	}
	events, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	for _, e := range events {
		if e.ActorID != "cowrie:shared" || e.HASSH != "shared" {
			t.Errorf("noncanonical event: actor=%q hassh=%q", e.ActorID, e.HASSH)
		}
	}
	actors := snapshotActors(t, st)
	if len(actors) != 1 || actors["cowrie:shared"].EventCount != 2 {
		t.Fatalf("actors=%+v", actors)
	}
}

func TestLateHASSHRollsBackAndRetriesWithoutAdvancingOffset(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:01Z","src_ip":"1.2.3.4","username":"root","session":"retry"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	before, _, err := st.GetIngestState(models.SourceCowrie, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER reject_reconcile BEFORE UPDATE OF hassh ON events BEGIN SELECT RAISE(ABORT,'injected reconciliation failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T11:00:02Z","session":"retry","hassh":"shared"}`)
	if _, err := IngestFileAppend(st, path, nil); err == nil {
		t.Fatal("reconciliation failure swallowed")
	}
	after, _, err := st.GetIngestState(models.SourceCowrie, path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Offset != before.Offset {
		t.Fatal("offset advanced past failed reconciliation")
	}
	a, err := st.GetActor("cowrie:1.2.3.4")
	if err != nil || a.EventCount != 1 {
		t.Fatalf("transaction did not roll back: %v %+v", err, a)
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec(`DROP TRIGGER reject_reconcile`); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	a, err = st.GetActor("cowrie:shared")
	if err != nil || a.EventCount != 1 {
		t.Fatalf("retry: %v %+v", err, a)
	}
}

func TestLateHASSHDoesNotMoveJournalOrAdminEvents(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:01Z","src_ip":"1.2.3.4","username":"root","session":"same"}`)
	if _, err := IngestFileAppend(st, path, []string{"1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO events(ts,source,kind,src_ip,session_id,actor_id,hassh) VALUES('2026-07-03T11:00:01Z','journal','failed_pass','5.6.7.8','same','journal:5.6.7.8','')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T11:00:02Z","session":"same","hassh":"shared"}`)
	if _, err := IngestFileAppend(st, path, []string{"1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT source,actor_id FROM events ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var source, id string
			if err := rows.Scan(&source, &id); err != nil {
				return err
			}
			if source == "cowrie" && id != "" || source == "journal" && id != "journal:5.6.7.8" {
				return errors.New("exempt or non-Cowrie event moved")
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLateHASSHBindingWriteFailureRetriesAfterReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:01Z","src_ip":"1.2.3.4","username":"root","session":"retry"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER reject_binding BEFORE INSERT ON cowrie_session_hassh BEGIN SELECT RAISE(ABORT,'injected binding failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T11:00:02Z","session":"retry","hassh":"shared"}`)
	if _, err := IngestFileAppend(st, path, nil); err == nil {
		t.Fatal("binding failure swallowed; future ticks lose canonical identity")
	}
	if err := st.WithTx(func(tx *sql.Tx) error { _, err := tx.Exec(`DROP TRIGGER reject_binding`); return err }); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:03Z","src_ip":"1.2.3.4","username":"admin","session":"retry"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	a, err := st.GetActor("cowrie:shared")
	if err != nil || a.EventCount != 2 {
		t.Fatalf("lost identity after restart: %v %+v", err, a)
	}
}

func TestLateHASSHPreservesRetainedLifetimeAndAnnotations(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, a := range []*models.Actor{
		{ID: "cowrie:1.2.3.4", Source: models.SourceCowrie, PrimaryIP: "1.2.3.4", FirstSeen: first, LastSeen: first, EventCount: 100, Flags: models.ActorFlagAuth, Campaigns: "old campaign", Notes: "operator old"},
		{ID: "cowrie:shared", Source: models.SourceCowrie, PrimaryIP: "9.9.9.9", HASSH: "shared", FirstSeen: first, LastSeen: first, EventCount: 200, Flags: models.ActorFlagAuth, Campaigns: "target campaign", Notes: "operator target"},
	} {
		seedActorState(t, st, a, map[string]int{"historic": a.EventCount}, map[string]models.IPStat{a.PrimaryIP: {Count: a.EventCount, First: first, Last: first}})
	}
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-07-03T11:00:01Z","src_ip":"1.2.3.4","username":"root","session":"late"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	// Set notes after ingestion: this assertion isolates reconciliation, not
	// the independently-existing classifier's generated-note behavior.
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE actors SET notes='operator old' WHERE id='cowrie:1.2.3.4'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-07-03T11:00:02Z","session":"late","hassh":"shared"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatal(err)
	}
	states, err := st.ActorStatesForIDs([]string{"cowrie:1.2.3.4", "cowrie:shared"})
	if err != nil {
		t.Fatal(err)
	}
	old, target := states["cowrie:1.2.3.4"], states["cowrie:shared"]
	if old == nil || old.Actor.EventCount != 100 || old.Users["historic"] != 100 || old.Users["root"] != 0 {
		t.Fatalf("lost old lifetime totals: %+v", old)
	}
	if target == nil || target.Actor.EventCount != 201 || target.Users["historic"] != 200 || target.Users["root"] != 1 {
		t.Fatalf("lost target lifetime totals: %+v", target)
	}
	if old.Actor.Notes != "operator old" || target.Actor.Notes != "operator target" || old.Actor.Campaigns != "old campaign" || target.Actor.Campaigns != "target campaign" {
		t.Fatal("operator annotations changed")
	}
	if !target.Actor.FirstSeen.Equal(first) {
		t.Fatal("historical first seen lost")
	}
}

func TestReconcilePreservesAnnotationThatLooksGenerated(t *testing.T) {
	// Arbitrary operator text keeps an emptied pre-HASSH actor, even when it
	// quotes classifier output. Exact legacy builder output ("N events, M
	// usernames", written into notes on every rebuild before v23) does not:
	// keeping it left a zero-event duplicate of every legacy actor that later
	// gained a fingerprint (see store.isOperatorNote).
	for _, tc := range []struct {
		note string
		keep bool
	}{
		{"1 events, 1 usernames - same box as last week", true},
		{"1 events, 1 usernames", false},
	} {
		st := openTestStore(t)
		path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-09-21T10:00:00Z","src_ip":"1.2.3.4","username":"root","session":"annotated"}`)
		if _, err := IngestFileAppend(st, path, nil); err != nil {
			t.Fatal(err)
		}
		if err := st.WithTx(func(tx *sql.Tx) error {
			_, err := tx.Exec("UPDATE actors SET notes=? WHERE id='cowrie:1.2.3.4'", tc.note)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		appendLine(t, path, `{"eventid":"cowrie.client.kex","timestamp":"2026-09-21T10:00:01Z","session":"annotated","hassh":"annotation-target"}`)
		if _, err := IngestFileAppend(st, path, nil); err != nil {
			t.Fatal(err)
		}
		old, err := st.GetActor("cowrie:1.2.3.4")
		if tc.keep && (err != nil || old == nil || old.Notes != tc.note || old.EventCount != 0) {
			t.Errorf("note %q: annotation-bearing actor removed: %+v err=%v", tc.note, old, err)
		}
		if !tc.keep && err == nil && old != nil {
			t.Errorf("note %q: legacy builder text kept an emptied actor: %+v", tc.note, old)
		}
		st.Close()
	}
}
