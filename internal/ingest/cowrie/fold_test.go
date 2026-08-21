package cowrie

import (
	"database/sql"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// The fold path (buildCowrieActorsForIDs) aggregates a touched actor by
// seeding the collector from its PERSISTED aggregate (actors + actor_users +
// actor_ips), then folding fresh events — not by re-scanning the actor's
// event history. These tests pin both halves: the fold, and the one-time
// legacy re-scan for pre-v18 (flags=0) rows.

// seedActorState inserts an actors row (+ optional user/ip children) with the
// given flags, bypassing the normal write path so the test controls the
// persisted aggregate exactly.
func seedActorState(t *testing.T, st *store.Store, a *models.Actor, users map[string]int, ips map[string]models.IPStat) {
	t.Helper()
	err := st.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO actors (id, source, primary_ip, playbook, intent, confidence,
			first_seen, last_seen, event_count, unique_users, attempts_per_hour, hassh, ssh_client,
			username_hash, campaigns, probe_score, notes, flags)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, a.Source, a.PrimaryIP, a.Playbook, a.Intent, a.Confidence,
			a.FirstSeen.UTC().Format(time.RFC3339Nano), a.LastSeen.UTC().Format(time.RFC3339Nano),
			a.EventCount, a.UniqueUsers, a.AttemptsPerHour, a.HASSH, a.SSHClient,
			a.UsernameHash, a.Campaigns, a.ProbeScore, a.Notes, a.Flags); err != nil {
			return err
		}
		for u, c := range users {
			if _, err := tx.Exec(`INSERT INTO actor_users (actor_id, username, count) VALUES (?, ?, ?)`, a.ID, u, c); err != nil {
				return err
			}
		}
		for ip, s := range ips {
			if _, err := tx.Exec(`INSERT INTO actor_ips (actor_id, ip, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?)`,
				a.ID, ip, s.First.UTC().Format(time.RFC3339Nano), s.Last.UTC().Format(time.RFC3339Nano), s.Count); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seedActorState: %v", err)
	}
}

// TestFoldUsesPersistedAggregate proves a touched actor's aggregate is
// continued from its persisted state, NOT re-derived from the events table:
// the seeded actor has an event_count of 5 with ZERO matching rows in the
// events table, so any event re-scan would produce a stale aggregate.
func TestFoldUsesPersistedAggregate(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	first := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	last := first.Add(2 * time.Hour)
	seedActorState(t, st, &models.Actor{
		ID:          "cowrie:9.9.9.9",
		Source:      models.SourceCowrie,
		PrimaryIP:   "9.9.9.9",
		Playbook:    "opportunistic",
		Intent:      "probe",
		FirstSeen:   first,
		LastSeen:    last,
		EventCount:  5,
		UniqueUsers: 1,
		Flags:       models.ActorFlagProbe | models.ActorFlagAuth,
		Campaigns:   "operator-note",
	}, map[string]int{"root": 5}, map[string]models.IPStat{
		"9.9.9.9": {Count: 5, First: first, Last: last},
	})

	// One fresh event for the same (IP-keyed) actor.
	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T15:00:00.000000Z","src_ip":"9.9.9.9","username":"root","session":"s9"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	a, err := st.GetActor("cowrie:9.9.9.9")
	if err != nil {
		t.Fatalf("GetActor: %v", err)
	}
	if a.EventCount != 6 {
		t.Errorf("EventCount = %d, want 5 seeded + 1 fresh = 6 (a re-scan of the events table would give 1)", a.EventCount)
	}
	if a.FirstSeen.After(first) || a.FirstSeen.IsZero() {
		t.Errorf("FirstSeen = %v, want the seeded %v preserved", a.FirstSeen, first)
	}
	if !a.LastSeen.After(last) {
		t.Errorf("LastSeen = %v, want it advanced past seeded %v", a.LastSeen, last)
	}
	if a.Campaigns != "operator-note" {
		t.Errorf("Campaigns = %q, want operator annotation preserved", a.Campaigns)
	}
	if a.Flags&models.ActorFlagProbe == 0 || a.Flags&models.ActorFlagAuth == 0 {
		t.Errorf("Flags = %d, want Probe|Auth retained through the fold", a.Flags)
	}

	ags, err := st.ActorStatesForIDs([]string{"cowrie:9.9.9.9"})
	if err != nil {
		t.Fatalf("ActorStatesForIDs: %v", err)
	}
	if got := ags["cowrie:9.9.9.9"].Users["root"]; got != 6 {
		t.Errorf("username count = %d, want 5 seeded + 1 fresh = 6", got)
	}
}

// TestFoldLegacyFallbackRescansOnce: a pre-v18 row (flags=0) can't be folded
// safely — its signals are unknown — so it gets one last full event re-scan,
// after which real flags are persisted and later ticks fold.
func TestFoldLegacyFallbackRescansOnce(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	// Batch 1: two events via the normal path — aggregate written WITH flags.
	path := writeTempCowrieLog(t,
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"7.7.7.7","username":"root","session":"s1"}`+"\n"+
			`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:05:00.000000Z","src_ip":"7.7.7.7","username":"admin","session":"s2"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("batch1: %v", err)
	}

	// Simulate a pre-v18 row: zero its flags, as the v17 schema left them.
	if err := st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE actors SET flags=0 WHERE id=?`, "cowrie:7.7.7.7")
		return err
	}); err != nil {
		t.Fatalf("zero flags: %v", err)
	}

	// Batch 2: one more event for the same actor. The fallback must re-scan
	// the actor's events (2 old + 1 new = 3) and persist real flags.
	appendLine(t, path, `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:10:00.000000Z","src_ip":"7.7.7.7","username":"root","session":"s3"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("batch2: %v", err)
	}

	a, err := st.GetActor("cowrie:7.7.7.7")
	if err != nil {
		t.Fatalf("GetActor: %v", err)
	}
	if a.EventCount != 3 {
		t.Errorf("EventCount = %d, want the 3 events after legacy re-scan", a.EventCount)
	}
	if a.Flags == 0 {
		t.Errorf("Flags = 0 after the fallback fold, want self-healed non-zero flags")
	}
	if a.Playbook != "opportunistic" {
		t.Errorf("Playbook = %q, want opportunistic (root+admin corpus)", a.Playbook)
	}
}
