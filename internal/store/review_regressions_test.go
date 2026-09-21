package store

import (
	"context"
	"github.com/networkshard/shardlure/pkg/models"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLegacyEventDedupDuringTimestampBackfill(t *testing.T) {
	for _, source := range []models.Source{models.SourceJournal, models.SourceCowrie} {
		for _, fraction := range []time.Duration{0, 100 * time.Millisecond, 123456789 * time.Nanosecond} {
			t.Run(string(source)+"/"+fraction.String(), func(t *testing.T) {
				st := newTestStore(t, "legacy-dedup.db")
				ts := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC).Add(fraction)
				e := &models.Event{TS: ts, Source: source, Kind: models.KindFailedPass, SrcIP: "8.8.8.8", SrcPort: 1234, Username: "root", Raw: "same journal line", SessionID: "session"}
				_, err := st.db.Exec("INSERT INTO events(ts,source,kind,src_ip,src_port,username,raw,session_id) VALUES(?,?,?,?,?,?,?,?)", ts.Format(time.RFC3339Nano), e.Source, e.Kind, e.SrcIP, e.SrcPort, e.Username, e.Raw, e.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				check := func() {
					t.Helper()
					for _, keys := range [][]string{
						{CanonicalEventTime(ts)},
						{ts.Format(time.RFC3339Nano)},
						{CanonicalEventTime(ts), ts.Format(time.RFC3339Nano), CanonicalEventTime(ts)},
					} {
						var ids []EventIdentity
						err := st.IterateEventIdentitiesByTS(source, keys, func(id EventIdentity) { ids = append(ids, id) })
						if err != nil {
							t.Fatal(err)
						}
						if len(ids) != 1 || ids[0].TS != CanonicalEventTime(ts) {
							t.Errorf("keys=%v dedup identities=%+v, want one canonical match", keys, ids)
						}
					}
					if source == models.SourceJournal {
						inserted, err := st.AppendJournalEventAtomic(e, nil)
						if err != nil {
							t.Fatal(err)
						}
						if inserted {
							t.Error("duplicate legacy journal event was inserted")
						}
					}
				}
				check()
				if _, err := st.BackfillEventTimes(context.Background(), 100); err != nil {
					t.Fatal(err)
				}
				check()
			})
		}
	}
}

func TestExactEventOrderAcrossTimestampMigration(t *testing.T) {
	for _, legacyIsEarlier := range []bool{true, false} {
		t.Run(map[bool]string{true: "legacy earlier", false: "legacy later"}[legacyIsEarlier], func(t *testing.T) {
			st := newTestStore(t, "mixed-order.db")
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			earlier, later := base.Add(600*time.Microsecond), base.Add(900*time.Microsecond)
			legacyTS, nativeTS := earlier, later
			if !legacyIsEarlier {
				legacyTS, nativeTS = later, earlier
			}
			res, err := st.db.Exec("INSERT INTO events(ts,source,kind,actor_id) VALUES(?,?,?,?)", legacyTS.Format(time.RFC3339Nano), "cowrie", "command", "cowrie:a")
			if err != nil {
				t.Fatal(err)
			}
			legacyID, _ := res.LastInsertId()
			e := &models.Event{TS: nativeTS, Source: models.SourceCowrie, Kind: models.KindCommand, ActorID: "cowrie:a"}
			if err := st.InsertEvent(e); err != nil {
				t.Fatal(err)
			}
			want := []int64{legacyID, e.ID}
			if !legacyIsEarlier {
				want = []int64{e.ID, legacyID}
			}
			for _, phase := range []string{"mixed", "backfilled"} {
				if phase == "backfilled" {
					if _, err := st.BackfillEventTimes(context.Background(), 100); err != nil {
						t.Fatal(err)
					}
				}
				check := func(label string, iterate func(func(*models.Event) error) error) {
					t.Helper()
					var ids []int64
					err := iterate(func(e *models.Event) error { ids = append(ids, e.ID); return nil })
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(ids, want) {
						t.Errorf("%s %s IDs=%v want %v", phase, label, ids, want)
					}
				}
				check("window", func(fn func(*models.Event) error) error { return st.IterateEventsSince(base, fn) })
				check("source", func(fn func(*models.Event) error) error { return st.IterateEventsBySource(models.SourceCowrie, fn) })
				check("actor", func(fn func(*models.Event) error) error { return st.IterateEventsByActorIDs([]string{"cowrie:a"}, fn) })
				latest, err := st.LatestEventTime()
				if err != nil {
					t.Fatal(err)
				}
				if !latest.Equal(later) {
					t.Errorf("%s latest=%s want %s", phase, latest, later)
				}
				top, total, err := st.EventsSinceCapped(base, 1)
				if err != nil {
					t.Fatal(err)
				}
				if total != 2 || len(top) != 1 || top[0].ID != want[1] {
					t.Errorf("%s capped=%v total=%d", phase, top, total)
				}
			}
		})
	}
}

func TestRetentionKeepsRecentlyRedeliveredEvidence(t *testing.T) {
	st := newTestStore(t, "active-evidence.db")
	now := time.Now().UTC()
	old := now.Add(-60 * 24 * time.Hour)
	path := filepath.Join(t.TempDir(), "inert-evidence")
	if err := os.WriteFile(path, []byte("inert fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	u := "cowrie-download:still-active"
	if err := st.RecordArtifact(Artifact{TS: old, URL: u, Origin: "cowrie_download", Status: "fetched", SHA256: "inert", SizeBytes: 128, LocalPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchArtifactTS(u, now); err != nil {
		t.Fatal(err)
	}
	if err := st.MaintenancePurge(30); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM artifacts WHERE url=?", u).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("retention deleted artifact observed again today")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("recently referenced evidence file was removed: %v", err)
	}
}

func TestEventDedupKeepsFormatsTogetherAtChunkBoundary(t *testing.T) {
	st := newTestStore(t, "dedup-chunk.db")
	base := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	first := &models.Event{TS: base, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "8.8.8.8"}
	if err := st.InsertEvent(first); err != nil {
		t.Fatal(err)
	}
	targetTime := base.Add(200 * time.Second)
	if _, err := st.db.Exec("INSERT INTO events(ts,source,kind,src_ip) VALUES(?,?,?,?)", targetTime.Format(time.RFC3339Nano), models.SourceJournal, models.KindFailedPass, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	// 199 two-format instants, then one whose trimmed and fixed strings are
	// identical. Flattening/deduping strings splits the target's two variants
	// across the old 400-parameter boundary.
	var keys []string
	for i := 0; i < 199; i++ {
		keys = append(keys, CanonicalEventTime(base.Add(time.Duration(i)*time.Second)))
	}
	keys = append(keys, CanonicalEventTime(base.Add(199*time.Second+123456789*time.Nanosecond)), CanonicalEventTime(targetTime))
	hits := 0
	converted := false
	err := st.IterateEventIdentitiesByTS(models.SourceJournal, keys, func(id EventIdentity) {
		if id.SrcIP == "9.9.9.9" {
			hits++
		}
		if !converted {
			converted = true
			if _, err := st.BackfillEventTimes(context.Background(), 1000); err != nil {
				t.Error(err)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("backfill between dedup chunks lost target: matches=%d, want 1", hits)
	}
}
