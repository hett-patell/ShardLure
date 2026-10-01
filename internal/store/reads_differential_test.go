package store

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestBoundedReadsMatchOraclesOnRandomData is the committed form of the
// store-reads audit's differential probe (Minor 4). The hand-written fixtures
// for the bounded /api/intel rewrites have no tie between a legacy row and a
// native row at the same instant, no whitespace-only command (" " is a command
// to both old and new code), and no NULL session_id or journal rows carrying
// commands in the shell-session case. Each fixed seed writes a mixed table with
// all of those, drawn from a small set of instants so exact-time ties are
// frequent within and across the native/legacy branches, legacy text written
// with -14h, +14h and +5:30 offsets (so it sorts on the wrong side of the
// window edge), and compares every new read with its old form:
//   - LastCommandsForActors with the whole-history ROW_NUMBER query;
//   - RecentCommands at several limits with orderedGlobalEventQuery;
//   - recentEventCountsByActor with the exact-time iterator;
//   - the command-floor session page with grouping the whole window.
func TestBoundedReadsMatchOraclesOnRandomData(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	since := base.Add(-6 * time.Hour)
	zones := []*time.Location{time.UTC, time.FixedZone("w", -14*3600), time.FixedZone("e", 14*3600), time.FixedZone("ist", 5*3600+1800)}
	commands := []any{nil, "", " ", "ls", "uname -a", "http://198.51.100.7/x", "cat /proc/cpuinfo"}
	actors := []any{nil, "", "cowrie:a", "cowrie:b", "cowrie:c", "journal:198.51.100.9", "cowrie:d"}
	sessions := []any{nil, "", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"}
	kinds := []string{"command", "connect", "file_download", "session_closed", "login_failed"}
	for seed := int64(1); seed <= 8; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			st := newTestStore(t, "reads_diff.db")
			instants := make([]time.Time, 40)
			for i := range instants {
				// Some before the window edge, most inside it; whole and
				// fractional seconds, so both RFC3339 spellings appear.
				instants[i] = since.Add(time.Duration(rng.Intn(9*3600)-2*3600)*time.Second + time.Duration(rng.Intn(2))*time.Duration(rng.Intn(1e9)))
			}
			tx, err := st.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			// The shapes the hand-written fixtures lack must actually occur.
			type branches struct{ legacy, native bool }
			tie := map[int]*branches{}
			var blank, nullSession, journalCmd bool
			for range 700 {
				idx := rng.Intn(len(instants))
				at := instants[idx]
				if tie[idx] == nil {
					tie[idx] = &branches{}
				}
				source := "cowrie"
				if rng.Intn(5) == 0 {
					source = "journal"
				}
				cols := []any{kinds[rng.Intn(len(kinds))], commands[rng.Intn(len(commands))], actors[rng.Intn(len(actors))], sessions[rng.Intn(len(sessions))], source}
				hasCmd := cols[1] != nil && cols[1] != ""
				blank = blank || cols[1] == " "
				nullSession = nullSession || (hasCmd && cols[3] == nil)
				journalCmd = journalCmd || (hasCmd && source == "journal")
				if rng.Intn(4) == 0 { // legacy: no ts_unix_ns, offset text
					tie[idx].legacy = true
					ts := at.In(zones[rng.Intn(len(zones))]).Format(time.RFC3339Nano)
					_, err = tx.Exec(`INSERT INTO events(ts,kind,command,actor_id,session_id,source,src_ip) VALUES(?,?,?,?,?,?,'192.0.2.4')`, append([]any{ts}, cols...)...)
				} else {
					tie[idx].native = true
					_, err = tx.Exec(`INSERT INTO events(ts,ts_unix_ns,kind,command,actor_id,session_id,source,src_ip) VALUES(?,?,?,?,?,?,?,'192.0.2.4')`, append([]any{formatFixedUTC(at), at.UnixNano()}, cols...)...)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			crossTie := false
			for _, b := range tie {
				crossTie = crossTie || (b.legacy && b.native)
			}
			if !crossTie || !blank || !nullSession || !journalCmd {
				t.Fatalf("seed lacks a shape: crossTie=%v blank=%v nullSession=%v journalCmd=%v", crossTie, blank, nullSession, journalCmd)
			}

			ids := []string{"cowrie:a", "cowrie:b", "cowrie:c", "cowrie:d", "journal:198.51.100.9", "cowrie:missing", ""}
			wantLast, err := lastCommandsWholeHistory(st, ids)
			if err != nil {
				t.Fatal(err)
			}
			gotLast, err := st.LastCommandsForActors(ids)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotLast, wantLast) {
				t.Fatalf("LastCommandsForActors:\n got %v\nwant %v", gotLast, wantLast)
			}

			for _, limit := range []int{1, 3, 17, 50, 120, 5000} {
				want, err := recentCommandsWholeWindow(st, limit)
				if err != nil {
					t.Fatal(err)
				}
				got, err := st.RecentCommands(limit)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("RecentCommands(%d): got %d rows, want %d\n got %+v\nwant %+v", limit, len(got), len(want), got[:min(3, len(got))], want[:min(3, len(want))])
				}
			}

			wantCounts := map[string]int{}
			if err := st.IterateEventsSinceContext(context.Background(), since, func(e *models.Event) error {
				if e.ActorID != "" {
					wantCounts[e.ActorID]++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			gotCounts, err := st.recentEventCountsByActor(context.Background(), since)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotCounts, wantCounts) {
				t.Fatalf("recentEventCountsByActor:\n got %v\nwant %v", gotCounts, wantCounts)
			}

			all, _, err := st.sessionSummaryPage(since, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, minCommands := range []int{1, 2} {
				var want []ShellSessionSummary
				for _, s := range all {
					if s.CmdCount >= minCommands {
						want = append(want, s)
					}
				}
				sort.SliceStable(want, func(i, j int) bool {
					if !want[i].EndTS.Equal(want[j].EndTS) {
						return want[i].EndTS.After(want[j].EndTS)
					}
					return want[i].ID < want[j].ID
				})
				for _, limit := range []int{0, 2, 30} {
					got, total, err := st.sessionSummaryPage(since, minCommands, limit)
					if err != nil {
						t.Fatal(err)
					}
					w := want
					if limit > 0 && len(w) > limit {
						w = w[:limit]
					}
					if total != len(want) || !reflect.DeepEqual(got, w) {
						t.Fatalf("sessions min %d limit %d: total %d want %d\n got %+v\nwant %+v", minCommands, limit, total, len(want), got, w)
					}
				}
			}
		})
	}
}
