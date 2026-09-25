package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// Native fixtures use the real writer; legacy fixtures then remove the migration
// marker and restore their original text. Expected membership/order below is
// literal, not computed with the query helpers under test.
func aggregateTimeEvent(t *testing.T, st *Store, raw string, native bool, kind models.EventKind, edit func(*models.Event)) int64 {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		if native {
			t.Fatal(err)
		}
		ts = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	}
	e := &models.Event{TS: ts, Source: models.SourceCowrie, Kind: kind,
		SrcIP: "192.0.2.10", Username: "root", Password: "inert",
		ActorID: "cowrie:fixture", SessionID: "fixture"}
	if edit != nil {
		edit(e)
	}
	if err := st.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	if !native {
		if _, err := st.db.Exec("UPDATE events SET ts=?,ts_unix_ns=NULL WHERE id=?", raw, e.ID); err != nil {
			t.Fatal(err)
		}
	}
	return e.ID
}

func TestCredentialWindowIncludesWholeSecondBoundary(t *testing.T) {
	st := newTestStore(t, "credential-boundary.db")
	cutoff := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for _, d := range []time.Duration{0, 500 * time.Millisecond} {
		if err := st.InsertEvent(&models.Event{TS: cutoff.Add(d), Source: models.SourceJournal,
			Kind: models.KindFailedPass, Username: "root", Password: "inert"}); err != nil {
			t.Fatal(err)
		}
	}
	users, err := st.TopUsernamesSince(cutoff, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Count != 2 {
		t.Fatalf("users=%+v; want root/2", users)
	}
}

func TestCredentialPasswordTotalIncludesLiteralQuestionMark(t *testing.T) {
	st := newTestStore(t, "literal-password.db")
	since := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	if err := st.InsertEvent(&models.Event{TS: since, Source: models.SourceCowrie,
		Kind: models.KindFailedPass, Username: "root", Password: "?"}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.TopPasswordsSince(since, 10)
	if err != nil || len(rows) != 1 || rows[0].Password != "?" {
		t.Fatalf("password list=%+v err=%v", rows, err)
	}
	count, err := st.DistinctCredentialCount("password", since)
	if err != nil || count != 1 {
		t.Fatalf("password total=%d err=%v, want 1", count, err)
	}
}

func TestAggregateCredentialWindowsMixFormatsExactly(t *testing.T) {
	st := newTestStore(t, "credential-formats.db")
	for _, fixture := range []struct {
		raw    string
		native bool
		user   string
	}{
		{"2026-09-21T10:59:59.999999999+01:00", false, "outside"},
		{"2026-09-21T10:00:00Z", true, "root"},
		{"2026-09-21T04:00:00.000000001-06:00", false, "root"},
		{"2026-09-21T10:00:00.5Z", true, "admin"},
		{"2026-09-21T10:00:00.900000001Z", false, "operator"},
	} {
		aggregateTimeEvent(t, st, fixture.raw, fixture.native, models.KindFailedPass,
			func(e *models.Event) { e.Username = fixture.user })
	}
	// Usernames attached to commands are not authentication evidence.
	aggregateTimeEvent(t, st, "2026-09-21T10:00:01Z", true, models.KindCommand, nil)
	cutoff := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for _, stage := range []string{"mixed", "backfilled"} {
		if stage == "backfilled" {
			if _, err := st.BackfillEventTimes(context.Background(), 100); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(stage, func(t *testing.T) {
			users, err := st.TopUsernamesSince(cutoff, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := []CredentialCount{{Username: "root", Count: 2}, {Username: "admin", Count: 1}, {Username: "operator", Count: 1}}
			if !reflect.DeepEqual(users, want) {
				t.Errorf("users=%+v, want %+v", users, want)
			}
			passwords, err := st.TopPasswordsSince(cutoff, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(passwords) != 1 || passwords[0].Password != "inert" || passwords[0].Count != 4 {
				t.Errorf("passwords=%+v", passwords)
			}
			combos, err := st.TopCombosSince(cutoff, 2)
			if err != nil {
				t.Fatal(err)
			}
			if len(combos) != 2 || combos[0].Username != "root" || combos[0].Count != 2 || combos[1].Username != "admin" {
				t.Errorf("combos=%+v", combos)
			}
			for column, want := range map[string]int{"username": 3, "password": 1} {
				got, err := st.DistinctCredentialCount(column, cutoff)
				if err != nil || got != want {
					t.Errorf("distinct %s=%d err=%v want=%d", column, got, err, want)
				}
			}
		})
	}
}

func TestAggregateFractionBoundaries(t *testing.T) {
	st := newTestStore(t, "fraction-boundaries.db")
	for _, fixture := range []struct {
		raw    string
		native bool
	}{
		{"2026-09-21T10:00:00Z", false},
		{"2026-09-21T10:00:00.1Z", true},
		{"2026-09-21T10:00:00.100000001Z", false},
		{"2026-09-21T10:00:00.11Z", true},
		{"2026-09-21T10:00:00.111Z", false},
		{"2026-09-21T10:00:00.111111111Z", true},
	} {
		aggregateTimeEvent(t, st, fixture.raw, fixture.native, models.KindFailedPass, nil)
	}
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		ns   int
		want int
	}{{0, 6}, {100000000, 5}, {100000001, 4}, {110000000, 3}, {111000000, 2}, {111111111, 1}, {111111112, 0}} {
		rows, err := st.TopUsernamesSince(base.Add(time.Duration(test.ns)), 0)
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		if len(rows) != 0 {
			got = rows[0].Count
		}
		if got != test.want {
			t.Errorf("cutoff ns=%d got=%d want=%d", test.ns, got, test.want)
		}
	}
}

func TestAggregateWindowActivityUsesInstants(t *testing.T) {
	st := newTestStore(t, "activity-instants.db")
	aggregateTimeEvent(t, st, "2026-09-21T10:59:59.999999999+01:00", false, models.KindCommand, nil)
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00Z", true, models.KindAccepted, nil)
	aggregateTimeEvent(t, st, "2026-09-21T04:00:00.000000001-06:00", false, models.KindCommand, nil)
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00.5Z", true, models.KindFileDown, nil)
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00.900000001Z", false, models.KindFileUp, nil)
	since := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	got, err := st.WindowActivitySince(since)
	if err != nil {
		t.Fatal(err)
	}
	if got.Events != 4 || got.UniqueIPs != 1 || got.Accepted != 1 || got.Commands != 1 || got.Downloads != 2 {
		t.Fatalf("activity=%+v", got)
	}
	empty, err := st.WindowActivitySince(since.Add(time.Hour))
	if err != nil || empty.Events != 0 || empty.Accepted != 0 || empty.Commands != 0 || empty.Downloads != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
}

func TestAggregateHoursNormalizeLegacyOffsets(t *testing.T) {
	st := newTestStore(t, "hours-offset.db")
	hour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	for _, test := range []struct {
		zone   *time.Location
		native bool
	}{
		{time.UTC, true}, {time.FixedZone("east", 5*3600+1800), false}, {time.FixedZone("west", -3*3600-1800), false},
	} {
		raw := hour.Add(15 * time.Minute).In(test.zone).Format(time.RFC3339Nano)
		aggregateTimeEvent(t, st, raw, test.native, models.KindConnect, nil)
	}
	rows, err := st.HourlyEventCounts(24)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Hits != 3 || !rows[0].Hour.Equal(hour) {
		t.Errorf("hours=%+v; want %s/3", rows, hour)
	}
	kinds, err := st.HourlyEventCountsByKind(24)
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 1 || kinds[0].Hits != 3 || kinds[0].Kind != "connect" || !kinds[0].Hour.Equal(hour) {
		t.Errorf("kind hours=%+v", kinds)
	}
}

func TestAggregateTunnelBoundsUseExactTimes(t *testing.T) {
	st := newTestStore(t, "tunnel-bounds.db")
	edit := func(e *models.Event) { e.DstIP = "203.0.113.10"; e.DstPort = 443 }
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00Z", true, models.KindTunnel, edit)
	since := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	count, err := st.CountTunnelTargetsSince(since)
	if err != nil || count != 1 {
		t.Errorf("count=%d err=%v; want 1", count, err)
	}
	aggregateTimeEvent(t, st, "2026-09-21T04:00:00.000000001-06:00", false, models.KindTunnel, edit)
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00.900000001Z", false, models.KindTunnel, edit)
	rows, err := st.TopTunnelTargets(since, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Hits != 3 || !rows[0].FirstSeen.Equal(since) || !rows[0].LastSeen.Equal(since.Add(900000001)) {
		t.Errorf("window rows=%+v", rows)
	}
	all, err := st.TopTunnelTargets(time.Time{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Hits != 3 || !all[0].FirstSeen.Equal(since) || !all[0].LastSeen.Equal(since.Add(900000001)) {
		t.Errorf("all-time rows=%+v", all)
	}
}

func TestAggregateDetailReadersOrderInstantsAndTies(t *testing.T) {
	for _, kind := range []models.EventKind{models.KindCommand, models.KindFileDown} {
		t.Run(string(kind), func(t *testing.T) {
			st := newTestStore(t, "details.db")
			for _, f := range []struct {
				raw, command string
				native       bool
			}{
				{"2026-09-21T10:00:00Z", "oldest", false},
				{"2026-09-21T10:00:00.5Z", "middle", false},
				{"2026-09-21T10:00:00.900000001Z", "latest", true},
				{"2026-09-21T05:00:00.900000001-05:00", "latest-tie", false},
			} {
				aggregateTimeEvent(t, st, f.raw, f.native, kind, func(e *models.Event) { e.Command = f.command; e.Filename = "inert.bin" })
			}
			want := []string{"latest-tie", "latest", "middle", "oldest"}
			rows, err := st.RecentCommands(4)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, row := range rows {
				got = append(got, row.Command)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("recent=%v want=%v", got, want)
			}
			rows, err = st.EventsByActor("cowrie:fixture", 2)
			if err != nil {
				t.Fatal(err)
			}
			got = nil
			for _, row := range rows {
				got = append(got, row.Command)
			}
			if !reflect.DeepEqual(got, want[:2]) {
				t.Errorf("actor=%v", got)
			}
			last, err := st.LastCommandByActor("cowrie:fixture")
			if err != nil || last != "latest-tie" {
				t.Errorf("last=%q err=%v", last, err)
			}
			batch, err := st.LastCommandsForActors([]string{"cowrie:fixture", "missing"})
			if err != nil || len(batch) != 1 || batch["cowrie:fixture"] != "latest-tie" {
				t.Errorf("batch=%v err=%v", batch, err)
			}
			var captures []*EventRow
			if kind == models.KindCommand {
				captures, err = st.RecentCommandEvents(2)
			} else {
				captures, err = st.RecentFileDownloadEvents(2)
			}
			if err != nil {
				t.Fatal(err)
			}
			got = nil
			for _, row := range captures {
				got = append(got, row.Command)
			}
			if !reflect.DeepEqual(got, want[:2]) {
				t.Errorf("capture=%v", got)
			}
		})
	}
}

func TestAggregateScopedCommandsIgnoreOtherActorsInvalidTime(t *testing.T) {
	st := newTestStore(t, "scoped-invalid.db")
	aggregateTimeEvent(t, st, "2026-09-21T10:00:00Z", true, models.KindCommand, func(e *models.Event) { e.Command = "wanted" })
	aggregateTimeEvent(t, st, "inert-private-timestamp", false, models.KindCommand, func(e *models.Event) { e.ActorID = "other"; e.Command = "unrelated" })
	rows, err := st.EventsByActor("cowrie:fixture", 2)
	if err != nil || len(rows) != 1 || rows[0].Command != "wanted" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	last, err := st.LastCommandByActor("cowrie:fixture")
	if err != nil || last != "wanted" {
		t.Fatalf("last=%q err=%v", last, err)
	}
	batch, err := st.LastCommandsForActors([]string{"cowrie:fixture"})
	if err != nil || batch["cowrie:fixture"] != "wanted" {
		t.Fatalf("batch=%v err=%v", batch, err)
	}
}

func TestAggregateLegacyNullDetailFieldsRemainReadable(t *testing.T) {
	st := newTestStore(t, "detail-null.db")
	id := aggregateTimeEvent(t, st, "2026-09-21T10:00:00Z", false, models.KindCommand, func(e *models.Event) { e.Command = "inert" })
	if _, err := st.db.Exec("UPDATE events SET src_ip=NULL,username=NULL,session_id=NULL,sha256=NULL,filename=NULL WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	rows, err := st.RecentCommands(1)
	if err != nil || len(rows) != 1 || rows[0].Command != "inert" || rows[0].Username != "" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	rows, err = st.EventsByActor("cowrie:fixture", 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("actor rows=%+v err=%v", rows, err)
	}
}

func TestAggregateReadersRejectMalformedLegacyTimeWithoutDisclosure(t *testing.T) {
	since := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	readers := []struct {
		name string
		kind models.EventKind
		read func(*Store) error
	}{
		{"users", models.KindFailedPass, func(s *Store) error { _, e := s.TopUsernamesSince(since, 1); return e }},
		{"passwords", models.KindFailedPass, func(s *Store) error { _, e := s.TopPasswordsSince(since, 1); return e }},
		{"combos", models.KindFailedPass, func(s *Store) error { _, e := s.TopCombosSince(since, 1); return e }},
		{"distinct", models.KindFailedPass, func(s *Store) error { _, e := s.DistinctCredentialCount("username", since); return e }},
		{"activity", models.KindCommand, func(s *Store) error { _, e := s.WindowActivitySince(since); return e }},
		{"hours", models.KindCommand, func(s *Store) error { _, e := s.HourlyEventCounts(72); return e }},
		{"hour-kinds", models.KindCommand, func(s *Store) error { _, e := s.HourlyEventCountsByKind(72); return e }},
		{"tunnels", models.KindTunnel, func(s *Store) error { _, e := s.TopTunnelTargets(since, 1); return e }},
		{"tunnel-count", models.KindTunnel, func(s *Store) error { _, e := s.CountTunnelTargetsSince(since); return e }},
		{"tunnel-count-all", models.KindTunnel, func(s *Store) error { _, e := s.CountTunnelTargetsSince(time.Time{}); return e }},
		{"recent", models.KindCommand, func(s *Store) error { _, e := s.RecentCommands(1); return e }},
		{"actor", models.KindCommand, func(s *Store) error { _, e := s.EventsByActor("cowrie:fixture", 1); return e }},
		{"last", models.KindCommand, func(s *Store) error { _, e := s.LastCommandByActor("cowrie:fixture"); return e }},
		{"last-batch", models.KindCommand, func(s *Store) error { _, e := s.LastCommandsForActors([]string{"cowrie:fixture"}); return e }},
		{"capture-command", models.KindCommand, func(s *Store) error { _, e := s.RecentCommandEvents(1); return e }},
		{"capture-file", models.KindFileDown, func(s *Store) error { _, e := s.RecentFileDownloadEvents(1); return e }},
	}
	for _, test := range readers {
		t.Run(test.name, func(t *testing.T) {
			st := newTestStore(t, "malformed.db")
			aggregateTimeEvent(t, st, "inert-private-timestamp", false, test.kind, func(e *models.Event) {
				e.Command = "inert"
				e.Filename = "inert"
				e.DstIP = "203.0.113.10"
				e.DstPort = 443
			})
			err := test.read(st)
			if err == nil {
				t.Fatal("malformed timestamp accepted")
			}
			if strings.Contains(err.Error(), "inert-private-timestamp") {
				t.Fatalf("timestamp disclosed: %v", err)
			}
		})
	}
}

func TestAggregateCredentialEveryFractionWidth(t *testing.T) {
	for digits := 1; digits <= 9; digits++ {
		t.Run(strings.Repeat("1", digits), func(t *testing.T) {
			st := newTestStore(t, "fraction-width.db")
			text := "2026-09-21T10:00:00." + strings.Repeat("1", digits) + "Z"
			cutoff, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				t.Fatal(err)
			}
			aggregateTimeEvent(t, st, text, false, models.KindFailedPass, nil)
			aggregateTimeEvent(t, st, text, true, models.KindFailedPass, nil)
			for _, tc := range []struct {
				delta time.Duration
				want  int
			}{{-1, 2}, {0, 2}, {1, 0}} {
				rows, err := st.TopUsernamesSince(cutoff.Add(tc.delta), 1)
				if err != nil {
					t.Fatal(err)
				}
				got := 0
				if len(rows) > 0 {
					got = rows[0].Count
				}
				if got != tc.want {
					t.Fatalf("width=%d delta=%d got=%d want=%d", digits, tc.delta, got, tc.want)
				}
			}
		})
	}
}
