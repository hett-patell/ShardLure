package actor

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestJournalUsernameHashHasUnambiguousFraming(t *testing.T) {
	a := usernameSetHash([]string{"a,b", "c"})
	b := usernameSetHash([]string{"a", "b,c"})
	if a == b {
		t.Fatal("distinct username corpora share the same comma-framed hash")
	}
}

func TestJournalSummaryOversizedCorruptStateStaysBounded(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "oversized-fold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const id = "journal:198.51.100.42"
	e := &models.Event{TS: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Source: models.SourceJournal, Kind: models.KindFailedPass, ActorID: id, SrcIP: "198.51.100.42", Username: "root"}
	if _, err := s.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdvanceJournalSummary(context.Background(), id, 1, NewJournalSummaryCodec()); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE journal_summaries SET status='pending',fold_state=zeroblob(8388608) WHERE actor_id=?", id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = s.AdvanceJournalSummary(context.Background(), id, 1, NewJournalSummaryCodec())
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 2<<20 {
		t.Fatalf("oversized stored fold materialized before validation: %d bytes", n)
	}
	a, err := s.GetActor(id)
	if err != nil || a.UniqueUsers != 1 {
		t.Fatalf("corrupt state repair lost authority: %+v err=%v", a, err)
	}
}

type pausedJournalCodec struct {
	store.JournalSummaryCodec
	once             sync.Once
	entered, release chan struct{}
}

func (c *pausedJournalCodec) AddUser(state []byte, user string) ([]byte, error) {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.JournalSummaryCodec.AddUser(state, user)
}

func TestJournalSummaryConcurrentInsertInvalidatesPublishedRevision(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "concurrent-fold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const id = "journal:198.51.100.40"
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	add := func(user string, at time.Time) error {
		e := &models.Event{TS: at, Source: models.SourceJournal, Kind: models.KindFailedPass, ActorID: id, SrcIP: "198.51.100.40", Username: user}
		_, err := s.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: user})
		return err
	}
	if err := add("root", base); err != nil {
		t.Fatal(err)
	}
	codec := &pausedJournalCodec{JournalSummaryCodec: NewJournalSummaryCodec(), entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	derived := make(chan error, 1)
	go func() { _, err := s.AdvanceJournalSummary(ctx, id, 10, codec); derived <- err }()
	select {
	case <-codec.entered:
	case <-ctx.Done():
		t.Fatal("derivation never reached page")
	}
	written := make(chan error, 1)
	go func() { written <- add("aardvark", base.Add(time.Hour)) }()
	close(codec.release)
	if err := <-derived; err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	a, err := s.GetActor(id)
	if err != nil || a.DerivedCurrent || a.UniqueUsers != 2 {
		t.Fatalf("stale revision was published: %+v err=%v", a, err)
	}
	if done, err := s.AdvanceJournalSummary(ctx, id, 10, NewJournalSummaryCodec()); err != nil || !done {
		t.Fatalf("fresh revision done=%v err=%v", done, err)
	}
	a, err = s.GetActor(id)
	if err != nil || !a.DerivedCurrent || a.UsernameHash != usernameSetHash([]string{"aardvark", "root"}) {
		t.Fatalf("lost concurrent name: %+v err=%v", a, err)
	}
}

func TestJournalSummaryFailedAndCancelledPagesKeepCursorAtomic(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "atomic-fold.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const id = "journal:198.51.100.41"
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i, user := range []string{"a", "b", "c"} {
		e := &models.Event{TS: base.Add(time.Duration(i) * time.Hour), Source: models.SourceJournal, Kind: models.KindFailedPass, ActorID: id, SrcIP: "198.51.100.41", Username: user}
		if _, err := s.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: user}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER reject_summary BEFORE UPDATE OF fold_state ON journal_summaries BEGIN SELECT RAISE(ABORT,'reject fold'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if done, err := s.AdvanceJournalSummary(context.Background(), id, 1, NewJournalSummaryCodec()); err == nil || done {
		t.Fatalf("failed page done=%v err=%v", done, err)
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		var cursor string
		var state []byte
		var building int
		if err := tx.QueryRow("SELECT user_cursor,fold_state,building_revision FROM journal_summaries WHERE actor_id=?", id).Scan(&cursor, &state, &building); err != nil {
			return err
		}
		if cursor != "" || state != nil || building != -1 {
			t.Fatalf("partial cursor/state committed: %q %v %d", cursor, state, building)
		}
		_, err := tx.Exec("DROP TRIGGER reject_summary")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.AdvanceJournalSummary(ctx, id, 1, NewJournalSummaryCodec()); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	for i := 0; ; i++ {
		if i > 5 {
			t.Fatal("rollback left a stalled cursor")
		}
		done, err := s.AdvanceJournalSummary(context.Background(), id, 1, NewJournalSummaryCodec())
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	a, err := s.GetActor(id)
	if err != nil || !a.DerivedCurrent || a.UniqueUsers != 3 {
		t.Fatalf("rollback lost evidence: %+v err=%v", a, err)
	}
}

func TestJournalReportHashUsesSameUnambiguousCorpus(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "report-hash.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	var hashes []string
	for i, users := range [][]string{{"a,b", "c"}, {"a", "b,c"}} {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		var events []*models.Event
		for _, u := range users {
			e := &models.Event{TS: now.Add(-time.Minute), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: ip, ActorID: JournalActorID(ip), Username: u}
			if err := s.InsertEvent(e); err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
		a := BuildFromJournalAggregated(events, AdminSet(nil))[0].Actor
		r, err := ReportEvidenceForIP(s, a, now)
		if err != nil {
			t.Fatal(err)
		}
		if r.UsernameHash != a.UsernameHash {
			t.Fatalf("batch/report hash mismatch: %s/%s", a.UsernameHash, r.UsernameHash)
		}
		hashes = append(hashes, r.UsernameHash)
	}
	if hashes[0] == hashes[1] {
		t.Fatal("reporting corpus hashes collide on comma-containing names")
	}
}

func TestJournalAnnotationsSurviveOverflowReplayAndReopen(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()
	previous := liveMaxUsersPerIP
	liveMaxUsersPerIP = 2
	defer func() { liveMaxUsersPerIP = previous }()
	path := filepath.Join(t.TempDir(), "journal-summary.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s != nil {
			s.Close()
		}
	}()
	const ip = "198.51.100.10"
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i, user := range []string{"root", "admin", "_overflow_", "用户名", "deploy", "ci", "root"} {
		if i == 3 {
			resetLiveCollectorForTest()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		e := &models.Event{TS: base.Add(time.Duration(i) * time.Hour), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: ip, Username: user, Raw: fmt.Sprint(i)}
		if inserted, err := SyncJournalEvent(s, e, AdminSet(nil)); err != nil || !inserted {
			t.Fatalf("append %d=%v err=%v", i, inserted, err)
		}
		if i == 0 {
			if err := s.WithTx(func(tx *sql.Tx) error {
				_, err := tx.Exec("UPDATE actors SET campaigns='operator-campaign',notes='operator note' WHERE id=?", JournalActorID(ip))
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if inserted, err := SyncJournalEvent(s, e, AdminSet(nil)); err != nil || inserted {
			t.Fatalf("replay=%v err=%v", inserted, err)
		}
	}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("summary did not finish")
		}
		done, err := s.AdvanceJournalSummary(context.Background(), JournalActorID(ip), 2, NewJournalSummaryCodec())
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	a, err := s.GetActor(JournalActorID(ip))
	if err != nil {
		t.Fatal(err)
	}
	if a.Campaigns != "operator-campaign" || a.Notes != "operator note" {
		t.Errorf("annotations changed: campaigns=%q notes=%q", a.Campaigns, a.Notes)
	}
	if a.EventCount != 7 || a.UniqueUsers != 6 {
		t.Errorf("counts=%d/%d want 7/6", a.EventCount, a.UniqueUsers)
	}
	if !a.DerivedCurrent || a.Playbook != "ops_target" || a.GeneratedNotes != "6 distinct usernames" {
		t.Errorf("inexact derived profile: %+v", a)
	}
	if a.UsernameHash != usernameSetHash([]string{"_overflow_", "admin", "ci", "deploy", "root", "用户名"}) {
		t.Errorf("live/batch hash diverged: %+v", a)
	}
}

func TestJournalSummaryCodecBoundedAndVersioned(t *testing.T) {
	codec := NewJournalSummaryCodec()
	state, err := codec.Start()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5000; i++ {
		state, err = codec.AddUser(state, fmt.Sprintf("name-%05d", i))
		if err != nil {
			t.Fatal(err)
		}
		if len(state) > 1024 {
			t.Fatalf("fold grows with corpus: %d bytes", len(state))
		}
	}
	for _, u := range []string{"ci", "deploy"} {
		state, err = codec.AddUser(state, u)
		if err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r, err := codec.Finish(state, store.JournalCounters{Count: 5002, UniqueUsers: 5002, First: base, Last: base.Add(5002 * time.Hour)})
	if err != nil || r.Playbook != "ops_target" || r.GeneratedNotes != "5002 distinct usernames" {
		t.Fatalf("derived=%+v err=%v", r, err)
	}
	for _, bad := range [][]byte{nil, []byte("broken"), []byte(`{"version":999}`)} {
		if _, err := codec.AddUser(bad, "root"); err == nil {
			t.Fatalf("invalid state accepted: %q", bad)
		}
	}
}

func TestJournalSummaryRestartsAfterLateNameAndCorruptState(t *testing.T) {
	resetLiveCollectorForTest()
	defer resetLiveCollectorForTest()
	s, err := store.Open(filepath.Join(t.TempDir(), "restart-summary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const ip = "198.51.100.20"
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	var events []*models.Event
	add := func(user string) {
		t.Helper()
		e := &models.Event{TS: base.Add(time.Duration(len(events)) * time.Hour), Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: ip, Username: user, Raw: fmt.Sprint(len(events))}
		if _, err := SyncJournalEvent(s, e, AdminSet(nil)); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	for _, u := range []string{"root", "zulu", "用户名"} {
		add(u)
	}
	codec := NewJournalSummaryCodec()
	if done, err := s.AdvanceJournalSummary(context.Background(), JournalActorID(ip), 1, codec); err != nil || done {
		t.Fatalf("first page done=%v err=%v", done, err)
	}
	add("aardvark") // before the previously saved cursor
	if done, err := s.AdvanceJournalSummary(context.Background(), JournalActorID(ip), 1, codec); err != nil || done {
		t.Fatalf("new revision done=%v err=%v", done, err)
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE journal_summaries SET fold_state=? WHERE actor_id=?", []byte("corrupt fold"), JournalActorID(ip))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if i > 15 {
			t.Fatal("restart stalled")
		}
		done, err := s.AdvanceJournalSummary(context.Background(), JournalActorID(ip), 1, codec)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	a, err := s.GetActor(JournalActorID(ip))
	if err != nil {
		t.Fatal(err)
	}
	want := BuildFromJournalAggregated(events, AdminSet(nil))[0].Actor
	if !a.DerivedCurrent || a.UniqueUsers != 4 || a.UsernameHash != want.UsernameHash || a.Playbook != want.Playbook {
		t.Fatalf("late/corrupt fold lost corpus: %+v want %+v", a, want)
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER forbid_corpus_rescan BEFORE UPDATE OF fold_state ON journal_summaries WHEN NEW.fold_state IS NOT OLD.fold_state BEGIN SELECT RAISE(ABORT,'unnecessary fold rewrite'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	add("root") // counts/rate changed, corpus did not: reuse the completed fold
	if done, err := s.AdvanceJournalSummary(context.Background(), JournalActorID(ip), 1, codec); err != nil || !done {
		t.Fatalf("duplicate name must reuse complete corpus done=%v err=%v", done, err)
	}
}

// Regression (whole-branch review): the live worker asked for the first 16
// pending ids in actor_id order and returned on the first failure, so one
// actor with a persistently bad row (an unparseable first_seen, say) blocked
// derivation for every journal actor sorting after it, leaving them masked as
// pending with probe score 0 and never offered for reporting.
func TestPendingJournalSummariesAreNotBlockedByOneFailingActor(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "hol.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ids := []string{"journal:198.51.100.1", "journal:198.51.100.2"}
	for _, id := range ids {
		e := &models.Event{TS: base, Source: models.SourceJournal, Kind: models.KindFailedPass, ActorID: id, SrcIP: id[len("journal:"):], Username: "root"}
		if _, err := s.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: "root"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE actors SET first_seen='not a time' WHERE id=?", ids[0])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cursor := ""
	var sawErr bool
	for cycle := 0; cycle < 3; cycle++ {
		next, err := AdvancePendingJournalSummaries(ctx, s, cursor, 1)
		if err != nil {
			sawErr = true
		}
		cursor = next
	}
	if !sawErr {
		t.Fatal("the failing actor's error was not reported")
	}
	pending, err := s.PendingJournalSummaries(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range pending {
		if id == ids[1] {
			t.Fatalf("healthy actor %s stayed pending behind a failing one", ids[1])
		}
	}
}
