package journal

import (
	"reflect"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestJournalctlFollowArgsStartAtEnd(t *testing.T) {
	want := []string{"-u", "sshd", "-n", "0", "-f", "-o", "short-iso", "--no-pager"}
	if got := journalctlFollowArgs("sshd"); !reflect.DeepEqual(got, want) {
		t.Fatalf("journalctl follow args = %q, want %q", got, want)
	}
}

func TestConsumeTailDeduplicatesAcceptedAndAttackReplays(t *testing.T) {
	st := openJournalTailTestStore(t)
	accepted := "2026-07-27T10:00:00+00:00 host sshd[101]: Accepted publickey for deploy from 198.51.100.27 port 52001 ssh2"
	attack := "2026-07-27T10:00:01+00:00 host sshd[102]: Failed password for root from 203.0.113.44 port 52002 ssh2"
	input := strings.Join([]string{accepted, accepted, attack, attack}, "\n") + "\n"

	if err := consumeTail(st, strings.NewReader(input), actor.AdminSet(nil)); err != nil {
		t.Fatalf("consume tail: %v", err)
	}

	events, err := st.EventsBySource(models.SourceJournal)
	if err != nil {
		t.Fatalf("load journal events: %v", err)
	}
	if got := len(events); got != 2 {
		t.Fatalf("journal event count = %d, want 2", got)
	}
	acceptedFound := false
	for _, e := range events {
		if e.Kind != models.KindAccepted {
			continue
		}
		acceptedFound = true
		if e.ActorID != "" {
			t.Fatalf("accepted event actor ID = %q, want empty", e.ActorID)
		}
	}
	if !acceptedFound {
		t.Fatal("accepted event missing after replay")
	}

	const actorID = "journal:203.0.113.44"
	actors, err := st.ListActors(10)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	if len(actors) != 1 || actors[0].ID != actorID {
		t.Fatalf("actors = %+v, want only %s", actors, actorID)
	}
	a, err := st.GetActor(actorID)
	if err != nil {
		t.Fatalf("load attack actor: %v", err)
	}
	if a.EventCount != 1 {
		t.Fatalf("actor event count = %d, want 1", a.EventCount)
	}
	stats, err := st.LoadJournalIPStats(actorID, "203.0.113.44")
	if err != nil {
		t.Fatalf("load journal IP stats: %v", err)
	}
	if stats.Count != 1 {
		t.Fatalf("actor IP count = %d, want 1", stats.Count)
	}
	if got := stats.UserCounts["root"]; got != 1 {
		t.Fatalf("actor root count = %d, want 1", got)
	}
}

func openJournalTailTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/tail.db")
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
