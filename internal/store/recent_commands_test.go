package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestRecentCommandsFillsSessionUsername verifies that command rows with an
// empty username pick up the login username from the same session — Cowrie
// only stamps username on auth events, not command.input.
func TestRecentCommandsFillsSessionUsername(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cmds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	ev := []*models.Event{
		{
			TS: now.Add(-2 * time.Minute), Source: models.SourceCowrie,
			Kind: models.KindAccepted, SrcIP: "9.9.9.9", SessionID: "s1",
			Username: "root", ActorID: "a1",
		},
		{
			TS: now.Add(-1 * time.Minute), Source: models.SourceCowrie,
			Kind: models.KindCommand, SrcIP: "9.9.9.9", SessionID: "s1",
			Command: "uname -a", ActorID: "a1",
			// Username intentionally empty — mirrors Cowrie command.input.
		},
		{
			TS: now.Add(-30 * time.Second), Source: models.SourceCowrie,
			Kind: models.KindCommand, SrcIP: "8.8.8.8", SessionID: "s2",
			Command: "id", Username: "admin", ActorID: "a2",
		},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(ev, nil); err != nil {
		t.Fatal(err)
	}

	cmds, err := st.RecentCommands(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 2 {
		t.Fatalf("got %d commands, want >= 2", len(cmds))
	}

	byCmd := map[string]string{}
	for _, c := range cmds {
		byCmd[c.Command] = c.Username
	}
	if byCmd["uname -a"] != "root" {
		t.Fatalf("uname -a user = %q, want root (filled from session login)", byCmd["uname -a"])
	}
	if byCmd["id"] != "admin" {
		t.Fatalf("id user = %q, want admin (kept from event)", byCmd["id"])
	}
}
