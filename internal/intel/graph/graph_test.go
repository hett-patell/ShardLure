package graph

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestBuild(t *testing.T) {
	t0 := time.Now()
	ev := func(actor, ip, hassh, user string) *models.Event {
		return &models.Event{TS: t0, ActorID: actor, SrcIP: ip, HASSH: hassh, Username: user, Kind: models.KindFailedPass}
	}
	events := []*models.Event{
		ev("act-1", "1.1.1.1", "abc123", "root"),
		ev("act-1", "1.1.1.1", "abc123", "admin"),
		ev("act-1", "1.1.1.2", "abc123", "root"),
		ev("act-2", "2.2.2.2", "deadbeef", "root"),
		ev("act-2", "2.2.2.2", "deadbeef", ""),
		ev("", "", "", ""), // pure noise - should not appear
	}

	g := Build(events, 0)

	idx := map[string]Node{}
	for _, n := range g.Nodes {
		idx[n.ID] = n
	}
	if _, ok := idx["actor:act-1"]; !ok {
		t.Fatalf("missing actor:act-1 in nodes: %+v", g.Nodes)
	}
	if idx["actor:act-1"].Weight != 3 {
		t.Errorf("act-1 weight = %d want 3", idx["actor:act-1"].Weight)
	}
	if idx["user:root"].Weight != 3 {
		t.Errorf("user:root weight = %d want 3", idx["user:root"].Weight)
	}

	// act-1 ↔ 1.1.1.1 should co-occur twice
	found := 0
	for _, e := range g.Edges {
		if (e.From == "actor:act-1" && e.To == "ip:1.1.1.1") ||
			(e.From == "ip:1.1.1.1" && e.To == "actor:act-1") {
			found = e.Weight
		}
	}
	if found != 2 {
		t.Errorf("act-1 <-> 1.1.1.1 weight = %d want 2", found)
	}

	// HASSH label clipped
	if idx["hassh:deadbeef"].Label != "deadbeef" {
		t.Errorf("short hassh label = %q", idx["hassh:deadbeef"].Label)
	}
}

func TestBuildTopN(t *testing.T) {
	t0 := time.Now()
	events := []*models.Event{}
	for i := 0; i < 100; i++ {
		events = append(events, &models.Event{
			TS: t0, ActorID: "a", SrcIP: "1.1.1.1", Username: "u",
		})
	}
	for i := 0; i < 5; i++ {
		events = append(events, &models.Event{
			TS: t0, ActorID: "b", SrcIP: "2.2.2.2", Username: "v",
		})
	}
	g := Build(events, 1) // cap each kind to 1 node
	actorCount := 0
	for _, n := range g.Nodes {
		if n.Kind == NodeActor {
			actorCount++
		}
	}
	if actorCount != 1 {
		t.Errorf("topN=1 should yield 1 actor node, got %d", actorCount)
	}
}
