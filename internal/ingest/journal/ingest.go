package journal

import (
	"fmt"
	"os"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Result struct {
	Events int
	Actors int
	SkippedAdmin int
}

func IngestFile(st *store.Store, path string, adminIPs []string, replace bool) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	events, err := ParseReader(f)
	if err != nil {
		return nil, err
	}

	admin := actor.AdminSet(adminIPs)
	if replace {
		if err := st.ClearAll(); err != nil {
			return nil, err
		}
	}

	skipped := 0
	var attack []*models.Event
	for _, e := range events {
		if e.Kind == models.KindAccepted && admin[e.SrcIP] {
			skipped++
			continue
		}
		if e.Kind == models.KindAccepted {
			// non-allowlisted success   still store but don't build actor
			if err := st.InsertEvent(e); err != nil {
				return nil, err
			}
			continue
		}
		attack = append(attack, e)
	}

	actors, _ := actor.BuildFromJournal(attack, admin)
	for _, e := range attack {
		if err := st.InsertEvent(e); err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
	}

	for _, a := range actors {
		if err := st.UpsertActor(a); err != nil {
			return nil, err
		}
		ipStats := map[string]int{}
		users := map[string]int{}
		for _, e := range attack {
			if e.ActorID != a.ID {
				continue
			}
			ipStats[e.SrcIP]++
			if e.Username != "" {
				users[e.Username]++
			}
		}
		for ip, c := range ipStats {
			if err := st.UpsertActorIP(a.ID, ip, a.LastSeen, c); err != nil {
				return nil, err
			}
		}
		for u, c := range users {
			if err := st.UpsertActorUser(a.ID, u, c); err != nil {
				return nil, err
			}
		}
	}

	return &Result{
		Events: len(attack),
		Actors: len(actors),
		SkippedAdmin: skipped,
	}, nil
}
