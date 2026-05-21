package journal

import (
	"os"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Result struct {
	Events       int
	Actors       int
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

	return persistJournalEvents(st, events, adminIPs, replace)
}

func persistJournalEvents(st *store.Store, events []*models.Event, adminIPs []string, replace bool) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	skipped := 0
	var stored []*models.Event
	var attack []*models.Event
	for _, e := range events {
		if e.Kind == models.KindAccepted && admin[e.SrcIP] {
			skipped++
			continue
		}
		if e.Kind == models.KindAccepted {
			// Non-allowlisted success is stored as telemetry but does not form an attacker actor.
			stored = append(stored, e)
			continue
		}
		attack = append(attack, e)
		stored = append(stored, e)
	}

	var actors []*models.Actor
	if replace {
		actors = actor.BuildFromJournal(attack, admin)
		if err := st.ReplaceSourceEventsAndActors(models.SourceJournal, stored, actors); err != nil {
			return nil, err
		}
	} else {
		all, err := st.EventsBySource(models.SourceJournal)
		if err != nil {
			return nil, err
		}
		all = append(all, stored...)
		actors = actor.BuildFromJournal(filterAttackJournalEvents(all), admin)
		if err := st.AppendEventsAndReplaceActors(models.SourceJournal, stored, all, actors); err != nil {
			return nil, err
		}
	}

	return &Result{
		Events:       len(stored),
		Actors:       len(actors),
		SkippedAdmin: skipped,
	}, nil
}

func filterAttackJournalEvents(events []*models.Event) []*models.Event {
	var out []*models.Event
	for _, e := range events {
		if e.Kind != models.KindAccepted {
			out = append(out, e)
		}
	}
	return out
}
