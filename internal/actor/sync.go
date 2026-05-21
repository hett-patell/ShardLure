package actor

import (
	"fmt"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func SyncJournalIP(st *store.Store, ip string, admin map[string]bool) error {
	events, err := st.EventsByIP(ip, 0)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	ptrs := make([]*models.Event, len(events))
	for i := range events {
		ptrs[i] = events[i]
	}
	actors := BuildFromJournal(ptrs, admin)
	if len(actors) == 0 {
		return nil
	}
	a := actors[0]
	if err := st.UpsertActor(a); err != nil {
		return err
	}
	users := map[string]int{}
	for _, e := range ptrs {
		if e.Username != "" {
			users[e.Username]++
		}
	}
	for u, c := range users {
		if err := st.UpsertActorUser(a.ID, u, c); err != nil {
			return err
		}
	}
	if err := st.UpsertActorIP(a.ID, ip, a.FirstSeen, a.LastSeen, len(ptrs)); err != nil {
		return err
	}
	for _, e := range ptrs {
		if e.ActorID != a.ID {
			e.ActorID = a.ID
			if err := st.UpdateEventActor(e.ID, a.ID); err != nil {
				return fmt.Errorf("update event actor: %w", err)
			}
		}
	}
	return nil
}
