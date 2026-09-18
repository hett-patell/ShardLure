package cowrie

import (
	"fmt"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// reconcileSession transfers only evidence proven to belong to this session.
// It never rebuilds a lifetime actor from the retention-limited event table.
func reconcileSession(st *store.Store, sid, hassh string) error {
	targetID := actor.CowrieActorID("", hassh)
	return st.ReconcileSessionHASSH(sid, targetID, hassh, func(states map[string]*store.ActorState, stream func(func(*models.Event) error) error) ([]*models.AggregatedActor, error) {
		cc := actor.NewCowrieCollector(actor.AdminSet(nil))
		target := states[targetID]
		if target != nil {
			cc.SeedActorState(target.Actor, target.Users, target.IPs)
		}
		generated := make(map[string]bool, len(states))
		for id, s := range states {
			if s.Actor.Source != models.SourceCowrie {
				return nil, fmt.Errorf("HASSH reconciliation: non-Cowrie aggregate %q", id)
			}
			generated[id] = s.Actor.Notes == "" || s.Actor.Notes == fmt.Sprintf("%d events, %d usernames", s.Actor.EventCount, s.Actor.UniqueUsers)
		}
		if err := stream(func(e *models.Event) error {
			old := states[e.ActorID]
			if old == nil || old.Actor.EventCount < 1 {
				return fmt.Errorf("HASSH reconciliation: missing event total for %q", e.ActorID)
			}
			ip := old.IPs[e.SrcIP]
			if ip.Count < 1 {
				return fmt.Errorf("HASSH reconciliation: missing IP total for %q", e.ActorID)
			}
			old.Actor.EventCount--
			ip.Count--
			if ip.Count == 0 {
				delete(old.IPs, e.SrcIP)
			} else {
				old.IPs[e.SrcIP] = ip
			}
			if e.Username != "" && e.Username != "?" {
				if old.Users[e.Username] < 1 {
					return fmt.Errorf("HASSH reconciliation: missing username total for %q", e.ActorID)
				}
				old.Users[e.Username]--
				if old.Users[e.Username] == 0 {
					delete(old.Users, e.Username)
				}
			}
			cc.Add(e)
			return nil
		}); err != nil {
			return nil, err
		}
		updated := cc.Finalize()
		for _, agg := range updated {
			if target != nil && !generated[targetID] {
				agg.Actor.Notes = target.Actor.Notes
			}
		}
		for id, s := range states {
			if id == targetID {
				continue
			}
			// Flags and time extents are conservative lifetime evidence: a single
			// retained session cannot establish which older observations supplied
			// them. Reclassify counts/users without erasing unknown history.
			remaining := actor.NewCowrieCollector(actor.AdminSet(nil))
			remaining.SeedActorState(s.Actor, s.Users, s.IPs)
			for _, agg := range remaining.Finalize() {
				agg.Actor.ID = id
				if !generated[id] {
					agg.Actor.Notes = s.Actor.Notes
				} else if agg.Actor.EventCount == 0 {
					agg.Actor.Notes = ""
				}
				updated = append(updated, agg)
			}
		}
		return updated, nil
	})
}
