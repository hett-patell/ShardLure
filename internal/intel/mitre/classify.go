package mitre

import (
	"sort"

	"github.com/networkshard/shardlure/pkg/models"
)

// Hit pairs a Technique with the number of events that matched it and
// the most recently seen actor. The dashboard shows top actors per
// technique so analysts can pivot straight from cell to actor card.
type Hit struct {
	Technique Technique
	Count     int
	// ActorCounts maps actorID -> hit count for that actor. Sorted at
	// JSON serialisation time so the consumer doesn't need to.
	ActorCounts map[string]int
}

// Classify walks events once and counts technique matches. A single
// event may match multiple techniques (e.g. an Accepted login is both
// T1078 and T1133 if you squint) and we count it against each one — the
// coverage grid is about *what was observed*, not unique tagging.
func Classify(events []*models.Event) []Hit {
	cat := techniques()
	idx := make(map[string]*Hit, len(cat))
	for i := range cat {
		idx[cat[i].ID] = &Hit{
			Technique:   cat[i],
			ActorCounts: map[string]int{},
		}
	}
	for _, e := range events {
		for i := range cat {
			if cat[i].match(e) {
				h := idx[cat[i].ID]
				h.Count++
				if e.ActorID != "" {
					h.ActorCounts[e.ActorID]++
				}
			}
		}
	}
	out := make([]Hit, 0, len(cat))
	for _, t := range cat {
		h := idx[t.ID]
		if h.Count > 0 {
			out = append(out, *h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Technique.ID < out[j].Technique.ID
	})
	return out
}

// ClassifyOne returns the technique IDs that match a single event. Used
// by future per-event tagging (e.g. in the session timeline) so the UI
// can show TTP tags inline.
func ClassifyOne(e *models.Event) []string {
	cat := techniques()
	var out []string
	for i := range cat {
		if cat[i].match(e) {
			out = append(out, cat[i].ID)
		}
	}
	return out
}

// CoverageGrid returns the full catalogue grouped by tactic with hit
// counts merged in (zero for non-matched techniques). The dashboard
// uses this to render the empty-cell pattern that gives an honest
// picture of what the honeypot can and can't see.
type GridTactic struct {
	Tactic     Tactic          `json:"tactic"`
	Techniques []GridTechnique `json:"techniques"`
}

type GridTechnique struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url,omitempty"`
	Count      int    `json:"count"`
	ActorCount int    `json:"actorCount"`
}

func CoverageGrid(hits []Hit) []GridTactic {
	hitsByID := make(map[string]Hit, len(hits))
	for _, h := range hits {
		hitsByID[h.Technique.ID] = h
	}
	cat := techniques()
	byTactic := map[Tactic][]GridTechnique{}
	for _, t := range cat {
		gt := GridTechnique{
			ID:   t.ID,
			Name: t.Name,
			URL:  t.URL,
		}
		if h, ok := hitsByID[t.ID]; ok {
			gt.Count = h.Count
			gt.ActorCount = len(h.ActorCounts)
		}
		byTactic[t.Tactic] = append(byTactic[t.Tactic], gt)
	}
	out := make([]GridTactic, 0, len(AllTactics()))
	for _, tac := range AllTactics() {
		// Include every tactic, even ones with no catalogued techniques.
		// Keeps grid columns aligned and signals 'we can't see this'
		// rather than 'this tactic does not exist'.
		out = append(out, GridTactic{Tactic: tac, Techniques: byTactic[tac]})
	}
	return out
}
