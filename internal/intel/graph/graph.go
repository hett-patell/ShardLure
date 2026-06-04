// Package graph builds the pivot graph for the red-team /intel
// visualisation. Nodes are typed entities (actor, ip, hassh, user)
// and edges are co-occurrence weights between them in the observed
// event stream. The shape is deliberately compact - vis-network
// chokes above ~2k nodes, so we cap at the top N most-active nodes
// per type.
package graph

import (
	"sort"
	"strings"

	"github.com/networkshard/shardlure/pkg/models"
)

// NodeKind identifies which entity type a node represents. The
// frontend uses this for both colour and shape.
type NodeKind string

const (
	NodeActor NodeKind = "actor"
	NodeIP    NodeKind = "ip"
	NodeHASSH NodeKind = "hassh"
	NodeUser  NodeKind = "user"
)

// Node is one rendered vis-network node. Weight is the number of
// distinct events the entity appears in - used to scale node size.
type Node struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Kind   NodeKind `json:"kind"`
	Weight int      `json:"weight"`
}

// Edge connects two nodes with a co-occurrence count. The semantics
// of "co-occur" depend on the endpoint kinds (e.g. actor↔ip means
// the actor was attributed to events from that IP).
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Weight int    `json:"weight"`
}

// Graph is the JSON payload sent to /api/intel/graph.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// Totals is the true distinct-node count per kind BEFORE the top-N cap, so
	// the UI can disclose that the rendered graph is a sample (e.g. "240 of
	// 4597 nodes"). Cap is the per-kind limit applied.
	Totals map[NodeKind]int `json:"totals"`
	Cap    int              `json:"cap"`
}

// Build aggregates an event slice into a pivot graph, keeping only
// the topN most-active nodes of each kind. Set topN=0 to use the
// default (60 per kind). Untyped/empty values are skipped silently.
func Build(events []*models.Event, topN int) Graph {
	if topN <= 0 {
		topN = 60
	}

	// Per-kind frequency counters drive ranking.
	type freq map[string]int
	actors := freq{}
	ips := freq{}
	hasshes := freq{}
	users := freq{}

	type pair struct{ a, b string }
	edges := map[pair]int{}
	addEdge := func(a, b string) {
		if a == "" || b == "" || a == b {
			return
		}
		// Canonicalise pair order so (a,b) == (b,a).
		if a > b {
			a, b = b, a
		}
		edges[pair{a, b}]++
	}

	for _, e := range events {
		if e == nil {
			continue
		}
		// Prefix IDs by kind so cross-kind collisions are impossible.
		var aID, iID, hID, uID string
		if e.ActorID != "" {
			aID = "actor:" + e.ActorID
			actors[aID]++
		}
		if e.SrcIP != "" {
			iID = "ip:" + e.SrcIP
			ips[iID]++
		}
		if e.HASSH != "" {
			hID = "hassh:" + e.HASSH
			hasshes[hID]++
		}
		if u := strings.TrimSpace(e.Username); u != "" {
			uID = "user:" + u
			users[uID]++
		}
		// Wire all co-occurring entities on the same event.
		addEdge(aID, iID)
		addEdge(aID, hID)
		addEdge(aID, uID)
		addEdge(iID, hID)
		addEdge(iID, uID)
		addEdge(hID, uID)
	}

	keep := map[string]bool{}
	pickTop := func(f freq, kind NodeKind, nodes *[]Node) {
		type kv struct {
			k string
			v int
		}
		s := make([]kv, 0, len(f))
		for k, v := range f {
			s = append(s, kv{k, v})
		}
		sort.Slice(s, func(i, j int) bool {
			if s[i].v != s[j].v {
				return s[i].v > s[j].v
			}
			return s[i].k < s[j].k
		})
		if len(s) > topN {
			s = s[:topN]
		}
		for _, kv := range s {
			keep[kv.k] = true
			*nodes = append(*nodes, Node{
				ID:     kv.k,
				Label:  trimPrefix(kv.k),
				Kind:   kind,
				Weight: kv.v,
			})
		}
	}

	nodes := []Node{}
	pickTop(actors, NodeActor, &nodes)
	pickTop(ips, NodeIP, &nodes)
	pickTop(hasshes, NodeHASSH, &nodes)
	pickTop(users, NodeUser, &nodes)

	// True distinct counts per kind (before the cap) so the UI can disclose
	// that the graph is a top-N-per-kind sample, not the whole population.
	out := Graph{
		Nodes: nodes,
		Cap:   topN,
		Totals: map[NodeKind]int{
			NodeActor: len(actors),
			NodeIP:    len(ips),
			NodeHASSH: len(hasshes),
			NodeUser:  len(users),
		},
	}
	for p, w := range edges {
		if !keep[p.a] || !keep[p.b] {
			continue
		}
		out.Edges = append(out.Edges, Edge{From: p.a, To: p.b, Weight: w})
	}
	// Stable edge ordering helps test snapshots and visual diffs.
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].Weight != out.Edges[j].Weight {
			return out.Edges[i].Weight > out.Edges[j].Weight
		}
		if out.Edges[i].From != out.Edges[j].From {
			return out.Edges[i].From < out.Edges[j].From
		}
		return out.Edges[i].To < out.Edges[j].To
	})
	return out
}

// trimPrefix strips the "kind:" namespace so node labels render cleanly.
func trimPrefix(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		// HASSH labels are 32-char md5 hashes - clip for readability.
		v := s[i+1:]
		if strings.HasPrefix(s, "hassh:") && len(v) > 12 {
			return v[:12] + "…"
		}
		return v
	}
	return s
}
