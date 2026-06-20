// Package ioc derives indicators-of-compromise from honeypot events
// and renders them in CSV or STIX 2.1 form for downstream consumption.
//
// Four kinds are recognised today:
//
//   - ip:   any src_ip seen as an attacker
//   - hash: sha256 of payloads cowrie captured during a session
//   - url:  any URL extracted from a command (wget/curl/http literals,
//     plus reverse-shell /dev/tcp targets normalised to URLs)
//   - user: any username an attacker attempted (failed or otherwise)
//
// Each indicator carries the first/last seen window, the count of
// observations, the contributing sources and actors, plus a short
// sample command so the analyst can recognise context at a glance.
package ioc

import (
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/capture"
	"github.com/networkshard/shardlure/pkg/models"
)

type Kind string

const (
	KindIP   Kind = "ip"
	KindHash Kind = "hash"
	KindURL  Kind = "url"
	KindUser Kind = "user"
)

// Indicator is a normalised IOC row: the same shape regardless of kind.
// Sources and Actors are deduped + sorted for stable output.
type Indicator struct {
	Kind          Kind      `json:"kind"`
	Value         string    `json:"value"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Count         int       `json:"count"`
	Sources       []string  `json:"sources"`
	Actors        []string  `json:"actors,omitempty"`
	SampleCommand string    `json:"sample_command,omitempty"`
}

type setBuilder struct {
	values map[string]struct{}
	order  []string
}

func (s *setBuilder) add(v string) {
	if v == "" {
		return
	}
	if s.values == nil {
		s.values = make(map[string]struct{})
	}
	if _, ok := s.values[v]; ok {
		return
	}
	s.values[v] = struct{}{}
	s.order = append(s.order, v)
}

func (s *setBuilder) slice() []string {
	if len(s.order) == 0 {
		return nil
	}
	out := append([]string(nil), s.order...)
	sort.Strings(out)
	return out
}

type accumulator struct {
	first, last time.Time
	count       int
	srcs        setBuilder
	actors      setBuilder
	sample      string
	sampleSeen  bool
}

func (a *accumulator) record(ts time.Time, source, actorID, sample string) {
	if a.count == 0 || ts.Before(a.first) {
		a.first = ts
	}
	if ts.After(a.last) {
		a.last = ts
	}
	a.count++
	a.srcs.add(source)
	a.actors.add(actor.TrimActorPrefix(actorID))
	// Use the most-recent non-empty command we see; that's typically
	// the most useful context (post-auth commands rather than initial
	// connection-only events).
	if sample != "" {
		a.sample = sample
		a.sampleSeen = true
	}
}

func (a *accumulator) seal(kind Kind, value string) Indicator {
	ind := Indicator{
		Kind:      kind,
		Value:     value,
		FirstSeen: a.first,
		LastSeen:  a.last,
		Count:     a.count,
		Sources:   a.srcs.slice(),
		Actors:    a.actors.slice(),
	}
	if a.sampleSeen {
		ind.SampleCommand = a.sample
	}
	return ind
}

// Collect walks events and produces deduped Indicator rows.
//
// Rules:
//   - kind=ip filters by event.SrcIP
//   - kind=hash filters by event.SHA256 (cowrie-only in practice)
//   - kind=url runs capture.ExtractURLs on every event.Command
//   - kind=user collects every non-empty username; the "session
//     accepted" kind matters more than failed attempts, but we want
//     all of them in the wordlist export.
//
// Pass kinds=nil to produce all four. Output is sorted by Count desc,
// then LastSeen desc, then Value asc.
func Collect(events []*models.Event, kinds []Kind) []Indicator {
	want := map[Kind]bool{}
	if len(kinds) == 0 {
		want[KindIP] = true
		want[KindHash] = true
		want[KindURL] = true
		want[KindUser] = true
	} else {
		for _, k := range kinds {
			want[k] = true
		}
	}

	type key struct {
		k Kind
		v string
	}
	bags := map[key]*accumulator{}
	get := func(k Kind, v string) *accumulator {
		kk := key{k, v}
		a := bags[kk]
		if a == nil {
			a = &accumulator{}
			bags[kk] = a
		}
		return a
	}

	for _, e := range events {
		if e == nil {
			continue
		}
		src := string(e.Source)
		if want[KindIP] && e.SrcIP != "" {
			get(KindIP, e.SrcIP).record(e.TS, src, e.ActorID, e.Command)
		}
		if want[KindUser] && e.Username != "" {
			get(KindUser, e.Username).record(e.TS, src, e.ActorID, e.Command)
		}
		if want[KindHash] && e.SHA256 != "" {
			get(KindHash, strings.ToLower(e.SHA256)).record(e.TS, src, e.ActorID, e.Command)
		}
		if want[KindURL] && e.Command != "" {
			for _, u := range capture.ExtractURLs(e.Command) {
				get(KindURL, u).record(e.TS, src, e.ActorID, e.Command)
			}
		}
	}

	out := make([]Indicator, 0, len(bags))
	for kk, a := range bags {
		out = append(out, a.seal(kk.k, kk.v))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// FilterByKind returns only the indicators of the requested kind.
// Convenience for the /api/ioc/csv?kind=ip handler.
func FilterByKind(in []Indicator, k Kind) []Indicator {
	out := make([]Indicator, 0, len(in))
	for _, ind := range in {
		if ind.Kind == k {
			out = append(out, ind)
		}
	}
	return out
}
