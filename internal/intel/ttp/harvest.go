// Package ttp clusters captured attacker commands into reusable
// templates (Tactics, Techniques and Procedures).
//
// Each command is normalised by replacing variable substrings (IPs,
// URLs, hex blobs, absolute paths) with placeholders so commands
// that differ only in their targets collapse into one row. The
// resulting templates are the TTPs the honeypot has actually
// observed - a concrete blue-team-facing answer to "what are
// attackers running once they're in?".
//
// The MITRE classifier from internal/intel/mitre is applied to each
// canonical command in the cluster so analysts can see which
// techniques map to each template.
package ttp

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/intel/mitre"
	"github.com/networkshard/shardlure/pkg/models"
)

// Row is one harvested TTP.
type Row struct {
	Template   string    `json:"template"`
	Count      int       `json:"count"`
	ActorCount int       `json:"actorCount"`
	Actors     []string  `json:"actors,omitempty"`
	Techniques []string  `json:"techniques,omitempty"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Samples    []string  `json:"samples,omitempty"`
}

var (
	reIPv4   = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reURL    = regexp.MustCompile(`https?://\S+`)
	reHex    = regexp.MustCompile(`\b[0-9a-fA-F]{12,}\b`)
	reTmp    = regexp.MustCompile(`/tmp/[^\s;|&]+`)
	rePort   = regexp.MustCompile(`:\d{2,5}\b`)
	rePath   = regexp.MustCompile(`/(?:home|root|var|opt|etc|usr|tmp)/[^\s;|&]+`)
	reNum    = regexp.MustCompile(`\b\d{3,}\b`)
	reSpaces = regexp.MustCompile(`\s+`)
)

// Normalise converts a raw command into its template form. The
// transformation is intentionally aggressive - we'd rather cluster
// two slightly-different commands together than show analysts five
// near-duplicate rows.
func Normalise(cmd string) string {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return ""
	}
	c = reURL.ReplaceAllString(c, "<URL>")
	c = reIPv4.ReplaceAllString(c, "<IP>")
	c = rePath.ReplaceAllString(c, "<PATH>") // before /tmp/X to catch home/etc/var first
	c = reTmp.ReplaceAllString(c, "<PATH>")
	c = reHex.ReplaceAllString(c, "<HEX>")
	c = rePort.ReplaceAllString(c, ":<PORT>")
	c = reNum.ReplaceAllString(c, "<N>")
	c = reSpaces.ReplaceAllString(c, " ")
	return c
}

type cluster struct {
	template string
	count    int
	actors   map[string]struct{}
	first    time.Time
	last     time.Time
	samples  []string
	techs    map[string]struct{}
}

func (c *cluster) record(e *models.Event, techs []string) {
	c.count++
	if e.ActorID != "" {
		c.actors[actor.TrimActorPrefix(e.ActorID)] = struct{}{}
	}
	if c.count == 1 || e.TS.Before(c.first) {
		c.first = e.TS
	}
	if e.TS.After(c.last) {
		c.last = e.TS
	}
	if len(c.samples) < 4 {
		// Avoid storing the same raw command twice in the sample
		// list - aggressive but cheap; samples are tiny.
		seen := false
		for _, s := range c.samples {
			if s == e.Command {
				seen = true
				break
			}
		}
		if !seen {
			c.samples = append(c.samples, e.Command)
		}
	}
	for _, t := range techs {
		c.techs[t] = struct{}{}
	}
}

// Harvest clusters commands across the given events. limit caps the
// returned rows; pass 0 for no limit. Events without a command are
// silently skipped.
//
// Honeypot command streams are massively repetitive (that's the premise of
// this package), so both the 8-regex Normalise pass and the ~19-matcher
// MITRE classification are memoized by the raw command within a call —
// otherwise a 7-day window with tens of thousands of duplicate commands
// re-ran every regex per event. The classification memo is keyed on
// (kind, command) because mitre matchers dispatch on both.
func Harvest(events []*models.Event, limit int) []Row {
	bags := map[string]*cluster{}
	normMemo := map[string]string{}
	type classKey struct {
		kind models.EventKind
		cmd  string
	}
	classMemo := map[classKey][]string{}
	for _, e := range events {
		if e == nil || e.Command == "" {
			continue
		}
		tmpl, ok := normMemo[e.Command]
		if !ok {
			tmpl = Normalise(e.Command)
			normMemo[e.Command] = tmpl
		}
		if tmpl == "" {
			continue
		}
		ck := classKey{e.Kind, e.Command}
		techs, ok := classMemo[ck]
		if !ok {
			techs = mitre.ClassifyOne(e)
			classMemo[ck] = techs
		}
		c := bags[tmpl]
		if c == nil {
			c = &cluster{
				template: tmpl,
				actors:   make(map[string]struct{}),
				techs:    make(map[string]struct{}),
			}
			bags[tmpl] = c
		}
		c.record(e, techs)
	}

	rows := make([]Row, 0, len(bags))
	for _, c := range bags {
		actors := make([]string, 0, len(c.actors))
		for a := range c.actors {
			actors = append(actors, a)
		}
		sort.Strings(actors)
		techs := make([]string, 0, len(c.techs))
		for t := range c.techs {
			techs = append(techs, t)
		}
		sort.Strings(techs)
		rows = append(rows, Row{
			Template:   c.template,
			Count:      c.count,
			ActorCount: len(c.actors),
			Actors:     actors,
			Techniques: techs,
			FirstSeen:  c.first,
			LastSeen:   c.last,
			Samples:    c.samples,
		})
	}

	// Rank by ActorCount (broader = more interesting), then Count, then
	// LastSeen. A command used by many distinct actors is a stronger
	// TTP signal than one used many times by a single actor.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ActorCount != rows[j].ActorCount {
			return rows[i].ActorCount > rows[j].ActorCount
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if !rows[i].LastSeen.Equal(rows[j].LastSeen) {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].Template < rows[j].Template
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}
