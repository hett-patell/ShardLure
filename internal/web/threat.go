package web

import (
	"math"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// Threat gauge scoring.
//
// # WHY THIS IS SERVER-SIDE AND WINDOWED
//
// The gauge used to be computed in the dashboard from whole-table cumulative
// totals. That cannot work: events only ever accumulate, so the two largest
// factors ratcheted to their caps and stayed there. On the reference deployment
// it read exactly 52 for months — volume 25/25 (raw 29.1, capped), diversity
// 25/25 (raw 24.9), aggression 0/25 and weaponisation 2/25. A number that can
// only go up, and has already arrived, measures nothing.
//
// Two of the old factors were also mis-scaled in a way no amount of windowing
// would fix:
//
//   - "aggression" was deploy-intent actors over classifiable actors, times 50,
//     so full marks needed HALF of all attackers to be deploying malware. Real
//     rate on the reference box is 0.54%, which rounds to 0. It is replaced by
//     ACCEPTED LOGINS: an attacker who got a shell is the aggression signal, it
//     is directly observed, and it moves.
//
//   - "weaponisation" divided shell activity by ALL events, and the event mix is
//     dominated by connect/client_version/failed_password noise, so genuine
//     command-and-download activity was structurally diluted to a couple of
//     percent. It is now an absolute rate over the window.
//
// # CALIBRATION
//
// Each factor is a log-scaled rate contributing 0-25. Floors and ceilings were
// fitted against 31 days of real history from the reference deployment so that a
// typical day lands mid-range with genuine headroom left, rather than pinning at
// either end. Behaviour of the fitted curve:
//
//	quiet night   1k events,   30 IPs,   10 logins,   20 weap ->  16  LOW
//	typical day  15k events,  215 IPs,  363 logins,  357 weap ->  50  HIGH
//	10x wave    150k events, 2000 IPs, 3600 logins, 3600 weap ->  79  CRITICAL
//	worst case    1M events,  20k IPs,  20k logins,  20k weap -> 100  CRITICAL
//
// Across those 31 real days the score ranges 46-58 (median 51) where the old
// formula produced a flat 52, so day-to-day movement is now visible.
//
// The label bands are deliberately NOT retuned. Most days on an internet-facing
// honeypot genuinely are high-activity, and widening MODERATE so a busy box
// reads calmer would be moving the goalposts to make the number look better.
const threatWindow = 24 * time.Hour

// threatFactor is one 0-25 component: a log-scaled rate between a floor (below
// which it contributes nothing) and a ceiling (at which it maxes out).
type threatFactor struct {
	Key   string
	Label string
	Floor float64
	Ceil  float64
}

var threatFactors = struct {
	Volume, Diversity, Intrusion, Weaponization threatFactor
}{
	// Volume: events in the window. Ceiling is deliberately far above anything
	// observed so a genuine flood still has somewhere to go.
	Volume: threatFactor{"volume", "Volume", 300, 1_000_000},
	// Diversity: distinct source IPs. A botnet spraying from thousands of hosts
	// is a different threat from one host retrying, which is what this separates.
	Diversity: threatFactor{"diversity", "Diversity", 5, 10_000},
	// Intrusion: accepted logins. Replaces the old deploy-intent ratio.
	Intrusion: threatFactor{"intrusion", "Intrusion", 5, 20_000},
	// Weaponization: commands plus downloads weighted x3, since fetching a
	// payload is a materially worse signal than running a command.
	Weaponization: threatFactor{"weaponization", "Weaponization", 5, 20_000},
}

// score maps a rate onto 0-25 on a log scale, clamped at both ends.
func (f threatFactor) score(v float64) float64 {
	if v <= 0 || f.Ceil <= f.Floor {
		return 0
	}
	if v < f.Floor {
		v = f.Floor
	}
	r := math.Log10(v/f.Floor) / math.Log10(f.Ceil/f.Floor)
	return 25 * math.Max(0, math.Min(1, r))
}

type threatComponent struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Max    int     `json:"max"`
	Raw    int     `json:"raw"`    // the observed rate, so the UI can show its work
	Ratio  float64 `json:"ratio"`  // 0-1 position between floor and ceiling
	Capped bool    `json:"capped"` // at the ceiling: escalation beyond this is invisible
}

// threatBlock is the whole gauge, ready to render. The client does no scoring:
// the calibration is domain policy and lives in exactly one place, where it can
// be unit-tested against real history.
type threatBlock struct {
	Score       int               `json:"score"`
	Label       string            `json:"label"`
	WindowHours int               `json:"windowHours"`
	Since       string            `json:"since"`
	Components  []threatComponent `json:"components"`
	// Events/UniqueIPs are echoed for the widget's footer line, which used to
	// print all-time totals next to a windowed score — two different things
	// presented as if they belonged together.
	Events    int `json:"events"`
	UniqueIPs int `json:"uniqueIps"`
}

func threatLabel(score int) string {
	switch {
	case score <= 20:
		return "LOW"
	case score <= 45:
		return "MODERATE"
	case score <= 70:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// buildThreatBlock scores a window. Pure, so the calibration is testable without
// a database or a browser.
func buildThreatBlock(a store.WindowActivity, window time.Duration) threatBlock {
	weapRaw := a.Commands + a.Downloads*3

	mk := func(f threatFactor, raw int) threatComponent {
		sc := f.score(float64(raw))
		return threatComponent{
			Key:    f.Key,
			Label:  f.Label,
			Score:  int(math.Round(sc)),
			Max:    25,
			Raw:    raw,
			Ratio:  sc / 25,
			Capped: float64(raw) >= f.Ceil,
		}
	}
	comps := []threatComponent{
		mk(threatFactors.Volume, a.Events),
		mk(threatFactors.Diversity, a.UniqueIPs),
		mk(threatFactors.Intrusion, a.Accepted),
		mk(threatFactors.Weaponization, weapRaw),
	}

	// Sum the UNROUNDED factor scores, then round once. Rounding each component
	// first and adding them lets four half-point roundings stack into a two-point
	// error in the headline number.
	var total float64
	total += threatFactors.Volume.score(float64(a.Events))
	total += threatFactors.Diversity.score(float64(a.UniqueIPs))
	total += threatFactors.Intrusion.score(float64(a.Accepted))
	total += threatFactors.Weaponization.score(float64(weapRaw))
	score := int(math.Round(math.Min(100, total)))

	return threatBlock{
		Score:       score,
		Label:       threatLabel(score),
		WindowHours: int(window.Hours()),
		Since:       a.Since.UTC().Format(time.RFC3339),
		Components:  comps,
		Events:      a.Events,
		UniqueIPs:   a.UniqueIPs,
	}
}
