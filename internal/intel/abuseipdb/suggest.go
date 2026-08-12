package abuseipdb

import (
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// Suggestion is a ranked report candidate for the dashboard "suggested targets"
// widget: a vetted brute-forcer with a composite priority score (0-100) and
// human-readable reasons so the ranking is explainable, not a black box.
type Suggestion struct {
	SrcIP           string   `json:"srcIp"`
	Playbook        string   `json:"playbook"`
	ProbeScore      int      `json:"probeScore"`
	EventCount      int      `json:"eventCount"`
	UniqueUsers     int      `json:"uniqueUsers"`
	AttemptsPerHour float64  `json:"attemptsPerHour"`
	LastSeen        string   `json:"lastSeen"` // RFC3339
	Priority        int      `json:"priority"` // 0-100 composite
	Reasons         []string `json:"reasons"`
}

// SuggestInput is one actor's scoring inputs.
//
// LastSeen now lives on ReportCandidate, because Vet needs it to reject dormant
// IPs and the gate must see everything it gates on. This wrapper stays: it is
// the seam where per-actor scoring context would attach, and collapsing it into
// a bare []ReportCandidate would churn every caller for no gain.
type SuggestInput struct {
	Cand ReportCandidate
	// LastSeen is deprecated: set Cand.LastSeen instead. When Cand.LastSeen is
	// zero this is copied into it, so existing callers keep working — but Vet
	// reads only Cand.LastSeen, so a value here alone no longer bypasses the
	// staleness gate.
	LastSeen time.Time
}

// lastSeen resolves the effective observation time, preferring the candidate's
// own field over the deprecated wrapper copy.
func (in SuggestInput) lastSeen() time.Time {
	if !in.Cand.LastSeen.IsZero() {
		return in.Cand.LastSeen
	}
	return in.LastSeen
}

// Priority weights. They sum to 100 so the composite reads as a percentage of
// an "ideal" report target. Confidence and recency dominate because AbuseIPDB
// values corroborated, CURRENT threats — a stale IP, however aggressive once,
// is lower-value to the community feed than one attacking right now.
const (
	wConfidence = 30.0 // our ProbeScore (how sure we are it's a brute-forcer)
	wRecency    = 30.0 // exponential decay on last-seen (active > dormant)
	wAggression = 20.0 // attempts/hour (sustained pressure)
	wBreadth    = 10.0 // distinct usernames tried (spray vs single-target)
	wVolume     = 10.0 // total events (weight of evidence)

	// recencyHalfLife: an actor last seen this long ago scores half its recency
	// weight; older decays exponentially toward 0. 24h means "today" ranks far
	// above "3 days ago", matching AbuseIPDB's freshness preference.
	recencyHalfLife = 24 * time.Hour

	// Saturation points: the input value at which a signal earns ~full weight.
	// Beyond these, more doesn't help (a log curve), so a single 100k-event
	// monster doesn't crowd out several fresh, high-confidence sprayers.
	aggressionSaturation = 500.0 // attempts/hour
	breadthSaturation    = 50.0  // distinct usernames
	volumeSaturation     = 5000.0
)

// Suggest ranks vetted report candidates by composite priority, most-urgent
// first. It runs each input through the SAME Vet gate the report path enforces
// (so a suggestion is always actionable), drops anything already reported
// within the window via alreadyReported, and returns at most `limit` rows.
//
// alreadyReported may be nil (nothing filtered). admin may be nil. now is
// injected for testability.
func Suggest(inputs []SuggestInput, admin *netmatch.Set, minProbe int, limit int, now time.Time, alreadyReported func(ip string) bool) []Suggestion {
	out := make([]Suggestion, 0, len(inputs))
	for _, in := range inputs {
		// Normalise before vetting: a caller using the deprecated wrapper field
		// must still be gated on staleness, not waved through on a zero value.
		cand := in.Cand
		cand.LastSeen = in.lastSeen()
		// Same gate, same arguments as the report path — a suggestion the
		// operator can click must be one Report would actually accept, or the
		// button lies. This is what excludes dormant IPs from the widget.
		if ok, _ := Vet(cand, admin, minProbe, now); !ok {
			continue
		}
		if alreadyReported != nil && alreadyReported(cand.SrcIP) {
			continue
		}
		pr, reasons := scoreOne(SuggestInput{Cand: cand}, now)
		out = append(out, Suggestion{
			SrcIP:           cand.SrcIP,
			Playbook:        cand.Playbook,
			ProbeScore:      cand.ProbeScore,
			EventCount:      cand.EventCount,
			UniqueUsers:     cand.UniqueUsers,
			AttemptsPerHour: cand.AttemptsPerHour,
			LastSeen:        cand.LastSeen.UTC().Format(time.RFC3339),
			Priority:        pr,
			Reasons:         reasons,
		})
	}
	// Rank by priority desc, then most-recent, then IP for a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].SrcIP < out[j].SrcIP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// scoreOne computes the 0-100 composite and the reasons that dominated it.
func scoreOne(in SuggestInput, now time.Time) (int, []string) {
	c := in.Cand

	confidence := float64(clampInt(c.ProbeScore, 0, 100)) / 100.0

	// Recency: exponential half-life decay. Future/zero last-seen clamps to
	// "now" (full weight) rather than producing a weird >1 factor.
	seen := in.lastSeen()
	age := now.Sub(seen)
	if age < 0 || seen.IsZero() {
		age = 0
	}
	recency := math.Pow(0.5, age.Hours()/recencyHalfLife.Hours())

	// Log-saturating curves: fast rise, then flatten near the saturation point.
	aggression := logSaturate(c.AttemptsPerHour, aggressionSaturation)
	breadth := logSaturate(float64(c.UniqueUsers), breadthSaturation)
	volume := logSaturate(float64(c.EventCount), volumeSaturation)

	score := wConfidence*confidence + wRecency*recency +
		wAggression*aggression + wBreadth*breadth + wVolume*volume
	priority := clampInt(int(math.Round(score)), 0, 100)

	// Reasons: surface the two or three signals that contributed most, so the
	// operator understands the ranking without reading the weights.
	type sig struct {
		label string
		val   float64
	}
	sigs := []sig{
		{"high confidence (probe " + itoa(c.ProbeScore) + ")", wConfidence * confidence},
		{recencyLabel(age), wRecency * recency},
		{"aggressive (" + itoaF(c.AttemptsPerHour) + "/h)", wAggression * aggression},
		{"broad spray (" + itoa(c.UniqueUsers) + " users)", wBreadth * breadth},
		{"high volume (" + itoa(c.EventCount) + " attempts)", wVolume * volume},
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].val > sigs[j].val })
	reasons := make([]string, 0, 3)
	for _, s := range sigs {
		if s.val < 2.0 { // ignore negligible contributors
			continue
		}
		reasons = append(reasons, s.label)
		if len(reasons) == 3 {
			break
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "meets reporting threshold")
	}
	return priority, reasons
}

// logSaturate maps x∈[0,∞) to [0,1] with a fast initial rise flattening near
// `sat`. ln(1+x)/ln(1+sat) reaches ~1.0 at x=sat and keeps climbing slowly
// beyond (clamped to 1), so extreme outliers don't dominate the composite.
func logSaturate(x, sat float64) float64 {
	if x <= 0 || sat <= 0 {
		return 0
	}
	v := math.Log1p(x) / math.Log1p(sat)
	if v > 1 {
		v = 1
	}
	return v
}

// recencyLabel describes the age in the operator's terms. The final branch says
// how stale rather than "recent activity", which was the previous wording: with
// the staleness gate capping age at 7 days it could only ever describe something
// 3-7 days old, so claiming "recent" understated it. In practice the label is
// dropped before it renders past ~93h (its weighted contribution falls under
// scoreOne's 2.0 negligible-contributor floor), but a reason string must not
// depend on being filtered out to be truthful.
func recencyLabel(age time.Duration) string {
	switch {
	case age < time.Hour:
		return "active now (last seen <1h)"
	case age < 24*time.Hour:
		return "active today"
	case age < 72*time.Hour:
		return "seen in last 3 days"
	default:
		return "last seen " + itoa(int(age.Hours()/24)) + "d ago"
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func itoa(n int) string { return strconv.Itoa(n) }

func itoaF(f float64) string { return strconv.FormatFloat(f, 'f', 0, 64) }
