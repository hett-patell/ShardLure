package script

// FamilyThreshold was measured on production (ARM, 30 days): variants of one
// bot sit at <= 0.09, the nearest unrelated pair at 0.197.
const (
	FamilyThreshold   = 0.12
	MaxDistanceTokens = 300
	minLengthRatio    = 0.8
)

// Tokens flattens an encoded script for distance, with ";" between lines.
func Tokens(enc string) []string {
	var out []string
	for i, c := range Split(enc) {
		if i > 0 {
			out = append(out, ";")
		}
		out = append(out, c...)
		if len(out) >= MaxDistanceTokens {
			return out[:MaxDistanceTokens]
		}
	}
	return out
}

// Distance is the optimal-string-alignment Damerau-Levenshtein distance over
// tokens, divided by the longer length.
func Distance(a, b []string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 0
	}
	prev2, prev, cur := make([]int, lb+1), make([]int, lb+1), make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			v := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				v = min(v, prev2[j-2]+1)
			}
			cur[j] = v
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return float64(prev[lb]) / float64(max(la, lb))
}

// InLengthBand is AssignFamily's pre-filter: two scripts are compared only
// when both have tokens and the shorter is at least minLengthRatio of the
// longer. Exported so callers can skip loading representatives AssignFamily
// would ignore, without re-implementing (and drifting from) the rule.
func InLengthBand(a, b int) bool {
	return a != 0 && b != 0 && float64(min(a, b))/float64(max(a, b)) >= minLengthRatio
}

// familyDistance is AssignFamily's distance; a test seam, so a test can
// prove the length band skips the O(n*m) computation rather than only
// losing on the threshold afterwards.
var familyDistance = Distance

type Rep struct {
	Fingerprint string
	Tokens      []string
}

// AssignFamily returns the closest representative within FamilyThreshold.
// reps must be sorted by Fingerprint; ties go to the first (smallest).
func AssignFamily(tokens []string, reps []Rep) (string, float64, bool) {
	best, bestD := "", 2.0
	for _, r := range reps {
		if !InLengthBand(len(tokens), len(r.Tokens)) {
			continue
		}
		if d := familyDistance(tokens, r.Tokens); d < bestD {
			best, bestD = r.Fingerprint, d
		}
	}
	if best == "" || bestD > FamilyThreshold {
		return "", 0, false
	}
	return best, bestD, true
}
