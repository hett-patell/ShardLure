package campaign

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// bridgeChain is the audit's attacker-shaped input (I-1): m two-actor key
// campaigns, already assigned by a first cycle, then one actor whose sessions
// {k_i, k_i+1, f_i} chain every campaign into one component and introduce m
// new values. Every k_i is shared by two actors only, so none is common, and
// the chaining actor carries all m lineages: attribution used to enumerate
// them once per floating value, m^2 in total.
func bridgeChain(m int) Input {
	var occ []Occurrence
	for i := 0; i < m; i++ {
		k := fmt.Sprintf("K%d", i)
		occ = append(occ, o("ssh_key", k, fmt.Sprintf("a%d", i), fmt.Sprintf("actorA%d", i), 0),
			o("ssh_key", k, fmt.Sprintf("b%d", i), fmt.Sprintf("actorB%d", i), 0))
	}
	first := groupT(Input{Occurrences: occ})
	for i := 0; i < m; i++ {
		s := fmt.Sprintf("z%d", i)
		occ = append(occ, o("ssh_key", fmt.Sprintf("K%d", i), s, "bridge", 1), o("payload", fmt.Sprintf("F%d", i), s, "bridge", 1))
		if i+1 < m {
			occ = append(occ, o("ssh_key", fmt.Sprintf("K%d", i+1), s, "bridge", 1))
		}
	}
	return Input{Occurrences: occ, Assignments: first.Assignments, Aliases: first.Aliases}
}

// A regroup over the bridge chain must stay near-linear: at m=2,000 (10,000
// occurrences) the quadratic attribution took 7.3 s on x86 (I-1), enough to
// outlive the worker lease and the 2-minute cycle budget. The bound here is
// loose on purpose (CI hosts vary); the audit's figure was 10x above it.
func TestGroupScalesOnBridgeChain(t *testing.T) {
	in := bridgeChain(2000)
	start := time.Now()
	out := groupT(in)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Group over the m=2000 bridge chain took %v, want well under 1 s", d)
	}
	if len(out.Campaigns) != 1 {
		t.Fatalf("the chain must form one component, got %d campaigns", len(out.Campaigns))
	}
	// The second cycle, fed its own output, is the steady state.
	start = time.Now()
	groupT(Input{Occurrences: in.Occurrences, Assignments: out.Assignments, Aliases: out.Aliases})
	if d := time.Since(start); d > time.Second {
		t.Fatalf("second cycle over the m=2000 bridge chain took %v, want well under 1 s", d)
	}
}

// TestGroupScaleMeasure logs the timings the audit report cites. Opt-in:
//
//	SHARDLURE_CAMPAIGN_SCALE=500,2000,4000 go test ./internal/campaign/ -run TestGroupScaleMeasure -v
func TestGroupScaleMeasure(t *testing.T) {
	spec := os.Getenv("SHARDLURE_CAMPAIGN_SCALE")
	if spec == "" {
		t.Skip("set SHARDLURE_CAMPAIGN_SCALE=<m,m,...> to measure")
	}
	for _, f := range splitComma(spec) {
		m, err := strconv.Atoi(f)
		if err != nil || m <= 0 {
			t.Fatalf("bad m %q", f)
		}
		in := bridgeChain(m)
		start := time.Now()
		out := groupT(in)
		d1 := time.Since(start)
		start = time.Now()
		groupT(Input{Occurrences: in.Occurrences, Assignments: out.Assignments, Aliases: out.Aliases})
		d2 := time.Since(start)
		t.Logf("m=%d occurrences=%d first=%v second=%v", m, len(in.Occurrences), d1, d2)
	}
}

func splitComma(s string) []string {
	var out []string
	for _, f := range []byte(s) {
		if f == ',' {
			out = append(out, "")
			continue
		}
		if len(out) == 0 {
			out = append(out, "")
		}
		out[len(out)-1] += string(f)
	}
	return out
}

// groupT runs Group with a background context for tests whose input is small
// enough that cancellation is not the question.
func groupT(in Input) Output {
	out, err := Group(context.Background(), in)
	if err != nil {
		panic(err)
	}
	return out
}
