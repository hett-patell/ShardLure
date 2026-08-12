package web

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func act(events, ips, accepted, commands, downloads int) store.WindowActivity {
	return store.WindowActivity{
		Since: time.Now().Add(-threatWindow), Events: events, UniqueIPs: ips,
		Accepted: accepted, Commands: commands, Downloads: downloads,
	}
}

// TestThreatScoreMovesOnRealHistory is the regression that matters. The old
// gauge scored cumulative totals and returned exactly 52 for months on the
// reference deployment. These are its real daily figures; the score has to vary
// across them, which is the whole point of windowing.
func TestThreatScoreMovesOnRealHistory(t *testing.T) {
	// day: events, ips, commands, downloads, accepted — from the reference box.
	days := [][5]int{
		{23864, 288, 503, 20, 605}, {7814, 287, 187, 15, 258},
		{24127, 235, 478, 18, 524}, {15004, 209, 279, 14, 362},
		{16235, 260, 324, 18, 376}, {15220, 223, 242, 10, 363},
		{12558, 210, 368, 23, 363}, {20024, 217, 359, 36, 404},
		{12239, 191, 302, 8, 356}, {10743, 211, 320, 21, 361},
		{13686, 223, 228, 33, 323}, {16663, 236, 283, 18, 392},
		{21994, 243, 339, 13, 426}, {14672, 170, 201, 21, 340},
		{14945, 193, 258, 19, 257}, {11939, 155, 191, 19, 252},
		{15755, 172, 351, 45, 435}, {30849, 180, 579, 22, 538},
	}
	seen := map[int]bool{}
	min, max := 101, -1
	for _, d := range days {
		s := buildThreatBlock(act(d[0], d[1], d[4], d[2], d[3]), threatWindow).Score
		seen[s] = true
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
	}
	if len(seen) < 5 {
		t.Errorf("only %d distinct scores across %d real days; the gauge is still "+
			"effectively constant (it read a flat 52 before windowing)", len(seen), len(days))
	}
	if max-min < 5 {
		t.Errorf("score spread %d over real history is too flat to be informative", max-min)
	}
	// Typical days must not sit at either rail, or there is no headroom to show
	// an escalation and no room to show things calming down.
	if min < 25 || max > 85 {
		t.Errorf("real history spans %d-%d; typical activity should sit mid-range, "+
			"leaving room in both directions", min, max)
	}
}

// TestThreatFactorsAreNotSaturatedByTypicalTraffic pins the specific defect: two
// factors were permanently at 25/25, so escalation in them was invisible.
func TestThreatFactorsAreNotSaturatedByTypicalTraffic(t *testing.T) {
	b := buildThreatBlock(act(15000, 215, 363, 300, 19), threatWindow)
	for _, c := range b.Components {
		if c.Capped {
			t.Errorf("%s is at its ceiling on a TYPICAL day; further escalation "+
				"could not raise the score", c.Label)
		}
		if c.Score >= c.Max {
			t.Errorf("%s scores %d/%d on a typical day: saturated", c.Label, c.Score, c.Max)
		}
		if c.Score == 0 {
			t.Errorf("%s scores 0 on a typical day, so it contributes nothing "+
				"(the old aggression factor failed exactly this way)", c.Label)
		}
	}
}

// TestThreatScoreEscalates checks the gauge responds to a worsening situation
// and reaches the top of the range only for genuinely extreme input.
func TestThreatScoreEscalates(t *testing.T) {
	quiet := buildThreatBlock(act(1000, 30, 10, 20, 0), threatWindow)
	typical := buildThreatBlock(act(15000, 215, 363, 300, 19), threatWindow)
	wave := buildThreatBlock(act(150000, 2000, 3600, 3000, 200), threatWindow)
	worst := buildThreatBlock(act(1000000, 20000, 20000, 20000, 5000), threatWindow)

	if !(quiet.Score < typical.Score && typical.Score < wave.Score && wave.Score < worst.Score) {
		t.Fatalf("not monotonic: quiet=%d typical=%d wave=%d worst=%d",
			quiet.Score, typical.Score, wave.Score, worst.Score)
	}
	if quiet.Label != "LOW" {
		t.Errorf("quiet night labelled %q, want LOW (score %d)", quiet.Label, quiet.Score)
	}
	if wave.Label != "CRITICAL" {
		t.Errorf("10x wave labelled %q, want CRITICAL (score %d)", wave.Label, wave.Score)
	}
	if worst.Score != 100 {
		t.Errorf("worst case scored %d, want the full 100", worst.Score)
	}
}

// TestThreatScoreZeroWindow covers a fresh install and a dead honeypot: no
// events must read 0/LOW, not a middling number from log-scale floors.
func TestThreatScoreZeroWindow(t *testing.T) {
	b := buildThreatBlock(act(0, 0, 0, 0, 0), threatWindow)
	if b.Score != 0 || b.Label != "LOW" {
		t.Errorf("empty window scored %d/%s, want 0/LOW", b.Score, b.Label)
	}
	for _, c := range b.Components {
		if c.Score != 0 {
			t.Errorf("%s scored %d on an empty window", c.Label, c.Score)
		}
	}
}

// TestThreatHeadlineRoundsOnce pins the headline to round(sum of unrounded
// factors), NOT to the sum of the rounded factors shown in the breakdown. Four
// half-point roundings can stack, and these inputs are cases where the two
// genuinely disagree — found by search, because an assertion that the headline
// merely matches the breakdown is satisfied by the buggy implementation and
// therefore proves nothing.
func TestThreatHeadlineRoundsOnce(t *testing.T) {
	cases := []struct {
		events, ips, accepted, commands int
		want                            int // round(sum); sum(round) would give want+1
	}{
		{1000, 50, 50, 50, 25},
		{1000, 50, 50, 89, 27},
		{1000, 50, 50, 128, 28},
	}
	for _, c := range cases {
		b := buildThreatBlock(act(c.events, c.ips, c.accepted, c.commands, 0), threatWindow)
		if b.Score != c.want {
			sum := 0
			for _, comp := range b.Components {
				sum += comp.Score
			}
			t.Errorf("events=%d ips=%d accepted=%d commands=%d: score = %d, want %d "+
				"(components sum to %d; rounding each before adding inflates the headline)",
				c.events, c.ips, c.accepted, c.commands, b.Score, c.want, sum)
		}
	}
}

// TestThreatBreakdownExplainsHeadline is the UI-honesty check: whatever the
// rounding, the displayed parts must still add up to roughly the number they sit
// under, or the widget contradicts itself on screen.
func TestThreatBreakdownExplainsHeadline(t *testing.T) {
	for _, d := range [][5]int{
		{15004, 209, 362, 279, 14}, {7814, 287, 258, 187, 15}, {30849, 180, 538, 579, 22},
	} {
		b := buildThreatBlock(act(d[0], d[1], d[2], d[3], d[4]), threatWindow)
		sum := 0
		for _, c := range b.Components {
			sum += c.Score
		}
		if diff := b.Score - sum; diff > 1 || diff < -1 {
			t.Errorf("headline %d vs components summing to %d (diff %d): the breakdown "+
				"must explain the number it sits under", b.Score, sum, diff)
		}
	}
}

// TestThreatWindowIsBounded pins the core fix: the gauge must describe a window,
// never an all-time total.
func TestThreatWindowIsBounded(t *testing.T) {
	b := buildThreatBlock(act(15000, 215, 363, 300, 19), threatWindow)
	if b.WindowHours != 24 {
		t.Errorf("windowHours = %d, want 24", b.WindowHours)
	}
	if b.Since == "" {
		t.Error("no window start reported; the client cannot say what the score covers")
	}
}

// TestThreatWeightsDownloadsAboveCommands checks fetching a payload counts for
// more than running a command, which is the only reason downloads are weighted.
func TestThreatWeightsDownloadsAboveCommands(t *testing.T) {
	cmds := buildThreatBlock(act(15000, 215, 363, 300, 0), threatWindow)
	dls := buildThreatBlock(act(15000, 215, 363, 0, 300), threatWindow)
	if dls.Score <= cmds.Score {
		t.Errorf("300 downloads scored %d, not more than 300 commands at %d",
			dls.Score, cmds.Score)
	}
}

// TestNeitherDashboardScoresTheGaugeItself is the guard for how this bug
// survived so long. BOTH pages render a Threat Level panel, and both used to
// compute it in their own template from all-time totals — so the value was
// frozen twice over, and fixing one page left the other wrong. Scoring belongs
// in Go; these pages may only draw what the API sends.
func TestNeitherDashboardScoresTheGaugeItself(t *testing.T) {
	for name, body := range map[string]string{"index.html": indexHTML, "intel.html": intelHTML} {
		if !strings.Contains(body, "renderGauge(d.threat)") {
			t.Errorf("%s: gauge is not fed from the server-scored d.threat block", name)
		}
		// Scoring fingerprints. Any of these inside a page means the calibration
		// has leaked back into a template, where it cannot be tested and will
		// drift from the other page.
		for _, banned := range []string{
			"volScore", "divScore", "agrScore", "weapScore",
			"Math.log10", "classifiable",
		} {
			if strings.Contains(body, banned) {
				t.Errorf("%s contains %q: gauge scoring must stay in threat.go, not in a "+
					"template where the two dashboards can disagree", name, banned)
			}
		}
		// The footer must describe the window it measured, not lifetime totals.
		if !strings.Contains(body, "(threat.windowHours||24)+'h") {
			t.Errorf("%s: gauge footer does not state the window; it previously printed "+
				"all-time totals beside a windowed score", name)
		}
	}
}

// TestBothDashboardsServeTheSameThreatBlock pins that the two APIs share one
// scored block from one cache, rather than each deriving their own.
func TestBothDashboardsServeTheSameThreatBlock(t *testing.T) {
	src := readSource(t, "server.go")
	if !strings.Contains(src, "Threat *threatBlock") || !strings.Contains(src, "Threat:       threat") {
		t.Error("/api/dashboard does not serve the shared threatBlock")
	}
	if !strings.Contains(src, "s.threatBlockCached()") {
		t.Error("/api/dashboard must reuse the cached block, not recompute the window")
	}
	intel := readSource(t, "intel.go")
	if !strings.Contains(intel, "s.threatBlockCached()") {
		t.Error("/api/intel must reuse the same cached block")
	}
}

// TestNoRateDisplayUsesTheLifetimeAverage pins every place that renders a "/h"
// figure to the WINDOWED rate. Actor.AttemptsPerHour is a lifetime mean; the
// Brute-Force Radar was ranking and printing it, which showed eight attackers
// that had been silent for 8 to 39 days as the "most aggressive".
//
// Asserted on the source because the wiring is what regresses: a new panel that
// copies `a.AttemptsPerHour` into a rate field reintroduces the bug silently.
func TestNoRateDisplayUsesTheLifetimeAverage(t *testing.T) {
	// Whitespace-insensitive: gofmt re-aligns struct fields whenever a
	// neighbouring field name changes length, so a literal-substring check
	// silently stops matching. A mutation test caught exactly that - the
	// mutation was a no-op and the assertion looked like it had failed to fire.
	banned := regexp.MustCompile(
		`(RateHour|AttemptsPerHour)\s*:\s*\w+\.AttemptsPerHour`)
	for _, name := range []string{"intel.go", "server.go", "api_intel.go"} {
		src := readSource(t, name)
		if m := banned.FindString(src); m != "" {
			t.Errorf("%s contains %q: a rate shown to the operator, or used to weight a "+
				"report, must come from store.RecentRatesByActor and not the lifetime average",
				name, m)
		}
	}
	// And the radar must use the windowed ranking query.
	if !strings.Contains(readSource(t, "intel.go"), "TopActorsByRecentRate") {
		t.Error("radar no longer ranks by TopActorsByRecentRate")
	}
	if strings.Contains(readSource(t, "intel.go"), "TopActorsByRate(") {
		t.Error("radar reverted to TopActorsByRate, which orders by the lifetime average")
	}
}

// TestWindowedPanelsDiscloseSampling pins the fix for silently sampled panels.
// The windowed-analytics fetch is capped, so on a busy deployment these panels
// describe a SAMPLE. The server already set an advisory header, but no panel
// reads response headers, so the numbers rendered as window totals — measured at
// 200,000 of 533,647 events with half the long tail missing.
func TestWindowedPanelsDiscloseSampling(t *testing.T) {
	src := readSource(t, "api_intel.go")
	// Every handler that caps its analysis must also report it in the BODY.
	for _, resp := range []string{"mitreResponse", "ttpResponse", "deobfResponse", "iocListResponse"} {
		i := strings.Index(src, "type "+resp+" struct {")
		if i < 0 {
			t.Errorf("%s not found", resp)
			continue
		}
		if !strings.Contains(src[i:i+strings.Index(src[i:], "}")], "Sampled") {
			t.Errorf("%s has no Sampled field: a capped analysis would render as a "+
				"window total with nothing said about it", resp)
		}
	}
	if n := strings.Count(src, "sampledWindow(len(events)"); n < 4 {
		t.Errorf("only %d handlers populate Sampled, want >= 4", n)
	}
	// And the dashboard must actually render it.
	if !strings.Contains(intelHTML, "function sampledNote(") {
		t.Fatal("no sampledNote renderer in the dashboard")
	}
	if n := strings.Count(intelHTML, "sampledNote(data)"); n < 4 {
		t.Errorf("sampledNote used in %d panels, want >= 4 (MITRE, TTP, IOC, deobf)", n)
	}
}

// TestWordlistCountsInSQL pins the wordlist fix: it must aggregate in the
// database, not fold a capped window of events in memory. Folding made it
// understate every count by ~60% and drop 47% of the distinct usernames.
func TestWordlistCountsInSQL(t *testing.T) {
	src := readSource(t, "api_intel.go")
	i := strings.Index(src, "func (s *Server) handleIntelWordlist(")
	if i < 0 {
		t.Fatal("wordlist handler not found")
	}
	body := src[i : i+3000]
	for _, banned := range []string{"wordlist.CollectUsernames(", "wordlist.CollectPasswords(", "wordlist.CollectCombos("} {
		if strings.Contains(body, banned) {
			t.Errorf("wordlist still folds events in memory via %s; that path is capped "+
				"and silently samples the window", banned)
		}
	}
	for _, want := range []string{"TopUsernamesSince", "TopPasswordsSince", "TopCombosSince"} {
		if !strings.Contains(body, want) {
			t.Errorf("wordlist does not use %s", want)
		}
	}
}
