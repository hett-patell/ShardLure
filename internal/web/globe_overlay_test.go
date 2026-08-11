package web

import (
	"regexp"
	"strings"
	"testing"
)

// The globe overlay code has broken three times in the same way: it assumed
// attacker geography is spread out, when in reality the busiest actors are
// several machines in one datacentre city. Two Amsterdam actors projected to
// byte-identical screen coordinates and stacked their labels into an illegible
// pile, which reads as the labels not existing at all.
//
// These tests pin the invariants that prevent it. They read the embedded asset
// rather than a copy, so they fail if the shipped dashboard regresses.

// TestOverlayPoolIsNotPreSliced guards the subtlest half of the bug: the
// selectors filter by country and separation, so handing them a pre-sliced
// top-N leaves almost nothing. A `.slice(0, 6)` feeding the pool once cut
// eighteen candidate stickers down to two.
func TestOverlayPoolIsNotPreSliced(t *testing.T) {
	body := indexHTML
	fn := extractFunc(t, body, "function buildThemeOverlays")
	if strings.Contains(fn, "geoActors.slice(") {
		t.Error("buildThemeOverlays pre-slices its candidate pool; the separation " +
			"and country filters then have almost nothing to choose from")
	}
	if !strings.Contains(fn, "ShardCobe.actorOrder") {
		t.Error("overlay pool must come from the deduped marker ordering, " +
			"otherwise several actors in one city each get their own overlay")
	}
}

// TestSignalAndMeridianShareOneImplementation is the real lesson from this bug
// class. Signal and Meridian emitted byte-identical overlays from two separate
// branches, so the stacking fix landed in one and silently left the other
// broken. Sharing the implementation makes that divergence impossible.
func TestSignalAndMeridianShareOneImplementation(t *testing.T) {
	body := indexHTML
	if n := strings.Count(body, "kind: 'analytics'"); n != 1 {
		t.Errorf("analytics chips are emitted from %d places, want 1: a second copy "+
			"is how Signal kept a bug that was already fixed in Meridian", n)
	}
	if !strings.Contains(body, "if (theme === 'signal' || theme === 'meridian')") {
		t.Error("Signal and Meridian should route through one shared overlay builder")
	}
}

// TestEveryOverlayThemeSelectsBySeparation checks that each theme which places
// per-actor overlays picks by great-circle separation, not by rank alone.
func TestEveryOverlayThemeSelectsBySeparation(t *testing.T) {
	body := indexHTML
	for _, caller := range []string{"buildSatChipOverlays", "sprite"} {
		if !strings.Contains(body, "pickSpreadOverlays") {
			t.Fatalf("%s: no shared spread picker in the dashboard", caller)
		}
	}
	// Both call sites must pass a separation and a cap.
	calls := regexp.MustCompile(`pickSpreadOverlays\([^)]*\{[^}]*\}`).FindAllString(body, -1)
	if len(calls) < 2 {
		t.Fatalf("found %d pickSpreadOverlays call sites, want 2 (Sprite + Sat/Chip themes)", len(calls))
	}
	for _, c := range calls {
		if !strings.Contains(c, "minSepDeg") {
			t.Errorf("call site without minSepDeg, so clustered actors will stack: %s", c)
		}
		if !strings.Contains(c, "max") {
			t.Errorf("call site without a cap, so a busy day floods the globe: %s", c)
		}
	}
}

// TestStickerIndexComesFromMarkerOrdering pins the wrong-country fix: a flag's
// index has to come from the same ordering the markers were built from, or
// marker a<i> belongs to a different actor and the flag lies about who is where.
func TestStickerIndexComesFromMarkerOrdering(t *testing.T) {
	body := indexHTML
	if !strings.Contains(body, "marker: 'a' + p.i") {
		t.Error("sticker marker id must use the pool index p.i, not the sticker's own")
	}
	if !strings.Contains(body, "if (!ordered) return out;") {
		t.Error("sprite must emit no stickers before marker data exists; guessing an " +
			"ordering puts flags on the wrong countries")
	}
}

// TestDeclutterGroupsByVisualClass keeps a satellite from suppressing its own
// analytics chip (they deliberately share a place) while still preventing two
// pieces of reading matter from overlapping.
func TestDeclutterGroupsByVisualClass(t *testing.T) {
	body := indexHTML
	if !strings.Contains(body, "DECLUTTER_GROUP") {
		t.Fatal("no declutter group map; overlays would contend across visual classes")
	}
	group := extractFunc(t, body, "var DECLUTTER_GROUP")
	for kind, want := range map[string]string{
		"analytics": "label", "live": "label", "sat": "mark", "sticker": "sticker",
	} {
		if !strings.Contains(group, kind+": '"+want+"'") {
			t.Errorf("declutter group for %q should be %q; text must compete with text, "+
				"and a mark must not hide its own label", kind, want)
		}
	}
}

// TestDeclutterFadesInnerVisual pins the anti-flicker fix: the wrapper's opacity
// is the front/back signal (Cobe's variable, or the projection test), so
// declutter has to fade a child and let the two multiply instead of fighting.
func TestDeclutterFadesInnerVisual(t *testing.T) {
	js := string(cobeGlobeJS)
	if !strings.Contains(js, "declutterTarget") {
		t.Fatal("declutter must resolve an inner element to fade")
	}
	if strings.Contains(js, "el.style.visibility") {
		t.Error("declutter must not toggle visibility on the wrapper: that overrides " +
			"the front/back signal and makes stickers blink")
	}
	for _, cls := range []string{".globe-sticker", ".globe-analytics", ".globe-sat"} {
		if !strings.Contains(js, cls) {
			t.Errorf("declutterTarget does not cover %s, so that overlay cannot fade", cls)
		}
	}
}

// TestArcsNeverExceedMarkers pins the orphaned-arc fix: both slice the head of
// the same ranked list, so fewer arcs than markers leaves dots with no line.
func TestArcsNeverExceedMarkers(t *testing.T) {
	js := string(cobeGlobeJS)
	if !strings.Contains(js, "Math.min(opts.maxArcs ?? COBE_MAX_ARCS, maxMarkers)") {
		t.Error("maxArcs must be clamped to maxMarkers, or a theme can silently " +
			"render markers with no arc reaching them")
	}
}

// extractFunc returns the source from a declaration up to the next top-level
// declaration, which is enough to assert on a single function's body.
func extractFunc(t *testing.T, body, decl string) string {
	t.Helper()
	i := strings.Index(body, decl)
	if i < 0 {
		t.Fatalf("declaration %q not found in the embedded dashboard", decl)
	}
	rest := body[i+len(decl):]
	if j := strings.Index(rest, "\nfunction "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestHotHighlightScalesWithCap pins a bug that only shows up once a theme lowers
// its entity cap: the `hot` highlight used absolute counts (16 arcs, 12 markers)
// tuned for the 80-entity default, so at Sprite's cap of 24 two THIRDS of the
// arcs were hot and the highlight became the majority.
func TestHotHighlightScalesWithCap(t *testing.T) {
	js := string(cobeGlobeJS)
	for _, abs := range []string{"i < 16 ? hot", "i < 12 ? hot"} {
		if strings.Contains(js, abs) {
			t.Errorf("found absolute hot-count %q; it must scale with the cap or a "+
				"theme that lowers maxArcs turns the highlight into the majority", abs)
		}
	}
	if !strings.Contains(js, "hotArcs") || !strings.Contains(js, "hotMarkers") {
		t.Fatal("expected proportional hotArcs/hotMarkers")
	}
	// The DEFAULT ratios must reproduce the historical 16 arcs / 12 markers at the
	// 80-entity default, so a theme that never set a cap is untouched. Asserted on
	// the default values themselves rather than on the surrounding expression,
	// which is free to be refactored.
	for knob, def := range map[string]string{
		"hotArcRatio":    "?? 0.2",
		"hotMarkerRatio": "?? 0.15",
	} {
		if !strings.Contains(js, "opts."+knob+" "+def) {
			t.Errorf("default for %s is not %q; 0.2 and 0.15 are what reproduce the "+
				"historical 16 arcs / 12 markers at the 80 default", knob, def)
		}
	}
}

// TestSignalGlobeDensityIsCapped keeps Signal from drifting back to the 80-arc
// default that made it too glowy (measured: 22% higher mean luminance, 65% more
// blown-out pixels).
func TestSignalGlobeDensityIsCapped(t *testing.T) {
	js := string(cobeGlobeJS)
	i := strings.Index(js, `if (theme === "signal")`)
	if i < 0 {
		t.Fatal("signal theme config not found")
	}
	sig := js[i:]
	if j := strings.Index(sig, `if (theme === "sprite")`); j > 0 {
		sig = sig[:j]
	}
	// Both modes (light and dark) must be capped: density is not a palette issue.
	if n := strings.Count(sig, "maxArcs: 26"); n != 2 {
		t.Errorf("signal declares maxArcs: 26 %d times, want 2 (light + dark)", n)
	}
	if strings.Contains(sig, "arcWidth: 0.5,") {
		t.Error("signal still uses the wide 0.5 arc; it was thinned to 0.35 to cut glow")
	}
}

// TestEntityOptsForwardsEveryKnob guards a silent-failure mode: entityOpts is an
// explicit whitelist, so a knob added to a theme config has no effect at all
// until it is listed there. hotArcRatio was added and dropped exactly this way.
func TestEntityOptsForwardsEveryKnob(t *testing.T) {
	globe := string(cobeGlobeJS)
	boot := string(cobeBootJS)

	// Every `opts.X` buildCobeEntities reads must appear in entityOpts.
	i := strings.Index(boot, "function entityOpts(cfg) {")
	if i < 0 {
		t.Fatal("entityOpts not found")
	}
	forward := boot[i : i+strings.Index(boot[i:], "}")]

	// Scope to buildCobeEntities. Other exports (bindGlobeInteraction) take their
	// own unrelated opts, and scanning the whole file reports those as failures.
	b := strings.Index(globe, "export function buildCobeEntities")
	if b < 0 {
		t.Fatal("buildCobeEntities not found")
	}
	body := globe[b:]
	if e := strings.Index(body[1:], "\nexport function "); e >= 0 {
		body = body[:e+1]
	}

	read := regexp.MustCompile(`opts\.([A-Za-z]+)`).FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	for _, m := range read {
		knob := m[1]
		if seen[knob] {
			continue
		}
		seen[knob] = true
		if !strings.Contains(forward, knob+": cfg."+knob) {
			t.Errorf("buildCobeEntities reads opts.%s but entityOpts does not forward it; "+
				"the theme setting would be silently ignored", knob)
		}
	}
	if len(seen) == 0 {
		t.Error("found no opts.* reads; the check is not actually looking at anything")
	}
}
