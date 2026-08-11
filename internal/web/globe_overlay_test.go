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
