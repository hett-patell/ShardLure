package web

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runGlobeJS imports the embedded cobe-globe.js under node and runs scenario
// (module code that prints one JSON line), returning that line.
func runGlobeJS(t *testing.T, scenario string) string {
	t.Helper()
	node := requireNode(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cobe-globe.mjs"), cobeGlobeJS, 0o600); err != nil {
		t.Fatal(err)
	}
	script := "import * as g from './cobe-globe.mjs';\n" + scenario
	path := filepath.Join(dir, "run.mjs")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, raw)
	}
	return strings.TrimSpace(string(raw))
}

// The globe draws one route, from the latest connection into the honeypot,
// coloured by how long ago it was active on the feed's heat scale. A source in
// the honeypot's own city is a dot with no route; no located connection leaves
// only the honeypot.
func TestGlobeDrawsOneRouteForTheLatestConnection(t *testing.T) {
	out := runGlobeJS(t, `
const cfg = g.cobeThemeConfig('obsidian');
const now = Date.UTC(2026, 10, 26, 12, 0, 0);
const home = { lat: 19.076, lon: 72.8777 };
const level = (c) => cfg.heat.findIndex((h) => String(h) === String(c)) + 1;
const draw = (conn) => {
  const e = g.buildCobeEntities(home, conn, cfg, now);
  return {
    markers: e.markers.map((m) => m.id),
    arcs: e.arcs.map((a) => a.id),
    heat: e.arcs.length ? level(e.arcs[0].color) : 0,
  };
};
console.log(JSON.stringify([
  draw({ ip: '89.160.20.130', lat: 58.41, lon: 15.62, ts: now - 20e3 }),
  draw({ ip: '81.2.69.185', lat: 51.5, lon: -0.12, ts: now - 7200e3 }),
  draw({ ip: '1.2.3.4', lat: 19.08, lon: 72.88, ts: now - 20e3 }),
  draw(null),
]));
`)
	type drawn struct {
		Markers, Arcs []string
		Heat          int
	}
	var got []drawn
	decodeJS(t, out, &got)
	if len(got) != 4 {
		t.Fatalf("harness returned %d scenarios, want 4: %s", len(got), out)
	}
	want := []drawn{
		{Markers: []string{"home", "latest-connection"}, Arcs: []string{"route"}, Heat: 5},
		{Markers: []string{"home", "latest-connection"}, Arcs: []string{"route"}, Heat: 1},
		{Markers: []string{"home", "latest-connection"}, Arcs: []string{}, Heat: 0},
		{Markers: []string{"home"}, Arcs: []string{}, Heat: 0},
	}
	for i, name := range []string{"20 s ago", "2 h ago", "in the honeypot's city", "no connection"} {
		if strings.Join(got[i].Markers, ",") != strings.Join(want[i].Markers, ",") ||
			strings.Join(got[i].Arcs, ",") != strings.Join(want[i].Arcs, ",") || got[i].Heat != want[i].Heat {
			t.Errorf("%s: drew %+v, want %+v", name, got[i], want[i])
		}
	}
}

// The globe turns to look at a route from the side, so its height reads as a
// curve: the view sits off the midpoint, toward the equator, equally far from
// both ends and with both on the visible side. Antipodes have no midpoint.
func TestRouteView(t *testing.T) {
	out := runGlobeJS(t, `
const deg = Math.PI / 180;
const vec = (p) => g.latLonToVec3(p.lat, p.lon);
const angle = (u, w) => Math.acos(Math.max(-1, Math.min(1, u[0] * w[0] + u[1] * w[1] + u[2] * w[2]))) / deg;
const midLat = (a, b) => {
  const u = vec(a), w = vec(b), s = [u[0] + w[0], u[1] + w[1], u[2] + w[2]];
  return Math.asin(s[1] / Math.hypot(s[0], s[1], s[2])) / deg;
};
const mumbai = { lat: 19.076, lon: 72.8777 };
const routes = [
  [{ lat: 58.41, lon: 15.62 }, mumbai],
  [{ lat: 40.71, lon: -74.0 }, mumbai],
  [{ lat: -37.82, lon: 144.97 }, mumbai],
  [{ lat: 0, lon: 170 }, { lat: 0, lon: -170 }],
];
const views = routes.map(([a, b]) => {
  const [lat, lon] = g.routeView(a, b);
  const v = vec({ lat, lon });
  return { lat, mid: midLat(a, b), toA: angle(v, vec(a)), toB: angle(v, vec(b)) };
});
console.log(JSON.stringify({ views, antipodes: g.routeView({ lat: 10, lon: 20 }, { lat: -10, lon: -160 }) }));
`)
	var got struct {
		Views []struct {
			Lat, Mid, ToA, ToB float64
		}
		Antipodes [2]float64
	}
	decodeJS(t, out, &got)
	if len(got.Views) != 4 {
		t.Fatalf("harness returned %d views, want 4: %s", len(got.Views), out)
	}
	for i, v := range got.Views {
		if math.Abs(v.ToA-v.ToB) > 1e-6 || v.ToA >= 90 {
			t.Errorf("route %d: view is %.2f° and %.2f° from its ends, want equal and under 90°", i, v.ToA, v.ToB)
		}
		if v.Mid != 0 && math.Abs(v.Lat) >= math.Abs(v.Mid) {
			t.Errorf("route %d: view latitude %.2f is not nearer the equator than the midpoint's %.2f", i, v.Lat, v.Mid)
		}
	}
	// An equatorial route tips 0.35 rad (20.05°) north or south.
	if eq := got.Views[3]; math.Abs(math.Abs(eq.Lat)-20.05) > 0.01 {
		t.Errorf("equatorial route across the antimeridian: view latitude %.2f, want ±20.05", eq.Lat)
	}
	if got.Antipodes != [2]float64{10, 20} {
		t.Errorf("antipodes = %v, want the source itself [10 20]", got.Antipodes)
	}
}

// readSource reads a file from this package for assertions about wiring that is
// not observable through the embedded assets.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
