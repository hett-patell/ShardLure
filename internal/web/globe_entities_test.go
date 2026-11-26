package web

import (
	"fmt"
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
    route: e.route ? [e.route.from.lat, e.route.from.lon, e.route.to.lat, e.route.to.lon] : [],
    heat: e.route ? level(e.route.color) : 0,
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
		Markers []string
		Route   []float64
		Heat    int
	}
	var got []drawn
	decodeJS(t, out, &got)
	if len(got) != 4 {
		t.Fatalf("harness returned %d scenarios, want 4: %s", len(got), out)
	}
	want := []drawn{
		{Markers: []string{"home", "latest-connection"}, Route: []float64{58.41, 15.62, 19.076, 72.8777}, Heat: 5},
		{Markers: []string{"home", "latest-connection"}, Route: []float64{51.5, -0.12, 19.076, 72.8777}, Heat: 1},
		{Markers: []string{"home", "latest-connection"}, Route: []float64{}, Heat: 0},
		{Markers: []string{"home"}, Route: []float64{}, Heat: 0},
	}
	for i, name := range []string{"20 s ago", "2 h ago", "in the honeypot's city", "no connection"} {
		if strings.Join(got[i].Markers, ",") != strings.Join(want[i].Markers, ",") ||
			fmt.Sprint(got[i].Route) != fmt.Sprint(want[i].Route) || got[i].Heat != want[i].Heat {
			t.Errorf("%s: drew %+v, want %+v", name, got[i], want[i])
		}
	}
}

// The route flies over the globe: Cobe's own arcs are quadratic curves whose
// middle sank inside the sphere on long routes (San Diego to Mumbai, 127°,
// sliced through the globe). Every point of the path must stay above the
// sphere, start and end on the two dots, follow one great circle, and rise
// off the surface in the middle, for short, long and antipodal routes alike.
func TestRoutePathFliesOverTheGlobe(t *testing.T) {
	out := runGlobeJS(t, `
const mumbai = { lat: 19.076, lon: 72.8777 };
const routes = {
  short: [{ lat: 23.0, lon: 72.6 }, mumbai],
  london: [{ lat: 51.5, lon: -0.12 }, mumbai],
  sandiego: [{ lat: 32.7157, lon: -117.1611 }, mumbai],
  antipodes: [{ lat: -19.076, lon: -107.1223 }, mumbai],
};
const elevation = g.cobeThemeConfig('obsidian').markerElevation;
const base = g.SPHERE_RADIUS + elevation;
const len = (v) => Math.hypot(v[0], v[1], v[2]);
const unit = (v) => v.map((c) => c / len(v));
const near = (a, b) => Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]) < 1e-6;
const out = {};
for (const [name, [a, b]] of Object.entries(routes)) {
  const pts = g.routePath(a, b, elevation);
  const radii = pts.map(len);
  // One great circle: every point's direction lies in the plane of the ends.
  const u = unit(pts[0]), w = unit(pts[pts.length - 1]);
  const n = [u[1] * w[2] - u[2] * w[1], u[2] * w[0] - u[0] * w[2], u[0] * w[1] - u[1] * w[0]];
  const nl = len(n);
  const offPlane = nl < 1e-9 ? 0 : Math.max(...pts.map((p) => Math.abs((p[0] * n[0] + p[1] * n[1] + p[2] * n[2]) / nl / len(p))));
  out[name] = {
    finite: pts.every((p) => p.every(Number.isFinite)),
    lowest: Math.min(...radii),
    middle: radii[Math.floor(radii.length / 2)],
    starts: near(pts[0], g.latLonToVec3(a.lat, a.lon).map((c) => c * base)),
    ends: near(pts[pts.length - 1], g.latLonToVec3(b.lat, b.lon).map((c) => c * base)),
    offPlane,
  };
}
console.log(JSON.stringify({ base, sphere: g.SPHERE_RADIUS, routes: out }));
`)
	var got struct {
		Base, Sphere float64
		Routes       map[string]struct {
			Finite, Starts, Ends     bool
			Lowest, Middle, OffPlane float64
		}
	}
	decodeJS(t, out, &got)
	if len(got.Routes) != 4 {
		t.Fatalf("harness returned %d routes, want 4: %s", len(got.Routes), out)
	}
	for name, r := range got.Routes {
		if !r.Finite {
			t.Errorf("%s: the path has a non-finite point", name)
			continue
		}
		if r.Lowest < got.Base-1e-9 {
			t.Errorf("%s: a point sits at radius %.3f, under the dots' %.3f (sphere %.1f): the route cuts into the globe", name, r.Lowest, got.Base, got.Sphere)
		}
		if r.Middle <= got.Base+0.001 {
			t.Errorf("%s: the middle sits at radius %.3f, not lifted off the dots' %.3f", name, r.Middle, got.Base)
		}
		if !r.Starts || !r.Ends {
			t.Errorf("%s: the path does not run from the source's dot to the honeypot's (starts %v, ends %v)", name, r.Starts, r.Ends)
		}
		if r.OffPlane > 1e-9 {
			t.Errorf("%s: a point strays %.2g off the great circle", name, r.OffPlane)
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
