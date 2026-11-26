/**
 * Lazy-loaded Cobe engine for the activity globe, shared by Obsidian and Kiln.
 *
 * The globe draws one route: from the newest connection's source into the
 * honeypot. Cobe draws the sphere and the two dots; the route is a lifted
 * great circle drawn in 2D on a canvas over it (drawRoute), so it flies over
 * the globe however long it is. The globe never spins on its own. A new
 * connection replaces the route: it draws itself from the source to the
 * honeypot, the source's dot pings as it leaves and the honeypot's as it
 * lands, and the globe turns to show the whole route, so motion on the page
 * always means "someone new connected". Under prefers-reduced-motion the route
 * simply appears and the turn is a cut.
 */
import createGlobe from "/vendor/cobe.esm.js";
import {
  bindGlobeInteraction,
  startGlobeLoop,
  cobeThemeConfig,
  cobeEntitiesKey,
  buildCobeEntities,
  projectVec,
  routePath,
  routeView,
  viewAngles,
} from "/cobe-globe.js?v=20";

let _globe = null;
let _stop = null;
let _ix = null;
let _state = null;
let _theme = null;
let _home = { lat: 19.076, lon: 72.8777 };
// The connection the globe draws, { ip, lat, lon, ts }, or null while the
// newest source has no location.
let _conn = null;
// The last connection drawn, to tell a new one from more activity on it.
let _last = null;
let _entities = null;
let _dataKey = "";
let _arrived = false;
let _frameOnPaint = false;
let _pings = [];
let _animFrame = 0;
// The route overlay: its canvas, the path it draws (points of Cobe's scene),
// that path's endpoints as a key, and its colour as 0..255 RGB.
let _routeCanvas = null;
let _routePts = null;
let _routeKey = "";
let _routeRGB = null;
// How much of the route is drawn, 0..1, and when it began drawing itself in
// (0 once it is whole).
let _drawn = 0;
let _drawAt = 0;

// The same source back after this long is a new connection, not more of one.
const QUIET_MS = 5 * 60 * 1000;
const PING_MS = 900;
// How long a new route takes to draw itself from the source to the honeypot,
// whose dot pings as it lands.
const DRAW_MS = 900;

function stage() {
  return document.getElementById("cobe-stage");
}
function wrap() {
  return document.getElementById("cobe-wrap");
}
function canvas() {
  return document.getElementById("cobe");
}
function overlays() {
  return document.getElementById("cobe-overlays");
}
const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function destroy() {
  if (_stop) {
    try {
      _stop();
    } catch (_) {}
    _stop = null;
  }
  if (_ix) {
    try {
      if (typeof _ix.destroy === "function") _ix.destroy();
    } catch (_) {}
  }
  if (_globe) {
    try {
      if (typeof _globe.destroy === "function") _globe.destroy();
    } catch (_) {}
    _globe = null;
  }
  cancelAnimationFrame(_animFrame);
  _animFrame = 0;
  _pings = [];
  _arrived = false;
  _routeKey = "";
  _routePts = null;
  _drawn = 0;
  _drawAt = 0;
  if (_routeCanvas) {
    const ctx = _routeCanvas.getContext("2d");
    if (ctx) {
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, _routeCanvas.width, _routeCanvas.height);
    }
  }
  _ix = null;
  _state = null;
  _theme = null;
  _entities = null;
  _dataKey = "";
  const ov = overlays();
  if (ov) ov.innerHTML = "";
  const st = stage();
  if (st) {
    st.hidden = true;
    st.classList.remove("on");
  }
}

async function ensure(theme) {
  if (_globe && _theme === theme) {
    const st = stage();
    if (st) {
      st.hidden = false;
      st.classList.add("on");
    }
    return _globe;
  }
  destroy();
  const st = stage();
  const w = wrap();
  const c = canvas();
  if (!st || !w || !c) return null;
  st.hidden = false;
  st.classList.add("on");

  const cfg = cobeThemeConfig(theme);
  _entities = buildCobeEntities(_home, _conn, cfg);
  // Open on the live route when there is one (a theme switch rebuilds the
  // globe), otherwise on the honeypot itself.
  const [lat, lon] = _conn ? routeView(_conn, _home) : [_home.lat, _home.lon];
  const [phi, theta] = viewAngles(lat, lon);
  _state = { phi, theta, targetPhi: phi, targetTheta: theta, interacting: false };
  const places = [{ id: "home", label: "Home", lat: _home.lat, lon: _home.lon }];
  // markerElevation is passed through so the fallback projection (browsers
  // without CSS anchor positioning) puts labels on the same sphere as the
  // WebGL markers rather than a hardcoded radius.
  _ix = bindGlobeInteraction(c, _state, {
    wrap: w,
    places,
    markerElevation: cfg.markerElevation,
  });
  // Width and height are framebuffer pixels: CSS size times a capped DPR (full
  // retina at globe size reallocates WebGL buffers and hangs weak GPUs).
  const css = Math.min(w.clientWidth || 480, w.clientHeight || 480);
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  const backing = Math.max(2, Math.min(1400, Math.round(css * dpr)));
  _globe = createGlobe(c, {
    devicePixelRatio: 1,
    width: backing,
    height: backing,
    phi,
    theta,
    dark: cfg.dark,
    diffuse: cfg.diffuse,
    mapSamples: cfg.mapSamples,
    mapBrightness: cfg.mapBrightness,
    mapBaseBrightness: cfg.mapBaseBrightness,
    baseColor: cfg.baseColor,
    markerColor: cfg.markerColor,
    glowColor: cfg.glowColor,
    markerElevation: cfg.markerElevation,
    markers: _entities.markers,
  });
  _dataKey = cobeEntitiesKey(_home, _entities.markers);
  _theme = theme;
  _routeCanvas = routeCanvas();
  setRoute(_entities.route, false);
  _stop = startGlobeLoop(_globe, _ix, (view) => drawRoute(view.phi, view.theta));
  return _globe;
}

/**
 * New dashboard data: the honeypot's location and the live connection,
 * { ip, lat, lon, ts } with ts in epoch ms, or null while the newest source has
 * no location. Painted at once, in the same tick the page moves the label, so
 * the two never disagree about where the connection is.
 */
function updateData(home, conn) {
  if (home) _home = home;
  if (conn !== undefined) {
    _conn = conn;
    if (conn) {
      // The first connection the page sees is where the globe opens, not an
      // arrival. After that a different source, or the same one back after a
      // quiet spell, is a new connection; more activity on one is not.
      if (!_last) {
        _frameOnPaint = true;
      } else if (conn.ip !== _last.ip || conn.ts - _last.ts > QUIET_MS) {
        _arrived = _arrived || !!_globe;
      }
      _last = { ip: conn.ip, ts: conn.ts };
    }
  }
  if (!_globe || !_theme) return;
  paint();
}

function paint() {
  if (!_globe || !_theme) return;
  const cfg = cobeThemeConfig(_theme);
  // Rebuilt on every poll, not only on new data: heat is age, so the route
  // cools while the honeypot is quiet.
  _entities = buildCobeEntities(_home, _conn, cfg);
  const arrived = _arrived;
  _arrived = false;
  const animate = arrived && !reducedMotion();
  const key = cobeEntitiesKey(_home, _entities.markers);
  if (key !== _dataKey) {
    _dataKey = key;
    try {
      _globe.update({ markers: _entities.markers });
      // A marker id Cobe has not seen before gets a fresh anchor div appended
      // to the wrapper, which would land AFTER the overlay container and break
      // tree order for every anchor created this tick. Re-assert the ordering.
      keepOverlaysLastInCobeWrapper();
    } catch (_) {}
  }
  setRoute(_entities.route, animate);
  if (_frameOnPaint && _conn) {
    _frameOnPaint = false;
    frameRoute(true);
  }
  if (arrived && _conn) {
    if (animate) {
      const at = performance.now();
      _pings = [{ place: "source", at }, { place: "home", at: at + DRAW_MS }];
      if (!_animFrame) _animFrame = requestAnimationFrame(animFrame);
    }
    frameRoute(false);
  }
  drawRoute(_state.phi, _state.theta);
}

// One frame of an arrival: the route drawing itself in and the two dots
// pinging, the source's as it leaves and the honeypot's as it lands.
function animFrame() {
  _animFrame = 0;
  if (!_globe || !_entities) return;
  const now = performance.now();
  if (_drawAt) {
    const t = Math.min(1, (now - _drawAt) / DRAW_MS);
    // Ease in and out, like something travelling.
    _drawn = t < 0.5 ? 4 * t * t * t : 1 - (2 - 2 * t) ** 3 / 2;
    if (t >= 1) _drawAt = 0;
  }
  _pings = _pings.filter((p) => now - p.at < PING_MS);
  const grow = new Map();
  for (const p of _pings) {
    const t = (now - p.at) / PING_MS;
    // Starts at 2.6x the dot's size and eases back to it.
    if (t >= 0) grow.set(p.place, 1 + 1.6 * (1 - t) * (1 - t));
  }
  try {
    _globe.update({
      markers: _entities.markers.map((m) =>
        grow.has(m.place) ? { ...m, size: m.size * grow.get(m.place) } : m
      ),
    });
  } catch (_) {}
  drawRoute(_state.phi, _state.theta);
  // The last frame, with every ping expired, puts the dots back to size.
  if (_pings.length || _drawAt) _animFrame = requestAnimationFrame(animFrame);
}

// The route is drawn on a canvas of its own, laid over Cobe's (index.html
// styles .globe-route): above the sphere, under the place label, and out of
// the way of a drag.
function routeCanvas() {
  const w = wrap();
  if (!w) return null;
  let c = w.querySelector(":scope > canvas.globe-route");
  if (!c) {
    c = document.createElement("canvas");
    c.className = "globe-route";
    c.setAttribute("aria-hidden", "true");
    w.appendChild(c);
  }
  return c;
}

/** The route to draw, from buildCobeEntities; animate draws a new one in. */
function setRoute(route, animate) {
  if (!route) {
    _routePts = null;
    _routeKey = "";
    _drawAt = 0;
    _drawn = 0;
    return;
  }
  const key = `${route.from.lat},${route.from.lon}>${route.to.lat},${route.to.lon}`;
  if (key !== _routeKey) {
    _routeKey = key;
    _routePts = routePath(route.from, route.to, cobeThemeConfig(_theme).markerElevation);
    _drawn = 1;
  }
  _routeRGB = route.color.map((c) => Math.round(c * 255));
  if (animate) {
    _drawAt = performance.now();
    _drawn = 0;
  }
}

/**
 * Draw the route for the view: project its points with Cobe's own rotation,
 * drop the ones the sphere hides, and stroke a soft halo under a core line in
 * the route's heat colour. While it draws itself in, a dot marks how far the
 * connection has reached.
 */
function drawRoute(phi, theta) {
  const c = _routeCanvas;
  if (!c) return;
  const w = c.clientWidth;
  const h = c.clientHeight;
  if (!w || !h) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const bw = Math.round(w * dpr);
  const bh = Math.round(h * dpr);
  if (c.width !== bw || c.height !== bh) {
    c.width = bw;
    c.height = bh;
  }
  const ctx = c.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const pts = _routePts;
  if (!pts || !_routeRGB || _drawn <= 0) return;
  // Runs of visible points; the drawn part may end partway along a segment.
  const end = _drawn * (pts.length - 1);
  const runs = [];
  let run = null;
  for (let i = 0; i <= Math.ceil(end); i++) {
    let v = pts[i];
    if (i > end) {
      const a = pts[i - 1];
      const f = end - (i - 1);
      v = [a[0] + (v[0] - a[0]) * f, a[1] + (v[1] - a[1]) * f, a[2] + (v[2] - a[2]) * f];
    }
    const p = projectVec(v, phi, theta);
    if (!p.visible) {
      run = null;
      continue;
    }
    if (!run) {
      run = [];
      runs.push(run);
    }
    run.push([p.x * w, p.y * h]);
  }
  const cfg = cobeThemeConfig(_theme);
  const [r, g, b] = _routeRGB;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  const stroke = (width, alpha) => {
    ctx.lineWidth = width;
    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
    for (const line of runs) {
      if (line.length < 2) continue;
      ctx.beginPath();
      ctx.moveTo(line[0][0], line[0][1]);
      for (let k = 1; k < line.length; k++) ctx.lineTo(line[k][0], line[k][1]);
      ctx.stroke();
    }
  };
  stroke(cfg.routeHaloWidth, cfg.routeHaloAlpha);
  stroke(cfg.routeWidth, 1);
  // run is the last run only if the drawn end itself is visible.
  if (_drawAt && run) {
    const [hx, hy] = run[run.length - 1];
    ctx.fillStyle = `rgb(${r}, ${g}, ${b})`;
    ctx.beginPath();
    ctx.arc(hx, hy, cfg.routeWidth * 1.8, 0, Math.PI * 2);
    ctx.fill();
  }
}

/** Turn to show the whole live route. Refused while the operator steers. */
function frameRoute(cut) {
  if (!_ix || !_state || !_conn) return;
  if (_ix.isDragging() || _state.interacting) return;
  const [lat, lon] = routeView(_conn, _home);
  if (cut || reducedMotion()) {
    const [phi, theta] = viewAngles(lat, lon);
    _state.phi = _state.targetPhi = phi;
    _state.theta = _state.targetTheta = theta;
    return;
  }
  _ix.focus(lat, lon);
}

/**
 * Keep the overlay container as the LAST child of Cobe's own wrapper.
 *
 * Two separate CSS-anchor-positioning requirements force this, and missing
 * either one makes an anchored label silently collapse onto one spot instead
 * of tracking its marker:
 *
 *  1. The anchor must be a descendant of the anchored element's containing
 *     block. Cobe appends its `anchor-name: --cobe-<id>` divs into the wrapper
 *     it inserts around the canvas, so the container has to live in there too
 *     (and must not be positioned itself — see #cobe-overlays in index.html).
 *  2. The anchor must PRECEDE the anchored element in tree order. Cobe creates
 *     an anchor div the first time it sees a marker id and appends it to the
 *     wrapper, so anchors keep arriving after the container.
 *
 * appendChild on an existing child moves it to the end, so calling this after
 * each marker update re-establishes the ordering.
 */
function keepOverlaysLastInCobeWrapper() {
  const c = canvas();
  const ov = overlays();
  const cobeWrapper = c && c.parentElement;
  if (!cobeWrapper || !ov) return;
  if (cobeWrapper.lastElementChild === ov) return;
  cobeWrapper.appendChild(ov);
}

function setOverlayPlaces(places, htmlNodes) {
  const ov = overlays();
  if (!ov) return;
  keepOverlaysLastInCobeWrapper();
  ov.innerHTML = "";
  (htmlNodes || []).forEach((el) => ov.appendChild(el));
  if (_ix && typeof _ix.setPlaces === "function") {
    _ix.setPlaces(places || []);
  }
}

const ShardCobe = {
  ensure,
  destroy,
  updateData,
  setOverlayPlaces,
  isActive: () => !!_globe,
  theme: () => _theme,
};

window.ShardCobe = ShardCobe;
export default ShardCobe;
