/**
 * Lazy-loaded Cobe engine for the activity globe, shared by Obsidian and Kiln.
 *
 * The globe draws one route: from the newest connection's source into the
 * honeypot. It never spins on its own. A new connection replaces the route:
 * the new one lifts off the surface, its source dot pings and then the
 * honeypot's as the connection lands, and the globe turns to show the whole
 * route, so motion on the page always means "someone new connected". Under
 * prefers-reduced-motion the route simply appears and the turn is a cut.
 */
import createGlobe from "/vendor/cobe.esm.js";
import {
  bindGlobeInteraction,
  startGlobeLoop,
  cobeThemeConfig,
  cobeEntitiesKey,
  buildCobeEntities,
  routeView,
  viewAngles,
} from "/cobe-globe.js?v=19";

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
let _riseAt = 0;
let _settle = false;
let _animFrame = 0;

// The same source back after this long is a new connection, not more of one.
const QUIET_MS = 5 * 60 * 1000;
const PING_MS = 900;
// The honeypot's dot pings this long after the source's: the connection lands.
const LAND_DELAY_MS = 450;
const RISE_MS = 700;
// A new route starts this fraction of its height off the surface.
const RISE_FROM = 0.1;

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
  _riseAt = 0;
  _settle = false;
  _arrived = false;
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
    arcColor: cfg.arcColor,
    arcWidth: cfg.arcWidth,
    arcHeight: cfg.arcHeight,
    markers: _entities.markers,
    arcs: _entities.arcs,
  });
  _dataKey = cobeEntitiesKey(_home, _entities.markers, _entities.arcs);
  _theme = theme;
  _stop = startGlobeLoop(_globe, _ix);
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
  const key = cobeEntitiesKey(_home, _entities.markers, _entities.arcs);
  try {
    // Cobe bakes the height into an arc when the arc is set, so the new
    // route's starting height goes in first.
    if (animate) _globe.update({ arcHeight: cfg.arcHeight * RISE_FROM });
    if (animate || key !== _dataKey) {
      _dataKey = key;
      _globe.update({ markers: _entities.markers, arcs: _entities.arcs });
      // A marker id Cobe has not seen before gets a fresh anchor div appended
      // to the wrapper, which would land AFTER the overlay container and break
      // tree order for every anchor created this tick. Re-assert the ordering.
      keepOverlaysLastInCobeWrapper();
    }
  } catch (_) {}
  if (_frameOnPaint && _conn) {
    _frameOnPaint = false;
    frameRoute(true);
  }
  if (arrived && _conn) {
    if (animate) {
      const at = performance.now();
      _riseAt = at;
      _pings = [{ place: "source", at }, { place: "home", at: at + LAND_DELAY_MS }];
      if (!_animFrame) _animFrame = requestAnimationFrame(animFrame);
    }
    frameRoute(false);
  }
}

// One frame of an arrival: the route rising to its height and the two dots
// pinging. The frame after the rise ends sends the route once more, because
// Cobe applies a new height to the arcs it is given in the NEXT update.
function animFrame() {
  _animFrame = 0;
  if (!_globe || !_entities) return;
  const cfg = cobeThemeConfig(_theme);
  const now = performance.now();
  _pings = _pings.filter((p) => now - p.at < PING_MS);
  const grow = new Map();
  for (const p of _pings) {
    const t = (now - p.at) / PING_MS;
    // Starts at 2.6x the dot's size and eases back to it.
    if (t >= 0) grow.set(p.place, 1 + 1.6 * (1 - t) * (1 - t));
  }
  const patch = {
    markers: _entities.markers.map((m) =>
      grow.has(m.place) ? { ...m, size: m.size * grow.get(m.place) } : m
    ),
  };
  if (_riseAt) {
    const t = Math.min(1, (now - _riseAt) / RISE_MS);
    const ease = 1 - (1 - t) ** 3;
    patch.arcHeight = cfg.arcHeight * (RISE_FROM + (1 - RISE_FROM) * ease);
    patch.arcs = _entities.arcs;
    if (t >= 1) {
      _riseAt = 0;
      _settle = true;
    }
  } else if (_settle) {
    patch.arcs = _entities.arcs;
    _settle = false;
  }
  try {
    _globe.update(patch);
  } catch (_) {}
  // The last frame, with every ping expired, puts the dots back to size.
  if (_pings.length || _riseAt || _settle) _animFrame = requestAnimationFrame(animFrame);
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
