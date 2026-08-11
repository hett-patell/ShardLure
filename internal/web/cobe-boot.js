/**
 * Lazy-loaded Cobe engine — the only globe engine, shared by all themes
 * (Signal / Meridian / Sprite).
 */
import createGlobe from "/vendor/cobe.esm.js";
import {
  bindGlobeInteraction,
  startGlobeLoop,
  cobeThemeConfig,
  buildCobeEntities,
  globeActorOrder,
  locationToAngles,
} from "/cobe-globe.js?v=5";

function cobeEntitiesKey(home, markers, arcs) {
  const h = `${Number(home.lat).toFixed(3)},${Number(home.lon).toFixed(3)}`;
  const mk = (markers || [])
    .map(
      (m) =>
        `${m.id || ""}:${m.location[0].toFixed(2)},${m.location[1].toFixed(2)}:${(m.size || 0).toFixed(3)}`
    )
    .join("|");
  const ar = (arcs || [])
    .map(
      (a) =>
        `${a.id || ""}:${a.from[0].toFixed(2)},${a.from[1].toFixed(2)}`
    )
    .join("|");
  return `${h}#${mk}#${ar}`;
}

let _globe = null;
let _stop = null;
let _ix = null;
let _state = null;
let _theme = null;
let _mode = "dark";
let _home = { lat: 19.076, lon: 72.8777 };
let _actors = [];

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
  _ix = null;
  _state = null;
  _theme = null;
  const ov = overlays();
  if (ov) ov.innerHTML = "";
  const st = stage();
  if (st) {
    st.hidden = true;
    st.classList.remove("on");
  }
}

async function ensure(theme, mode) {
  _mode = mode || "dark";
  // Honor prefers-reduced-motion: skip globe creation entirely so no
  // continuous rAF loop spins when the user opted out of motion.
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    destroy();
    return null;
  }
  if (theme !== "meridian" && theme !== "sprite" && theme !== "signal") {
    destroy();
    return null;
  }
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
  w.style.width = "";
  w.style.height = "";

  const cfg = cobeThemeConfig(theme, _mode);
  _state = {
    phi: 2.4,
    theta: 0.22,
    targetPhi: 2.4,
    targetTheta: 0.22,
    scale: 1,
    targetScale: 1,
    autoRotate: true,
    interacting: false,
  };
  const places = [{ id: "home", label: "Home", lat: _home.lat, lon: _home.lon }];
  // markerElevation is passed through so the fallback projection (browsers
  // without CSS anchor positioning) puts overlays on the same sphere as the
  // WebGL markers rather than a hardcoded radius.
  _ix = bindGlobeInteraction(c, _state, {
    wrap: w,
    places,
    markerElevation: cfg.markerElevation,
  });
  const size = () => Math.min(w.clientWidth || 480, w.clientHeight || 480) * 2;
  const { markers, arcs } = buildCobeEntities(_home, _actors, cfg.colors, entityOpts(cfg));
  _globe = createGlobe(c, {
    devicePixelRatio: Math.min(window.devicePixelRatio || 1, 1.5),
    width: size(),
    height: size(),
    phi: _state.phi,
    theta: _state.theta,
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
    markers,
    arcs,
  });
  _theme = theme;
  _stop = startGlobeLoop(_globe, _ix);
  try {
    const [p, th] = locationToAngles(_home.lat, _home.lon);
    _state.targetPhi = p;
    _state.targetTheta = th;
  } catch (_) {}
  return _globe;
}

let _dataKey = "";
let _dataTimer = 0;
function updateData(home, actors) {
  if (home) _home = home;
  if (actors) _actors = actors;
  if (!_globe || !_theme) return;
  clearTimeout(_dataTimer);
  _dataTimer = setTimeout(() => {
    if (!_globe || !_theme) return;
    const cfg = cobeThemeConfig(_theme, _mode);
    const { markers, arcs } = buildCobeEntities(_home, _actors, cfg.colors, entityOpts(cfg));
    const key = cobeEntitiesKey(_home, markers, arcs);
    if (key === _dataKey) return;
    _dataKey = key;
    try {
      _globe.update({ markers, arcs });
      // A marker id Cobe has not seen before gets a fresh anchor div appended
      // to the wrapper, which would land AFTER the overlay container and break
      // tree order for every anchor created this tick. Re-assert the ordering.
      keepOverlaysLastInCobeWrapper();
    } catch (_) {}
  }, 200);
}

/**
 * Keep the overlay container as the LAST child of Cobe's own wrapper.
 *
 * Two separate CSS-anchor-positioning requirements force this, and missing
 * either one makes every anchored sticker silently collapse onto one spot
 * instead of tracking its marker:
 *
 *  1. The anchor must be a descendant of the anchored element's containing
 *     block. Cobe appends its `anchor-name: --cobe-<id>` divs into the wrapper
 *     it inserts around the canvas, so the container has to live in there too
 *     (and must not be positioned itself — see #cobe-overlays in themes.css).
 *  2. The anchor must PRECEDE the anchored element in tree order. Cobe creates
 *     an anchor div the first time it sees a marker id and appends it to the
 *     wrapper, so anchors keep arriving after the container. Observed exactly
 *     this: `home` (anchor created first) resolved while `a0..a4` did not.
 *
 * appendChild on an existing child moves it to the end, so calling this after
 * each marker update re-establishes the ordering. Data refreshes are ~30s
 * apart, so the DOM move is nowhere near a hot path.
 */
function keepOverlaysLastInCobeWrapper() {
  const c = canvas();
  const ov = overlays();
  const cobeWrapper = c && c.parentElement;
  if (!cobeWrapper || !ov) return;
  if (cobeWrapper.lastElementChild === ov) return;
  cobeWrapper.appendChild(ov);
}

/** Density + marker-scale knobs a theme may override (see cobeThemeConfig). */
function entityOpts(cfg) {
  return {
    maxArcs: cfg.maxArcs,
    maxMarkers: cfg.maxMarkers,
    markerSize: cfg.markerSize,
  };
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
  // Marker-id ordering, so overlay builders can anchor to `--cobe-a<i>` and be
  // certain index i is the same actor the marker represents.
  //
  // Takes NO argument on purpose. It previously accepted a list, and callers
  // passed a different one to what markers were built from: the dashboard feeds
  // Cobe `mergeActorsForGlobe(actors, topActors)` but kept the unmerged
  // `actors` for overlays. Both then ran the same geo-dedupe over different
  // inputs, so index i resolved to a different actor on each side and flags
  // rendered over the wrong country (Brazil beside India). Reading `_actors` —
  // the exact list buildCobeEntities consumed — makes that divergence
  // impossible to reintroduce. Returns null before the first data arrives so
  // callers can skip rather than guess an ordering.
  actorOrder: () => {
    if (!_actors || !_actors.length) return null;
    const cfg = cobeThemeConfig(_theme, _mode);
    return globeActorOrder(_actors, cfg.maxMarkers);
  },
};

window.ShardCobe = ShardCobe;
export default ShardCobe;
