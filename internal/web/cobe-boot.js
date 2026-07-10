/**
 * Lazy-loaded Cobe engine for Meridian / Sprite themes.
 * Imported only when a light theme is selected — not on Dragon (globe.gl).
 */
import createGlobe from "https://esm.sh/cobe@2.0.1";
import {
  bindGlobeInteraction,
  startGlobeLoop,
  cobeThemeConfig,
  buildCobeEntities,
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

async function ensure(theme) {
  if (theme !== "meridian" && theme !== "sprite") {
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

  const cfg = cobeThemeConfig(theme);
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
  _ix = bindGlobeInteraction(c, _state, { wrap: w, places });
  const size = () => Math.min(w.clientWidth || 480, w.clientHeight || 480) * 2;
  const { markers, arcs } = buildCobeEntities(_home, _actors, cfg.colors);
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
    const cfg = cobeThemeConfig(_theme);
    const { markers, arcs } = buildCobeEntities(_home, _actors, cfg.colors);
    const key = cobeEntitiesKey(_home, markers, arcs);
    if (key === _dataKey) return;
    _dataKey = key;
    try {
      _globe.update({ markers, arcs });
    } catch (_) {}
  }, 200);
}

function setOverlayPlaces(places, htmlNodes) {
  const ov = overlays();
  if (!ov) return;
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
