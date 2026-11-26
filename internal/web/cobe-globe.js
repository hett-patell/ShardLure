/**
 * Interactive Cobe helpers for the activity globe (Obsidian and Kiln).
 * Cobe 2.x: no onRender — rAF + update.
 *
 * The globe draws the live connection: one route from the newest source into
 * the honeypot, coloured on the same heat scale as the feed's dots. Cobe draws
 * the sphere and the two dots; the route itself is a lifted great circle drawn
 * in 2D over it (routePath, projectVec), because Cobe's own arcs cut through
 * the globe on long routes.
 */

export function locationToAngles(lat, lon) {
  return [
    Math.PI - ((lon * Math.PI) / 180 - Math.PI / 2),
    (lat * Math.PI) / 180,
  ];
}

/** View angles that centre a point, with the pitch kept off the poles. */
export function viewAngles(lat, lon) {
  const [phi, theta] = locationToAngles(lat, lon);
  return [phi, clamp(theta, -0.8, 0.9)];
}

export function latLonToVec3(lat, lon) {
  const r = (lat * Math.PI) / 180;
  const a = (lon * Math.PI) / 180 - Math.PI;
  const o = Math.cos(r);
  return [-o * Math.cos(a), Math.sin(r), o * Math.sin(a)];
}

/** Cobe's sphere radius in clip space; markers sit markerElevation above it. */
export const SPHERE_RADIUS = 0.8;

/**
 * Project a point of Cobe's scene for the view, with Cobe's own rotation. x and
 * y are fractions of the canvas; a point is hidden when it is behind the
 * sphere (z < 0) and its projection falls inside the sphere's disc.
 */
export function projectVec(v, phi, theta) {
  const [x, y, z] = v;
  const ct = Math.cos(theta);
  const st = Math.sin(theta);
  const cp = Math.cos(phi);
  const sp = Math.sin(phi);

  const cx = cp * x + sp * z;
  const cy = sp * st * x + ct * y - cp * st * z;
  const cz = -sp * ct * x + st * y + cp * ct * z;

  const front = cz >= 0;
  const outsideDisk = cx * cx + cy * cy >= SPHERE_RADIUS * SPHERE_RADIUS;
  return {
    x: (cx + 1) / 2,
    y: (-cy + 1) / 2,
    visible: front || outsideDisk,
    front,
  };
}

export function projectLatLon(lat, lon, phi, theta, elevation = 0.02) {
  const r = SPHERE_RADIUS + elevation;
  const [x, y, z] = latLonToVec3(lat, lon);
  return projectVec([x * r, y * r, z * r], phi, theta);
}

function vecToLatLon(v) {
  const len = Math.hypot(v[0], v[1], v[2]);
  const lat = (Math.asin(v[1] / len) * 180) / Math.PI;
  let lon = ((Math.atan2(v[2], -v[0]) + Math.PI) * 180) / Math.PI;
  if (lon > 180) lon -= 360;
  return [lat, lon];
}

/**
 * Where to centre the globe to show a whole route as an arc, as [lat, lon]:
 * the route's midpoint, tipped `tilt` radians sideways off it, toward the
 * equator. Seen square-on, the arc's height points at the viewer and the route
 * reads as a flat line; from the side it curves. Both ends stay on the visible
 * side for any route shorter than about 160°.
 */
export function routeView(a, b, tilt = 0.35) {
  const va = latLonToVec3(a.lat, a.lon);
  const vb = latLonToVec3(b.lat, b.lon);
  const m = [va[0] + vb[0], va[1] + vb[1], va[2] + vb[2]];
  const n = [
    va[1] * vb[2] - va[2] * vb[1],
    va[2] * vb[0] - va[0] * vb[2],
    va[0] * vb[1] - va[1] * vb[0],
  ];
  const ml = Math.hypot(m[0], m[1], m[2]);
  const nl = Math.hypot(n[0], n[1], n[2]);
  // Antipodes have no midpoint and a single point has no side: centre the
  // source itself.
  if (ml < 1e-3 || nl < 1e-6) return [a.lat, a.lon];
  const side = (s) =>
    m.map((c, i) => (c / ml) * Math.cos(tilt) + s * (n[i] / nl) * Math.sin(tilt));
  const one = side(1);
  const other = side(-1);
  return vecToLatLon(Math.abs(one[1]) < Math.abs(other[1]) ? one : other);
}

// How far a route rises off the sphere at its middle: in proportion to its
// length, so a short hop stays a low arch, and capped so the top of the
// longest one still fits the canvas when it passes over the rim.
const ROUTE_LIFT_PER_LENGTH = 0.22;
const ROUTE_LIFT_MAX = 0.16;

/**
 * The route from a to b as points of Cobe's scene: the great circle between
 * them, from marker height at either end up to a lift at the middle.
 *
 * Cobe's own arcs are quadratic curves through a control point above the
 * midpoint, and on a long route their middle sinks inside the sphere: San
 * Diego to Mumbai is 127°, and its apex fell at 0.72 under a 0.8 sphere, so
 * the route sliced through the globe. Every point here stays above it.
 */
export function routePath(a, b, elevation, steps = 96) {
  const va = latLonToVec3(a.lat, a.lon);
  const vb = latLonToVec3(b.lat, b.lon);
  const dot = clamp(va[0] * vb[0] + va[1] * vb[1] + va[2] * vb[2], -1, 1);
  const angle = Math.acos(dot);
  // The direction from a toward b within the route's plane. Antipodes have
  // no single great circle; any will do, so go over a pole.
  let w = [vb[0] - dot * va[0], vb[1] - dot * va[1], vb[2] - dot * va[2]];
  if (Math.hypot(w[0], w[1], w[2]) < 1e-6) {
    w = Math.abs(va[1]) < 0.9 ? [0, 1, 0] : [1, 0, 0];
    const d = w[0] * va[0] + w[1] * va[1] + w[2] * va[2];
    w = [w[0] - d * va[0], w[1] - d * va[1], w[2] - d * va[2]];
  }
  const wl = Math.hypot(w[0], w[1], w[2]);
  w = w.map((c) => c / wl);
  const base = SPHERE_RADIUS + elevation;
  const lift = Math.min(ROUTE_LIFT_MAX, ROUTE_LIFT_PER_LENGTH * base * angle);
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const c = Math.cos(angle * t);
    const s = Math.sin(angle * t);
    const r = base + lift * Math.sin(Math.PI * t);
    points.push([
      (va[0] * c + w[0] * s) * r,
      (va[1] * c + w[1] * s) * r,
      (va[2] * c + w[2] * s) * r,
    ]);
  }
  return points;
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function shortestAngleDelta(from, to) {
  let d = to - from;
  while (d > Math.PI) d -= Math.PI * 2;
  while (d < -Math.PI) d += Math.PI * 2;
  return d;
}

/**
 * True when the browser can position elements against Cobe's published anchors.
 * Cobe 2.x emits a 1px anchor div per marker/arc carrying
 * `anchor-name: --cobe-<id>` (and `--cobe-visible-<id>` for front/back), placed
 * with its own projection. Using them means zero projection math on our side
 * and exact alignment by construction. Chromium-only today, hence the fallback.
 */
export const supportsCobeAnchors = () =>
  typeof CSS !== "undefined" &&
  typeof CSS.supports === "function" &&
  CSS.supports("position-anchor", "--x") &&
  CSS.supports("anchor-name", "--x");

/** Cobe's anchor-name for a marker id, or "" when the element isn't anchorable. */
function anchorNameFor(el) {
  const marker = el.getAttribute("data-marker");
  return marker ? `--cobe-${marker}` : "";
}

/**
 * Pointer handling for the activity globe: drag to look around (with a little
 * inertia), double-click to return to the honeypot. The page keeps its wheel
 * and keys, and the globe never turns on its own: focus() is how new activity
 * turns it.
 */
export function bindGlobeInteraction(canvas, state, opts = {}) {
  const wrap = opts.wrap || canvas.parentElement;
  const places = opts.places || [];
  // Theme markerElevation, so the fallback projection lands on the same sphere
  // as the WebGL markers.
  const markerElevation = Number.isFinite(opts.markerElevation)
    ? opts.markerElevation
    : 0.03;
  const surface = wrap || canvas;
  const pitch = (theta) => clamp(theta, -0.85, 0.95);

  let dragging = false;
  let moved = false;
  let lastX = 0;
  let lastY = 0;
  let pointerPhi = 0;
  let pointerTheta = 0;
  let velPhi = 0;
  let velTheta = 0;
  let steerTimer = 0;
  let lastTickAt = performance.now();

  state.phi ??= 2.4;
  state.theta ??= 0.2;
  state.targetPhi ??= state.phi;
  state.targetTheta ??= state.theta;
  state.interacting ??= false;

  surface.style.touchAction = "none";
  surface.style.cursor = "grab";
  surface.style.userSelect = "none";
  canvas.style.touchAction = "none";
  canvas.style.cursor = "grab";
  canvas.style.position = canvas.style.position || "relative";
  canvas.style.zIndex = "2";

  // While the operator steers, and for a moment after, new activity does not
  // take the globe away from them.
  const holdSteer = (ms) => {
    state.interacting = true;
    clearTimeout(steerTimer);
    steerTimer = setTimeout(() => {
      state.interacting = false;
    }, ms);
  };

  const focus = (lat, lon) => {
    const [p, t] = viewAngles(lat, lon);
    state.targetPhi = state.phi + shortestAngleDelta(state.phi, p);
    state.targetTheta = t;
    velPhi = 0;
    velTheta = 0;
  };

  const beginDrag = (clientX, clientY) => {
    dragging = true;
    moved = false;
    lastX = clientX;
    lastY = clientY;
    pointerPhi = state.phi;
    pointerTheta = state.theta;
    velPhi = 0;
    velTheta = 0;
    clearTimeout(steerTimer);
    state.interacting = true;
    state.targetPhi = state.phi;
    state.targetTheta = state.theta;
    surface.style.cursor = "grabbing";
    canvas.style.cursor = "grabbing";
  };

  const onMove = (clientX, clientY) => {
    if (!dragging) return;
    const dx = clientX - lastX;
    const dy = clientY - lastY;
    if (Math.abs(dx) + Math.abs(dy) > 2) moved = true;

    const nextPhi = pointerPhi + dx * 0.008;
    const nextTheta = pitch(pointerTheta + dy * 0.005);

    velPhi = nextPhi - state.phi;
    velTheta = nextTheta - state.theta;

    state.phi = nextPhi;
    state.theta = nextTheta;
    state.targetPhi = nextPhi;
    state.targetTheta = nextTheta;
  };

  const endDrag = () => {
    if (!dragging) return;
    dragging = false;
    surface.style.cursor = "grab";
    canvas.style.cursor = "grab";
    velPhi *= 0.92;
    velTheta *= 0.92;
    holdSteer(moved ? 3200 : 1800);
  };

  const skipSel = "button, a, input, .globe-overlay, [data-place]";

  const onPointerDown = (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    if (e.target.closest && e.target.closest(skipSel)) return;
    beginDrag(e.clientX, e.clientY);
    try {
      surface.setPointerCapture(e.pointerId);
    } catch (_) {}
    e.preventDefault();
  };
  surface.addEventListener("pointerdown", onPointerDown, { passive: false });

  const onPointerMove = (e) => {
    if (!dragging) return;
    onMove(e.clientX, e.clientY);
  };
  window.addEventListener("pointermove", onPointerMove);
  window.addEventListener("pointerup", endDrag);
  window.addEventListener("pointercancel", endDrag);

  const onDblClick = (e) => {
    e.preventDefault();
    const home = places.find((p) => p.id === "home") || places[0];
    if (home) {
      focus(home.lat, home.lon);
      holdSteer(3200);
    }
  };
  canvas.addEventListener("dblclick", onDblClick);

  let labelEls = [];
  let placeById = {};

  // Labels sit centred just above the point they name.
  const LABEL_TRANSFORM = "translate(-50%, calc(-100% - 10px))";

  const rebindLabels = (nextPlaces) => {
    placeById = Object.fromEntries((nextPlaces || []).map((p) => [p.id, p]));
    labelEls = wrap ? [...wrap.querySelectorAll(".globe-overlay, [data-place]")] : [];
    labelEls.forEach((el) => {
      el.style.pointerEvents = "none";
      el.style.position = "absolute";
      el.style.left = "0";
      el.style.top = "0";
      el.style.right = "auto";
      el.style.bottom = "auto";
      el.style.zIndex = "3";
      el.style.margin = "0";
      el.style.translate = "none";
      el.style.transform = LABEL_TRANSFORM;
      el.style.transition = "opacity .2s ease";
      el.style.opacity = "0";

      // Preferred path: hand positioning to Cobe's own anchors. `left/top` are
      // cleared so the anchor's inset rules win, and opacity is driven by
      // --cobe-visible-<id>. That variable is deliberately a NON-numeric token
      // ("N"), so when the marker is front-facing `opacity: N` is invalid at
      // computed-value time and opacity falls back to its initial 1; when the
      // marker rotates out of view Cobe deletes the variable and the var()
      // fallback of 0 hides the element. Odd, but it is Cobe's own contract.
      const anchor = anchorNameFor(el);
      el._cobeAnchored = false;
      if (anchor && supportsCobeAnchors()) {
        el._cobeAnchored = true;
        el.style.positionAnchor = anchor;
        el.style.left = "anchor(center)";
        el.style.top = "auto";
        el.style.bottom = "anchor(top)";
        // anchor(center) aligns the element's LEFT EDGE with the marker centre,
        // so it is pulled back half its own width, and lifted clear of the dot.
        // The anchor insets already sit it above the marker, so the projected
        // path's -100% lift must not apply as well.
        el.style.translate = "-50% -10px";
        el.style.transform = "none";
        el.style.opacity = `var(--cobe-visible-${el.getAttribute("data-marker")}, 0)`;
      } else {
        el.style.positionAnchor = "auto";
        el.style.bottom = "auto";
      }
    });
  };

  rebindLabels(places);

  const syncLabels = (phi, theta) => {
    for (const el of labelEls) {
      const place = placeById[el.getAttribute("data-place")];
      if (!place) {
        el.style.opacity = "0";
        continue;
      }
      // Elements anchored to a Cobe marker are positioned by the LIBRARY's own
      // projection (see anchorNameFor), so skip our JS projection entirely —
      // that is what makes them pixel-exact instead of ~2-6px adrift.
      if (el._cobeAnchored) continue;
      // Elevation MUST match the theme's markerElevation, otherwise the label
      // is projected onto a different sphere than the marker it annotates and
      // drifts outward toward the limb.
      const p = projectLatLon(place.lat, place.lon, phi, theta, markerElevation);
      el.style.left = `${(p.x * 100).toFixed(2)}%`;
      el.style.top = `${(p.y * 100).toFixed(2)}%`;
      el.style.opacity = p.front ? "1" : "0";
    }
  };

  const baseSize = wrap
    ? Math.min(wrap.clientWidth, wrap.clientHeight) || 480
    : 480;

  return {
    isDragging: () => dragging,
    focus,
    wrap,
    baseSize,
    destroy() {
      surface.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", endDrag);
      window.removeEventListener("pointercancel", endDrag);
      canvas.removeEventListener("dblclick", onDblClick);
      clearTimeout(steerTimer);
    },
    setPlaces(next) {
      rebindLabels(next);
    },
    tick() {
      const now = performance.now();
      const elapsed = Math.min(50, now - lastTickAt);
      lastTickAt = now;
      // Time-based easing, so a turn takes as long on a throttled idle frame as
      // on a busy one.
      const easing = 1 - Math.exp(-elapsed / 240);
      if (!dragging) {
        if (Math.abs(velPhi) > 0.0002 || Math.abs(velTheta) > 0.0002) {
          state.phi += velPhi;
          state.theta = pitch(state.theta + velTheta);
          state.targetPhi = state.phi;
          state.targetTheta = state.theta;
          velPhi *= 0.94;
          velTheta *= 0.92;
        } else {
          state.phi += shortestAngleDelta(state.phi, state.targetPhi) * easing;
          state.theta += (state.targetTheta - state.theta) * easing;
        }
      }
      syncLabels(state.phi, state.theta);
      return { phi: state.phi, theta: state.theta };
    },
  };
}

/**
 * Drive the globe: ease the view, repaint only when it changed, and call
 * onFrame(view) after each repaint so anything drawn over the sphere moves
 * with it in the same frame.
 */
export function startGlobeLoop(globe, ix, onFrame) {
  let raf = 0;
  let alive = true;
  const wrap = ix.wrap;
  let base = ix.baseSize || 480;
  // The stage sizes the sphere in CSS; follow it so the canvas backing tracks
  // a resize instead of keeping its first measurement.
  const resize = wrap && new ResizeObserver(([entry]) => {
    base = entry.contentRect.width || base;
  });
  if (resize) resize.observe(wrap);
  // Cap the backing store: full retina at globe size reallocates WebGL buffers
  // and hangs weak GPUs.
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  const backing = (cssPx) => Math.max(2, Math.round(Math.min(1400, cssPx * dpr)));

  let lastW = 0;
  let lastPhi = NaN;
  let lastTheta = NaN;
  let lastPaint = 0;
  // Cobe decodes its land texture asynchronously and uploads it on load
  // WITHOUT drawing, and it only draws inside update(). A globe that is not
  // turning would keep its first frame, drawn before the texture: an even
  // speckle with no continents (Chromium decodes late enough to show it).
  // Paint at the idle cadence for a moment after start instead.
  const warmUntil = performance.now() + 2000;

  const onVis = () => {
    if (!document.hidden && alive) schedule(0);
  };
  document.addEventListener("visibilitychange", onVis);

  const schedule = (ms) => {
    if (!alive || raf) return;
    if (ms > 0) {
      raf = setTimeout(() => {
        raf = 0;
        frame();
      }, ms);
    } else {
      raf = requestAnimationFrame(() => {
        raf = 0;
        frame();
      });
    }
  };

  const frame = () => {
    if (!alive) return;
    if (document.hidden) return;

    const view = ix.tick();
    const w = backing(base);
    const now = performance.now();

    const sizeChanged = w !== lastW;
    const angleChanged =
      Math.abs(view.phi - lastPhi) > 0.0002 ||
      Math.abs(view.theta - lastTheta) > 0.0002;
    const interacting = ix.isDragging();

    // Throttle paints: 60fps while dragging, ~30fps while turning, ~12fps idle.
    const minGap = interacting ? 0 : angleChanged ? 32 : 80;
    const due = now - lastPaint >= minGap;

    if (due && (sizeChanged || angleChanged || interacting || now < warmUntil)) {
      const patch = { phi: view.phi, theta: view.theta };
      if (sizeChanged) {
        patch.width = w;
        patch.height = w;
        lastW = w;
      }
      globe.update(patch);
      lastPhi = view.phi;
      lastTheta = view.theta;
      lastPaint = now;
      if (onFrame) onFrame(view);
    }

    schedule(interacting ? 0 : minGap || 32);
  };

  schedule(0);
  return () => {
    alive = false;
    if (resize) resize.disconnect();
    document.removeEventListener("visibilitychange", onVis);
    if (raf) {
      cancelAnimationFrame(raf);
      clearTimeout(raf);
      raf = 0;
    }
  };
}

/* Globe materials. The sphere and the honeypot are neutral; the live route and
   its source dot are coloured by heat, on the feed's scale: a connection in
   the last minute is the hottest thing on the page, one quiet for an hour has
   cooled to grey. Triples are 0..1 RGB, as Cobe takes them.
   heat[2..4] are --heat-3…5 from themes.css. The two cool steps are picked for
   the globe rather than copied from the panel tokens (--heat-1 is an "off"
   dot and would vanish into the sphere), so each ramp gains contrast against
   its own sphere at every step and the coolest route still reads. */
const GLOBE_SHARED = {
  mapSamples: 20000,
  markerElevation: 0.02,
  homeMarkerSize: 0.024,
  // Source dot size by heat level 1..5.
  sourceSize: [0.014, 0.016, 0.019, 0.022, 0.026],
  // The route over the sphere, in CSS pixels: a core line, and a soft halo
  // under it in the same colour.
  routeWidth: 1.75,
  routeHaloWidth: 6,
  routeHaloAlpha: 0.22,
};

const GLOBE_THEMES = {
  obsidian: {
    dark: 1,
    diffuse: 1.25,
    mapBrightness: 2.4,
    mapBaseBrightness: 0.012,
    baseColor: [0.24, 0.30, 0.29],
    glowColor: [0.09, 0.13, 0.12],
    markerColor: [0.58, 0.64, 0.62],
    home: [0.90, 0.93, 0.92],
    heat: [
      [0.30, 0.36, 0.35],
      [0.55, 0.36, 0.27],
      [0.72, 0.34, 0.17],
      [0.95, 0.52, 0.25],
      [1.00, 0.76, 0.50],
    ],
  },
  kiln: {
    dark: 0,
    diffuse: 1.4,
    // Light mode darkens a dot by its brightness and clips past 1, so 5.2 gave
    // solid black land that outweighed the route; this leaves a mid-tone
    // speckle and keeps the oxblood route the darkest stroke on the sphere.
    mapBrightness: 0.6,
    mapBaseBrightness: 0.05,
    baseColor: [0.88, 0.92, 0.90],
    glowColor: [0.84, 0.90, 0.87],
    markerColor: [0.30, 0.36, 0.34],
    home: [0.11, 0.13, 0.13],
    heat: [
      [0.58, 0.64, 0.62],
      [0.80, 0.52, 0.40],
      [0.77, 0.38, 0.18],
      [0.64, 0.25, 0.11],
      [0.44, 0.14, 0.06],
    ],
  },
};

/** Cobe createGlobe options, marker colours and route styling for a theme. */
export function cobeThemeConfig(theme) {
  return { ...GLOBE_SHARED, ...(GLOBE_THEMES[theme] || GLOBE_THEMES.obsidian) };
}

/** Recency as heat, on the feed's scale (heatForAge in index.html): 5 under a minute, 1 from an hour. */
export function globeHeat(ageSec) {
  if (!Number.isFinite(ageSec)) return 1;
  return ageSec < 60 ? 5 : ageSec < 300 ? 4 : ageSec < 900 ? 3 : ageSec < 3600 ? 2 : 1;
}

// Within ~10 km: a route that short is a dot, not a line.
function samePlace(a, b) {
  return Math.round(a.lat * 10) === Math.round(b.lat * 10) &&
    Math.round(a.lon * 10) === Math.round(b.lon * 10);
}

/** Stable key so globe.update runs only when the markers actually change. */
export function cobeEntitiesKey(home, markers) {
  const h = `${Number(home.lat).toFixed(3)},${Number(home.lon).toFixed(3)}`;
  const mk = (markers || [])
    .map(
      (m) =>
        `${m.id}:${m.location[0].toFixed(2)},${m.location[1].toFixed(2)}:${m.size.toFixed(3)}:${m.color}`
    )
    .join("|");
  return `${h}#${mk}`;
}

/**
 * Markers and the route for the live connection, { lat, lon, ts } with ts in
 * epoch ms, or null while there is none to place. Its dot is
 * "latest-connection", the id the label anchors to; a source in the
 * honeypot's own city gets the dot but no route. The route is { from, to,
 * color, level }, drawn by the caller along routePath.
 */
export function buildCobeEntities(home, conn, cfg, now = Date.now()) {
  const markers = [
    {
      id: "home",
      place: "home",
      location: [home.lat, home.lon],
      size: cfg.homeMarkerSize,
      color: cfg.home,
    },
  ];
  let route = null;
  if (conn && Number.isFinite(conn.lat) && Number.isFinite(conn.lon)) {
    const level = globeHeat((now - conn.ts) / 1000);
    const color = cfg.heat[level - 1];
    markers.push({
      id: "latest-connection",
      place: "source",
      location: [conn.lat, conn.lon],
      size: cfg.sourceSize[level - 1],
      color,
    });
    if (!samePlace(conn, home)) {
      route = {
        from: { lat: conn.lat, lon: conn.lon },
        to: { lat: home.lat, lon: home.lon },
        color,
        level,
      };
    }
  }
  return { markers, route };
}
