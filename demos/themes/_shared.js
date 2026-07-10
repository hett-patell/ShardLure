// Shared mock telemetry + interactive Cobe helpers for theme studies.
export const HOME = [19.076, 72.8777];

export const SUMMARY = {
  events: 118655,
  actors: 1333,
  ips: 1773,
  countries: 47,
  threat: 52,
  uptime: "5h 37m",
  origin: "Mumbai · IN",
};

export const COUNTRIES = [
  { name: "Netherlands", cc: "NL", hits: 28890, lat: 52.1, lon: 5.3 },
  { name: "Bulgaria", cc: "BG", hits: 11001, lat: 43.2, lon: 27.9 },
  { name: "Vietnam", cc: "VN", hits: 5472, lat: 21.0, lon: 105.8 },
  { name: "India", cc: "IN", hits: 5373, lat: 22.72, lon: 75.83 },
  { name: "United States", cc: "US", hits: 4317, lat: 32.78, lon: -96.8 },
  { name: "Singapore", cc: "SG", hits: 4286, lat: 1.35, lon: 103.82 },
  { name: "United Kingdom", cc: "GB", hits: 3554, lat: 52.3, lon: -0.61 },
  { name: "China", cc: "CN", hits: 3404, lat: 32.06, lon: 118.76 },
];

export const ACTORS = [
  { ip: "92.118.39.14", playbook: "default_credential_spray", cc: "US", events: 6098 },
  { ip: "103.192.199.168", playbook: "service_account_enum", cc: "IN", events: 44474 },
  { ip: "176.53.159.196", playbook: "opportunistic", cc: "TR", events: 1026 },
  { ip: "193.46.255.86", playbook: "service_account_enum", cc: "GB", events: 2301 },
  { ip: "222.186.57.79", playbook: "opportunistic", cc: "CN", events: 1020 },
];

export const IPS = [
  { ip: "91.92.40.29", loc: "BG · Varna", hits: 4949 },
  { ip: "45.153.34.167", loc: "NL · Eygelshoven", hits: 4660 },
  { ip: "45.153.34.71", loc: "NL · Eygelshoven", hits: 4660 },
  { ip: "8.138.147.213", loc: "CN", hits: 3201 },
  { ip: "103.192.199.168", loc: "IN · Indore", hits: 2804 },
];

export const USERS = [
  ["root", 15105], ["admin", 3580], ["user", 1661], ["ubuntu", 892], ["test", 640], ["oracle", 412],
];

export const PASSWORDS = [
  ["123456", 364], ["123", 171], ["1234", 170], ["password", 98], ["admin", 87],
];

export const CMDS = [
  ["uname -s -v -n -r -m", 1182],
  ["uname -a", 277],
  ["cat /proc/cpuinfo", 198],
  ["wget http://…/x.sh", 94],
  ["curl -fsSL http://… | sh", 61],
];

export const SESSIONS = [
  ["12:33", "195.178.110.228", "root"],
  ["12:32", "195.178.110.228", "root"],
  ["12:30", "121.78.125.123", "admin"],
  ["12:12", "188.44.20.34", "ubuntu"],
  ["12:10", "222.186.57.79", "root"],
];

export const FEED = [
  ["12:36:25", "91.92.40.6", "root", "failed_password"],
  ["12:36:24", "91.92.40.6", "", "connect"],
  ["12:36:00", "103.192.199.168", "oracle", "failed_password"],
  ["12:35:36", "195.178.110.228", "root", "accepted", "uname -a"],
  ["12:34:48", "176.53.159.196", "admin", "command", "cat /proc/cpuinfo"],
  ["12:32:27", "193.46.255.86", "", "connect"],
  ["12:31:42", "193.46.255.86", "postgres", "failed_password"],
];

export const CAPTURE = { saved: 381, fetching: 0, failed: 1, bytes: "112 MB" };

/** Places used for focus buttons + clickable marker labels */
export const PLACES = [
  { id: "home", label: "Home", lat: HOME[0], lon: HOME[1] },
  { id: "nl", label: "NL", lat: 52.1, lon: 5.3 },
  { id: "bg", label: "BG", lat: 43.2, lon: 27.9 },
  { id: "us", label: "US", lat: 32.78, lon: -96.8 },
  { id: "in", label: "IN", lat: 22.72, lon: 75.83 },
  { id: "cn", label: "CN", lat: 32.06, lon: 118.76 },
];

export function fmt(n) {
  return n.toLocaleString("en-US");
}

export function locationToAngles(lat, lon) {
  return [
    Math.PI - ((lon * Math.PI) / 180 - Math.PI / 2),
    (lat * Math.PI) / 180,
  ];
}

/** Match Cobe's lat/lon → unit sphere (from cobe@2 source). */
export function latLonToVec3(lat, lon) {
  const r = (lat * Math.PI) / 180;
  const a = (lon * Math.PI) / 180 - Math.PI;
  const o = Math.cos(r);
  return [-o * Math.cos(a), Math.sin(r), o * Math.sin(a)];
}

/**
 * Project a lat/lon onto the canvas using the same rotation as Cobe
 * (phi / theta). Returns { x, y } in 0–1 canvas fractions and visible.
 * Globe radius in Cobe is 0.8; we lift markers slightly like markerElevation.
 */
export function projectLatLon(lat, lon, phi, theta, elevation = 0.02) {
  const [x0, y0, z0] = latLonToVec3(lat, lon);
  const r = 0.8 + elevation;
  const x = x0 * r;
  const y = y0 * r;
  const z = z0 * r;

  const ct = Math.cos(theta);
  const st = Math.sin(theta);
  const cp = Math.cos(phi);
  const sp = Math.sin(phi);

  // Same as Cobe's camera transform for markers
  const cx = cp * x + sp * z;
  const cy = sp * st * x + ct * y - cp * st * z;
  const cz = -sp * ct * x + st * y + cp * ct * z;

  const onFront = cz >= 0;
  const outsideDisk = cx * cx + cy * cy >= 0.64;
  return {
    x: (cx + 1) / 2,
    y: (-cy + 1) / 2,
    visible: onFront || outsideDisk,
    front: onFront,
  };
}

export function tickClock(el) {
  const paint = () => {
    el.textContent = new Date().toISOString().slice(11, 19) + "Z";
  };
  paint();
  return setInterval(paint, 1000);
}

export function drawSpark(canvas, color = "#0d5c63") {
  const ctx = canvas.getContext("2d");
  const pts = Array.from({ length: 48 }, (_, i) =>
    8 + Math.sin(i / 3.2) * 6 + Math.random() * 10 + (i > 40 ? 18 : 0)
  );
  const max = Math.max(...pts);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  pts.forEach((v, i) => {
    const x = (i / (pts.length - 1)) * canvas.width;
    const y = canvas.height - (v / max) * (canvas.height - 4) - 2;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  return pts;
}

/** Default markers/arcs for honeypot → home story */
export function globeEntities(colors) {
  const {
    home = [0.05, 0.36, 0.39],
    hot = [0.65, 0.48, 0.18],
    cool = [0.18, 0.42, 0.31],
    arc = [0.13, 0.36, 0.39],
  } = colors || {};

  const markers = [
    { id: "home", location: HOME, size: 0.07, color: home },
    { id: "nl", location: [52.1, 5.3], size: 0.055, color: hot },
    { id: "bg", location: [43.2, 27.9], size: 0.045, color: hot },
    { id: "us", location: [32.78, -96.8], size: 0.05, color: hot },
    { id: "in", location: [22.72, 75.83], size: 0.04, color: cool },
    { id: "cn", location: [32.06, 118.76], size: 0.04, color: cool },
  ];
  const arcs = [
    { id: "nl-home", from: [52.1, 5.3], to: HOME, color: arc },
    { id: "us-home", from: [32.78, -96.8], to: HOME, color: hot },
    { id: "cn-home", from: [32.06, 118.76], to: HOME, color: cool },
  ];
  return { markers, arcs };
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
 * Full interactive controls for a Cobe canvas:
 * - drag (phi + theta)
 * - momentum on release
 * - wheel zoom (scale)
 * - double-click → home
 * - focus(lat,lon) with easing
 * - clickable marker labels inside wrap
 */
export function bindGlobeInteraction(canvas, state, opts = {}) {
  const wrap = opts.wrap || canvas.parentElement;
  const places = opts.places || PLACES;
  const onFocus = opts.onFocus || (() => {});
  // Drag surface = wrap (or canvas). Binding to wrap means CSS labels
  // can't steal the gesture even if anchor positioning fails.
  const surface = wrap || canvas;

  let dragging = false;
  let moved = false;
  let lastX = 0;
  let lastY = 0;
  let pointerPhi = 0;
  let pointerTheta = 0;
  let velPhi = 0;
  let velTheta = 0;
  let resumeTimer = 0;
  let focusHoldUntil = 0;

  // Ensure interaction state fields exist
  state.phi ??= 2.4;
  state.theta ??= 0.2;
  state.targetPhi ??= state.phi;
  state.targetTheta ??= state.theta;
  state.scale ??= 1;
  state.targetScale ??= 1;
  state.autoRotate ??= true;
  state.interacting ??= false;

  surface.style.touchAction = "none";
  surface.style.cursor = "grab";
  surface.style.userSelect = "none";
  canvas.style.touchAction = "none";
  canvas.style.cursor = "grab";
  // Keep the WebGL canvas above decorative rings / failed-anchor labels
  canvas.style.position = canvas.style.position || "relative";
  canvas.style.zIndex = "2";

  const pauseAuto = (ms = 2800) => {
    state.autoRotate = false;
    state.interacting = true;
    clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => {
      if (Date.now() < focusHoldUntil) return;
      state.autoRotate = true;
      state.interacting = false;
    }, ms);
  };

  const focus = (lat, lon, meta = {}) => {
    const [p, t] = locationToAngles(lat, lon);
    state.targetPhi = state.phi + shortestAngleDelta(state.phi, p);
    state.targetTheta = clamp(t, -0.8, 0.9);
    velPhi = 0;
    velTheta = 0;
    state.autoRotate = false;
    state.interacting = true;
    focusHoldUntil = Date.now() + 4500;
    clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => {
      state.autoRotate = true;
      state.interacting = false;
    }, 4500);
    onFocus({ lat, lon, ...meta });
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
    state.autoRotate = false;
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
    const nextTheta = clamp(pointerTheta + dy * 0.005, -0.85, 0.95);

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
    pauseAuto(moved ? 3200 : 1800);
  };

  surface.addEventListener(
    "pointerdown",
    (e) => {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      if (e.target.closest && e.target.closest("button, a, input, .pin, .label, .sticker, .sat, .live-badge, .analytics, [data-place]")) return;
      beginDrag(e.clientX, e.clientY);
      try {
        surface.setPointerCapture(e.pointerId);
      } catch (_) {}
      e.preventDefault();
    },
    { passive: false }
  );

  window.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    onMove(e.clientX, e.clientY);
  });
  window.addEventListener("pointerup", endDrag);
  window.addEventListener("pointercancel", endDrag);

  // Mouse fallback only when PointerEvent is unavailable
  if (!window.PointerEvent) {
    surface.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      if (e.target.closest && e.target.closest("button, a, input, .pin, .label, .sticker, .sat, .live-badge, .analytics, [data-place]")) return;
      beginDrag(e.clientX, e.clientY);
      e.preventDefault();
    });
    window.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      onMove(e.clientX, e.clientY);
    });
    window.addEventListener("mouseup", endDrag);
  }

  canvas.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? -0.05 : 0.05;
      // Zoom is a layout multiplier — NOT Cobe's GL `scale` (that clips
      // the sphere into a square once it exceeds the canvas).
      state.targetScale = clamp((state.targetScale || 1) + delta, 0.7, 1.55);
      pauseAuto(2000);
    },
    { passive: false }
  );

  canvas.addEventListener("dblclick", (e) => {
    e.preventDefault();
    focus(HOME[0], HOME[1], { id: "home", label: "Home" });
    state.targetScale = 1;
  });

  // Manual label/overlay projection — Cobe CSS anchors are unreliable here
  // (anchors live in a nested wrapper Cobe inserts; visibility vars are "N").
  const labelEls = wrap
    ? [...wrap.querySelectorAll(".pin, .label, .sticker, .sat, .live-badge, .analytics, [data-place]")].filter(
        (el) => !el.classList.contains("arc-tag")
      )
    : [];

  // Hide arc tags — they need midpoint projection we don't need for demos.
  if (wrap) {
    wrap.querySelectorAll(".arc-tag").forEach((el) => {
      el.style.display = "none";
    });
  }

  const placeById = Object.fromEntries(places.map((p) => [p.id, p]));

  const overlayTransform = (el) => {
    // data-offset: "above" | "pin" | "side" | "float" (default by class)
    const mode =
      el.getAttribute("data-offset") ||
      (el.classList.contains("sticker")
        ? "float"
        : el.classList.contains("sat")
          ? "float"
          : el.classList.contains("live-badge") || el.classList.contains("analytics")
            ? "side"
            : "pin");
    const tilt = getComputedStyle(el).getPropertyValue("--tilt").trim() || "0deg";
    if (mode === "float") {
      return el.classList.contains("sticker")
        ? `translate(-50%, calc(-100% - 28px)) rotate(${tilt})`
        : "translate(-50%, calc(-100% - 28px))";
    }
    if (mode === "side") return "translate(14px, -50%)";
    if (mode === "center") return "translate(-50%, -50%)";
    return "translate(-50%, calc(-100% - 8px))";
  };

  labelEls.forEach((el) => {
    el.style.pointerEvents = "none";
    el.style.cursor = "pointer";
    el.style.position = "absolute";
    el.style.left = "0";
    el.style.top = "0";
    el.style.right = "auto";
    el.style.bottom = "auto";
    el.style.zIndex = el.classList.contains("sticker") || el.classList.contains("sat") ? "4" : "3";
    el.style.margin = "0";
    // Kill CSS Anchor Positioning leftovers from the demos' stylesheets
    el.style.positionAnchor = "auto";
    el.style.translate = "none";
    el.style.transform = overlayTransform(el);
    el.style.transition = "opacity .2s ease";
    el.style.opacity = "0";
    el.title = el.title || "Click to focus";
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = el.getAttribute("data-place");
      const place = placeById[id];
      if (place) focus(place.lat, place.lon, place);
    });
  });

  const syncLabels = (phi, theta) => {
    for (const el of labelEls) {
      const id = el.getAttribute("data-place");
      const place = placeById[id];
      if (!place) {
        el.style.opacity = "0";
        el.style.pointerEvents = "none";
        continue;
      }
      const elev = el.classList.contains("sat") ? 0.06 : 0.02;
      const p = projectLatLon(place.lat, place.lon, phi, theta, elev);
      el.style.left = `${(p.x * 100).toFixed(2)}%`;
      el.style.top = `${(p.y * 100).toFixed(2)}%`;
      el.style.transform = overlayTransform(el);
      if (p.front) {
        el.style.opacity = "1";
        el.style.pointerEvents = "auto";
        el.style.zIndex = el.classList.contains("sticker") || el.classList.contains("sat") ? "4" : "3";
      } else {
        el.style.opacity = "0";
        el.style.pointerEvents = "none";
        el.style.zIndex = "0";
      }
    }
  };

  // Capture the wrap's natural size once (before we start mutating it for zoom).
  const baseSize = wrap
    ? Math.min(wrap.clientWidth, wrap.clientHeight) || 480
    : 480;

  return {
    isDragging: () => dragging,
    focus,
    wrap,
    baseSize,
    /**
     * Advance interaction state one frame.
     * Cobe 2.x has NO onRender — callers must rAF + globe.update().
     * `zoom` resizes the wrap; GL `scale` stays 1 so the sphere never clips.
     */
    tick() {
      if (!dragging) {
        if (Math.abs(velPhi) > 0.0002 || Math.abs(velTheta) > 0.0002) {
          state.phi += velPhi;
          state.theta = clamp(state.theta + velTheta, -0.85, 0.95);
          state.targetPhi = state.phi;
          state.targetTheta = state.theta;
          velPhi *= 0.94;
          velTheta *= 0.92;
        } else {
          if (state.autoRotate && !state.interacting) {
            state.targetPhi += 0.002;
          }
          state.phi += shortestAngleDelta(state.phi, state.targetPhi) * 0.085;
          state.theta += (state.targetTheta - state.theta) * 0.085;
        }
        state.scale += ((state.targetScale || 1) - (state.scale || 1)) * 0.14;
      }
      syncLabels(state.phi, state.theta);
      return {
        phi: state.phi,
        theta: state.theta,
        zoom: state.scale || 1,
      };
    },
    places,
  };
}

/**
 * Cobe 2.x removed onRender. Drive the globe yourself:
 *   const stop = startGlobeLoop(globe, ix, ({ phi }) => { ... });
 *
 * Zoom grows/shrinks the wrap + canvas backing store and keeps Cobe's
 * internal scale at 1 — so the globe stays a circle, never a clipped square.
 */
export function startGlobeLoop(globe, ix, onFrame) {
  let raf = 0;
  let alive = true;
  const wrap = ix.wrap;
  const base = ix.baseSize || 480;
  // Match existing demos: width/height passed as CSS px * 2 (retina-ish),
  // with devicePixelRatio: 2 in createGlobe.
  const backing = (cssPx) => Math.max(2, Math.round(cssPx * 2));

  const frame = () => {
    if (!alive) return;
    const view = ix.tick();
    const cssPx = base * view.zoom;
    if (wrap) {
      wrap.style.width = `${cssPx}px`;
      wrap.style.height = `${cssPx}px`;
    }
    globe.update({
      phi: view.phi,
      theta: view.theta,
      scale: 1,
      width: backing(cssPx),
      height: backing(cssPx),
    });
    if (onFrame) onFrame(view);
    raf = requestAnimationFrame(frame);
  };
  raf = requestAnimationFrame(frame);
  return () => {
    alive = false;
    cancelAnimationFrame(raf);
  };
}

/** Wire focus button group (#focuses) to interaction.focus */
export function wireFocusButtons(el, ix, places = PLACES) {
  if (!el) return places;
  const list = places.filter((p) =>
    ["home", "nl", "bg", "us", "cn", "in"].includes(p.id)
  );
  el.innerHTML = list
    .map(
      (p, i) =>
        `<button type="button" data-i="${i}" class="${i === 0 ? "on" : ""}">${p.label}</button>`
    )
    .join("");
  el.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    el.querySelectorAll("button").forEach((b) => b.classList.remove("on"));
    btn.classList.add("on");
    const p = list[+btn.dataset.i];
    ix.focus(p.lat, p.lon, p);
  });
  return list;
}
