/**
 * Interactive Cobe helpers for Meridian / Sprite themes.
 * Cobe 2.x: no onRender — rAF + update.
 */

export function locationToAngles(lat, lon) {
  return [
    Math.PI - ((lon * Math.PI) / 180 - Math.PI / 2),
    (lat * Math.PI) / 180,
  ];
}

export function latLonToVec3(lat, lon) {
  const r = (lat * Math.PI) / 180;
  const a = (lon * Math.PI) / 180 - Math.PI;
  const o = Math.cos(r);
  return [-o * Math.cos(a), Math.sin(r), o * Math.sin(a)];
}

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

export function bindGlobeInteraction(canvas, state, opts = {}) {
  const wrap = opts.wrap || canvas.parentElement;
  const places = opts.places || [];
  // Theme markerElevation, so the fallback projection lands on the same sphere
  // as the WebGL markers.
  const markerElevation = Number.isFinite(opts.markerElevation)
    ? opts.markerElevation
    : 0.03;
  const onFocus = opts.onFocus || (() => {});
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

  const skipSel =
    "button, a, input, .pin, .label, .sticker, .sat, .live-badge, .analytics, .globe-overlay, [data-place]";

  surface.addEventListener(
    "pointerdown",
    (e) => {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      if (e.target.closest && e.target.closest(skipSel)) return;
      beginDrag(e.clientX, e.clientY);
      try {
        surface.setPointerCapture(e.pointerId);
      } catch (_) {}
      e.preventDefault();
    },
    { passive: false }
  );

  const onPointerMove = (e) => {
    if (!dragging) return;
    onMove(e.clientX, e.clientY);
  };
  window.addEventListener("pointermove", onPointerMove);
  window.addEventListener("pointerup", endDrag);
  window.addEventListener("pointercancel", endDrag);

  const onWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.05 : 0.05;
    state.targetScale = clamp((state.targetScale || 1) + delta, 0.7, 1.55);
    pauseAuto(2000);
  };
  canvas.addEventListener("wheel", onWheel, { passive: false });

  const onDblClick = (e) => {
    e.preventDefault();
    const home = places.find((p) => p.id === "home") || places[0];
    if (home) {
      focus(home.lat, home.lon, home);
      state.targetScale = 1;
    }
  };
  canvas.addEventListener("dblclick", onDblClick);

  let labelEls = [];
  let placeById = {};

  /** Just the decorative rotation, for elements positioned by CSS anchors. */
  const tiltOnly = (el) => {
    const tilt = getComputedStyle(el).getPropertyValue("--tilt").trim();
    return tilt && tilt !== "0deg" ? `rotate(${tilt})` : "none";
  };

  const overlayTransform = (el) => {
    const mode =
      el.getAttribute("data-offset") ||
      (el.classList.contains("sticker") || el.classList.contains("globe-sticker")
        ? "float"
        : el.classList.contains("sat") || el.classList.contains("globe-sat")
          ? "float"
          : el.classList.contains("live-badge") ||
              el.classList.contains("globe-live") ||
              el.classList.contains("analytics") ||
              el.classList.contains("globe-analytics") ||
              el.classList.contains("globe-node")
            ? "side"
            : "pin");
    const tilt = getComputedStyle(el).getPropertyValue("--tilt").trim() || "0deg";
    if (mode === "float") {
      return el.classList.contains("sticker") || el.classList.contains("globe-sticker")
        ? `translate(-50%, calc(-100% - 28px)) rotate(${tilt})`
        : "translate(-50%, calc(-100% - 28px))";
    }
    if (mode === "side") return "translate(14px, -50%)";
    if (mode === "center") return "translate(-50%, -50%)";
    return "translate(-50%, calc(-100% - 8px))";
  };

  const rebindLabels = (nextPlaces) => {
    placeById = Object.fromEntries((nextPlaces || []).map((p) => [p.id, p]));
    labelEls = wrap
      ? [...wrap.querySelectorAll(".globe-overlay, [data-place]")].filter(
          (el) => !el.classList.contains("arc-tag")
        )
      : [];
    labelEls.forEach((el) => {
      el.style.pointerEvents = "none";
      el.style.cursor = "pointer";
      el.style.position = "absolute";
      el.style.left = "0";
      el.style.top = "0";
      el.style.right = "auto";
      el.style.bottom = "auto";
      el.style.zIndex =
        el.classList.contains("sticker") ||
        el.classList.contains("globe-sticker") ||
        el.classList.contains("sat") ||
        el.classList.contains("globe-sat")
          ? "4"
          : "3";
      el.style.margin = "0";
      el.style.translate = "none";
      el.style.transform = overlayTransform(el);
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
        // so it must be pulled back half its own width or every sticker sits
        // consistently right of its marker (measured: exactly 18.5px for a
        // 37px sticker). Using the `translate` property keeps `transform`
        // free for the decorative tilt.
        el.style.translate = "-50% 0";
        // The anchor insets already sit the element directly above the marker,
        // so the translate half of overlayTransform must NOT also apply — that
        // double-counted the lift and pushed stickers 54px off (100% of height
        // plus the 28px float gap). Keep only the decorative tilt.
        el.style.transform = tiltOnly(el);
        el.style.opacity = `var(--cobe-visible-${el.getAttribute("data-marker")}, 0)`;
        el.style.pointerEvents = "none";
      } else {
        el.style.positionAnchor = "auto";
        el.style.bottom = "auto";
      }
      if (!el._cobeBound) {
        el._cobeBound = true;
        el.addEventListener("click", (e) => {
          e.stopPropagation();
          const id = el.getAttribute("data-place");
          const place = placeById[id];
          if (place) focus(place.lat, place.lon, place);
        });
      }
    });
  };

  rebindLabels(places);

  // ---- runtime declutter for anchor-positioned stickers -------------------
  // Anchored stickers are placed by CSS, so we cannot know at BUILD time which
  // ones will overlap: that depends on the live rotation, and two points 22°
  // apart foreshorten to ~12px near the limb. Rather than emit a handful of
  // widely-separated flags and hide the rest of the world, emit many and let
  // geometry decide each pass — as the globe turns, different countries become
  // readable and take their turn.
  //
  // Priority is DOM order, which callers emit in volume order, so the busiest
  // country always wins a contested spot. Throttled because it reads layout;
  // the globe itself only paints at 12-30fps when idle.
  let lastDeclutter = 0;
  const declutterAnchored = () => {
    const now = performance.now();
    if (now - lastDeclutter < 120) return;
    lastDeclutter = now;
    const kept = [];
    const PAD = 3; // px of breathing room between two stickers
    for (const el of labelEls) {
      if (!el._cobeAnchored) continue;
      // Cobe drives opacity via --cobe-visible-<id>; a back-facing sticker is
      // already invisible and must not block a front-facing one.
      if (parseFloat(getComputedStyle(el).opacity || "0") < 0.5) {
        el.style.visibility = "hidden";
        continue;
      }
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) {
        el.style.visibility = "hidden";
        continue;
      }
      const hit = kept.some(
        (k) =>
          r.left < k.right + PAD &&
          r.right > k.left - PAD &&
          r.top < k.bottom + PAD &&
          r.bottom > k.top - PAD
      );
      if (hit) {
        el.style.visibility = "hidden";
      } else {
        el.style.visibility = "visible";
        kept.push(r);
      }
    }
  };

  const syncLabels = (phi, theta) => {
    declutterAnchored();
    for (const el of labelEls) {
      const id = el.getAttribute("data-place");
      const place = placeById[id];
      if (!place) {
        el.style.opacity = "0";
        el.style.pointerEvents = "none";
        continue;
      }
      // Elements anchored to a Cobe marker are positioned by the LIBRARY's own
      // projection (see anchorNameFor), so skip our JS projection entirely —
      // that is what makes them pixel-exact instead of ~2-6px adrift.
      if (el._cobeAnchored) continue;
      const offset = el.getAttribute("data-offset");
      // Elevation MUST match the theme's markerElevation, otherwise the overlay
      // is projected onto a different sphere than the marker it annotates and
      // drifts outward toward the limb (measured up to ~2px at 0.02-vs-0.03,
      // ~6px for the old float value). Float lift is a CSS translate, not an
      // elevation bump — doing both double-counted it.
      const elev = markerElevation;
      void offset;
      const p = projectLatLon(place.lat, place.lon, phi, theta, elev);
      el.style.left = `${(p.x * 100).toFixed(2)}%`;
      el.style.top = `${(p.y * 100).toFixed(2)}%`;
      el.style.transform = overlayTransform(el);
      if (p.front) {
        el.style.opacity = "1";
        el.style.pointerEvents = "auto";
        el.style.zIndex =
          el.classList.contains("sticker") ||
          el.classList.contains("globe-sticker") ||
          el.classList.contains("sat") ||
          el.classList.contains("globe-sat")
            ? "4"
            : "3";
      } else {
        el.style.opacity = "0";
        el.style.pointerEvents = "none";
        el.style.zIndex = "0";
      }
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
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", endDrag);
      window.removeEventListener("pointercancel", endDrag);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("dblclick", onDblClick);
      clearTimeout(resumeTimer);
    },
    setPlaces(next) {
      rebindLabels(next);
    },
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
  };
}

export function startGlobeLoop(globe, ix, onFrame) {
  let raf = 0;
  let alive = true;
  const wrap = ix.wrap;
  const base = ix.baseSize || 480;
  // Cap DPR — full retina * zoom reallocates WebGL buffers and hangs weak GPUs.
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  const backing = (cssPx) => Math.max(2, Math.round(cssPx * dpr));

  let lastW = 0;
  let lastH = 0;
  let lastPhi = NaN;
  let lastTheta = NaN;
  let lastCss = 0;
  let lastPaint = 0;

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
    const cssPx = base * view.zoom;
    const w = backing(cssPx);
    const h = w;
    const now = performance.now();

    const sizeChanged = w !== lastW || h !== lastH;
    const angleChanged =
      Math.abs(view.phi - lastPhi) > 0.0002 ||
      Math.abs(view.theta - lastTheta) > 0.0002;
    const zoomChanged = Math.abs(cssPx - lastCss) > 0.4;
    const interacting = !!(ix.isDragging && ix.isDragging());

    // Throttle paints: 60fps while dragging, ~30fps while auto-rotating, ~12fps idle.
    const minGap = interacting ? 0 : angleChanged || zoomChanged ? 32 : 80;
    const due = now - lastPaint >= minGap;

    if (due && (sizeChanged || angleChanged || zoomChanged || interacting)) {
      if (wrap && (sizeChanged || zoomChanged)) {
        wrap.style.width = `${cssPx}px`;
        wrap.style.height = `${cssPx}px`;
      }
      const patch = { phi: view.phi, theta: view.theta, scale: 1 };
      if (sizeChanged) {
        patch.width = w;
        patch.height = h;
        lastW = w;
        lastH = h;
      }
      globe.update(patch);
      lastPhi = view.phi;
      lastTheta = view.theta;
      lastCss = cssPx;
      lastPaint = now;
      if (onFrame) onFrame(view);
    }

    schedule(interacting ? 0 : minGap || 32);
  };

  schedule(0);
  return () => {
    alive = false;
    document.removeEventListener("visibilitychange", onVis);
    if (raf) {
      cancelAnimationFrame(raf);
      clearTimeout(raf);
      raf = 0;
    }
  };
}

/** Theme palettes for Cobe createGlobe options + marker/arc RGB triples. */
export function cobeThemeConfig(theme, mode) {
  if (theme === "signal") {
    if (mode === "light") {
      return {
        dark: 0,
        diffuse: 1.15,
        mapSamples: 8000,
        mapBrightness: 1.35,
        mapBaseBrightness: 0.08,
        baseColor: [0.92, 0.92, 0.88],
        markerColor: [0.55, 0.68, 0.0],
        glowColor: [0.85, 0.86, 0.80],
        markerElevation: 0.022,
        arcColor: [0.55, 0.68, 0.0],
        arcWidth: 0.5,
        arcHeight: 0.3,
        colors: {
          home: [0.55, 0.68, 0.0],
          hot: [0.77, 0.12, 0.15],
          cool: [0.12, 0.54, 0.30],
          arc: [0.55, 0.68, 0.0],
        },
      };
    }
    return {
      dark: 1,
      diffuse: 1.05,
      mapSamples: 8000,
      mapBrightness: 2.8,
      mapBaseBrightness: 0.015,
      baseColor: [0.07, 0.08, 0.09],
      markerColor: [0.82, 0.99, 0.09],
      glowColor: [0.12, 0.14, 0.10],
      markerElevation: 0.03,
      arcColor: [0.82, 0.99, 0.09],
      arcWidth: 0.5,
      arcHeight: 0.32,
      colors: {
        home: [0.82, 0.99, 0.09],
        hot: [0.90, 0.16, 0.19],
        cool: [0.25, 0.85, 0.52],
        arc: [0.82, 0.99, 0.09],
      },
    };
  }
  if (theme === "sprite") {
    // Sprite's globe was the noisiest of the three: 80 coral arcs fanning out of
    // one point over ~30 saturated green/amber dots, inside a BLUE rim glow that
    // did not exist anywhere else in this warm cream palette. Retuned for calm:
    // warm glow, flush markers, far fewer and thinner arcs, muted marker ink.
    return {
      dark: 0,
      diffuse: 1.5,
      mapSamples: 9000,
      mapBrightness: 5.0,
      // mapBaseBrightness is what makes the dot map VISIBLE on a light globe (it
      // floors the map value so ocean is stippled too). Setting it to 0 renders
      // a blank sphere at this size — verified by sweeping the parameter.
      mapBaseBrightness: 0.1,
      baseColor: [1, 0.975, 0.93],
      markerColor: [0.91, 0.36, 0.3],
      glowColor: [0.97, 0.91, 0.79],
      // Flush with the surface. Elevated markers read as clutter floating above
      // the globe, and the reference globes all sit them on it.
      markerElevation: 0,
      arcColor: [0.89, 0.48, 0.36],
      arcWidth: 0.3,
      // Kept close to the surface. Higher values (0.44 was tried) loop the arc
      // well outside the globe silhouette, which reads as a rendering glitch
      // rather than as an arc once the globe rotates.
      arcHeight: 0.34,
      // Density caps. The globe is 415px; 80 arcs there is a scribble, not a
      // visualisation. The top talkers carry the signal.
      maxArcs: 12,
      maxMarkers: 24,
      markerSize: { base: 0.02, cap: 0.024, div: 900 },
      colors: {
        home: [0.91, 0.36, 0.3],
        // One muted ink for attacker markers: the hot/cool split added colour
        // noise without encoding anything the size did not already show.
        hot: [0.58, 0.44, 0.32],
        cool: [0.58, 0.44, 0.32],
        arc: [0.89, 0.48, 0.36],
      },
      stickers: { max: 5, minSeparationDeg: 22 },
    };
  }
  // meridian (default light)
  return {
    dark: 0,
    diffuse: 1.38,
    mapSamples: 8000,
    mapBrightness: 5.6,
    mapBaseBrightness: 0.04,
    baseColor: [0.92, 0.94, 0.96],
    markerColor: [0.13, 0.36, 0.39],
    glowColor: [0.72, 0.82, 0.88],
    markerElevation: 0.022,
    arcColor: [0.13, 0.36, 0.39],
    arcWidth: 0.45,
    arcHeight: 0.28,
    colors: {
      home: [0.05, 0.36, 0.39],
      hot: [0.65, 0.48, 0.18],
      cool: [0.18, 0.42, 0.31],
      arc: [0.13, 0.36, 0.39],
    },
  };
}

/** Max markers/arcs on the live Cobe globe (Dragon globe.gl uses 80). */
export const COBE_MAX_ARCS = 80;
export const COBE_MAX_MARKERS = 80;

/** Stable key so globe.update runs when geo/arcs actually change (not just ids). */
export function cobeEntitiesKey(home, markers, arcs) {
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

/**
 * The actor list in the exact order buildCobeEntities assigns marker ids
 * (`a0`, `a1`, …). DOM overlays anchored to `--cobe-a<i>` MUST derive their
 * index from this list, not from the raw actor array: markers come from the
 * deduped+capped set, so raw index i and marker `a<i>` are different actors
 * whenever two actors share a geo bucket — which is common (Amsterdam and
 * Frankfurt collapse constantly). Exported so index.html can build overlays
 * against the same ordering instead of duplicating the rule.
 */
export function globeActorOrder(actors, maxMarkers = COBE_MAX_MARKERS) {
  const ranked = (actors || [])
    .filter((a) => Number.isFinite(a.lat) && Number.isFinite(a.lon))
    .sort((a, b) => (b.events || 0) - (a.events || 0));
  return dedupeActorsByLocation(ranked).slice(0, maxMarkers);
}

/** Drop lower-volume actors that share the same ~1° geo bucket so arcs spread globally. */
function dedupeActorsByLocation(actors) {
  const seen = new Map();
  for (const a of actors) {
    const k = `${a.lat.toFixed(1)},${a.lon.toFixed(1)}`;
    const prev = seen.get(k);
    if (!prev || (a.events || 0) > (prev.events || 0)) seen.set(k, a);
  }
  return [...seen.values()].sort((x, y) => (y.events || 0) - (x.events || 0));
}

/**
 * Build Cobe markers + arcs from live dashboard actors + home.
 * Caps match globe.gl (80) so Meridian/Sprite show the same attack fan-in.
 */
export function buildCobeEntities(home, actors, colors, opts = {}) {
  const maxArcs = opts.maxArcs ?? COBE_MAX_ARCS;
  const maxMarkers = opts.maxMarkers ?? COBE_MAX_MARKERS;
  // Per-theme marker scale. Defaults reproduce the original curve exactly, so
  // themes that don't override it are untouched.
  const ms = opts.markerSize || {};
  const szBase = ms.base ?? 0.028;
  const szCap = ms.cap ?? 0.05;
  const szDiv = ms.div ?? 350;
  const {
    home: homeC = [0.05, 0.36, 0.39],
    hot = [0.65, 0.48, 0.18],
    cool = [0.18, 0.42, 0.31],
    arc = [0.13, 0.36, 0.39],
  } = colors || {};

  const ranked = (actors || [])
    .filter((a) => Number.isFinite(a.lat) && Number.isFinite(a.lon))
    .sort((a, b) => (b.events || 0) - (a.events || 0));
  const spread = dedupeActorsByLocation(ranked);

  const markers = [
    {
      id: "home",
      location: [home.lat, home.lon],
      size: 0.085,
      color: homeC,
    },
  ];
  spread.slice(0, maxMarkers).forEach((a, i) => {
    const n = a.events || 0;
    const size = szBase + Math.min(szCap, Math.sqrt(n) / szDiv);
    markers.push({
      id: "a" + i,
      location: [a.lat, a.lon],
      size,
      color: i < 12 ? hot : cool,
    });
  });

  const arcs = spread.slice(0, maxArcs).map((a, i) => ({
    id: "arc" + i,
    from: [a.lat, a.lon],
    to: [home.lat, home.lon],
    color: i < 16 ? hot : arc,
  }));

  return { markers, arcs };
}
