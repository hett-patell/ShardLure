// Shared intel-console helpers for Meridian / Sprite demos.
import { INTEL } from "./_intel_data.js";

export { INTEL };

export function fmt(n) {
  if (n == null || Number.isNaN(n)) return "—";
  return Number(n).toLocaleString("en-US");
}

export function fmtRate(n) {
  if (n == null) return "—";
  return Number(n).toFixed(1) + "/h";
}

export function shortTime(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toISOString().slice(11, 19) + "Z";
  } catch {
    return String(iso).slice(11, 19) || "—";
  }
}

export function uptime(sec) {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `${h}h ${m}m`;
}

export function threatLabel(score) {
  if (score >= 70) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 25) return "ELEVATED";
  return "LOW";
}

/** Rough threat score from live summary shape (matches demo gauge feel). */
export function threatScore(intel = INTEL) {
  const actors = intel.actors || [];
  const radar = intel.radar || [];
  const vol = Math.min(25, Math.round((intel.summary?.eventCount || 0) / 800));
  const div = Math.min(25, (intel.summary?.countries || 0));
  const agg = Math.min(25, Math.round((radar[0]?.rateHour || 0) / 8));
  const wpn = Math.min(25, Math.round((actors[0]?.probeScore || 0) / 4));
  return Math.min(100, vol + Math.min(22, div) + agg + Math.min(20, wpn / 2 + 4));
}

export function wireTabs(root = document) {
  const tabs = root.querySelectorAll("[data-view]");
  const views = root.querySelectorAll(".view");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const id = tab.getAttribute("data-view");
      tabs.forEach((t) => t.classList.toggle("on", t === tab));
      tabs.forEach((t) => t.classList.toggle("active", t === tab));
      views.forEach((v) => {
        const on = v.id === `view-${id}`;
        v.classList.toggle("on", on);
        v.classList.toggle("active", on);
        v.hidden = !on;
      });
    });
  });
}

export function wireWindowChips(root = document) {
  root.querySelectorAll("[data-window]").forEach((chip) => {
    chip.addEventListener("click", () => {
      root.querySelectorAll("[data-window]").forEach((c) => c.classList.remove("on"));
      chip.classList.add("on");
    });
  });
}

export function barRows(items, { labelKey = "label", hitsKey = "hits", max } = {}) {
  const list = items || [];
  const m = max || Math.max(1, ...list.map((x) => x[hitsKey] || 0));
  return list
    .map((x, i) => {
      const hits = x[hitsKey] || 0;
      const label = x[labelKey] || x.name || x.cc || "—";
      const pct = ((hits / m) * 100).toFixed(1);
      return `<div class="bar" style="--i:${i}">
        <span class="lbl" title="${label}">${label}</span>
        <div class="track"><i style="width:${pct}%"></i></div>
        <span class="n">${fmt(hits)}</span>
      </div>`;
    })
    .join("");
}

export function geoBars(countries) {
  const max = Math.max(1, ...(countries || []).map((c) => c.hits));
  return (countries || [])
    .map(
      (c, i) => `<div class="bar" style="--i:${i}">
      <span class="lbl"><b>${c.cc || ""}</b> ${c.country || c.name || ""}</span>
      <div class="track"><i style="width:${((c.hits / max) * 100).toFixed(1)}%"></i></div>
      <span class="n">${(c.hits / 1000).toFixed(1)}k</span>
    </div>`
    )
    .join("");
}

export function radarBars(radar) {
  const max = Math.max(1, ...(radar || []).map((r) => r.rateHour || 0));
  return (radar || [])
    .map(
      (r, i) => `<div class="bar" style="--i:${i}">
      <span class="lbl mono">${r.ip}</span>
      <div class="track"><i style="width:${(((r.rateHour || 0) / max) * 100).toFixed(1)}%"></i></div>
      <span class="n">${fmtRate(r.rateHour)}</span>
    </div>`
    )
    .join("");
}

export function credList(entries, key) {
  return (entries || [])
    .map((e) => {
      const name = e[key] || e.username || e.password || e.value || "—";
      const count = e.count ?? e.hits ?? 0;
      return `<div class="cred"><code>${esc(name)}</code><span>${fmt(count)}</span></div>`;
    })
    .join("");
}

export function actorsTable(actors) {
  return (actors || [])
    .map((a) => {
      const loc = [a.cc, a.city || a.country].filter(Boolean).join(" · ");
      return `<tr data-actor="${esc(a.id)}">
        <td class="ip">${esc(a.ip)}</td>
        <td class="muted">${esc(loc)}</td>
        <td><span class="tag">${esc(a.playbook || "—")}</span></td>
        <td>${esc(a.intent || "—")}</td>
        <td class="n">${fmt(a.events)}</td>
        <td class="n probe">${a.probeScore ?? "—"}</td>
        <td class="cmd">${esc(a.lastCommand || "—")}</td>
        <td class="muted">${shortTime(a.lastSeen)}</td>
      </tr>`;
    })
    .join("");
}

export function cmdsTable(rows) {
  return (rows || [])
    .map(
      (r) => `<tr>
      <td class="muted">${shortTime(r.ts)}</td>
      <td class="ip">${esc(r.ip || r.srcIp || "")}</td>
      <td>${esc(r.user || r.username || "")}</td>
      <td><span class="kind ${esc(r.kind)}">${esc(r.kind)}</span></td>
      <td class="cmd">${esc(r.command || "—")}</td>
    </tr>`
    )
    .join("");
}

export function timelineRows(events) {
  return (events || [])
    .map(
      (e) => `<div class="tl-row">
      <span class="t">${shortTime(e.ts)}</span>
      <span class="ip">${esc(e.srcIp || e.ip || "")}</span>
      <span class="u">${esc(e.username || e.user || "")}</span>
      <span class="kind ${esc(e.kind)}">${esc(e.kind)}</span>
      ${e.command ? `<span class="cmd">${esc(e.command)}</span>` : ""}
    </div>`
    )
    .join("");
}

export function mitreCards(hits) {
  return (hits || [])
    .map(
      (h) => `<div class="mitre-card">
      <div class="mid">${esc(h.id)}</div>
      <div class="mname">${esc(h.name)}</div>
      <div class="mtactic">${esc(h.tactic)}</div>
      <div class="mstats"><b>${fmt(h.count)}</b> hits · ${fmt(h.actorCount)} actors</div>
    </div>`
    )
    .join("");
}

export function sessionsList(sessions) {
  return (sessions || [])
    .map(
      (s) => `<div class="sess">
      <div class="sess-top">
        <span class="ip">${esc(s.ip)}</span>
        <span class="tag">${esc(s.user || "—")}</span>
        <span class="muted">${fmt(s.events)} ev · ${s.durMs ?? "—"}ms</span>
      </div>
      <div class="sess-meta mono">${esc(s.client || "")} · ${esc((s.hassh || "").slice(0, 16))}</div>
      <div class="muted">${shortTime(s.start)} → ${shortTime(s.end)}</div>
    </div>`
    )
    .join("");
}

export function ttpTable(rows) {
  return (rows || [])
    .map(
      (r) => `<tr>
      <td class="cmd">${esc(r.template)}</td>
      <td class="n">${fmt(r.count)}</td>
      <td class="n">${fmt(r.actorCount)}</td>
    </tr>`
    )
    .join("");
}

export function payloadsTable(rows) {
  return (rows || [])
    .map(
      (p) => `<tr>
      <td class="muted">${shortTime(p.ts)}</td>
      <td><span class="tag ${esc(p.status)}">${esc(p.status)}</span></td>
      <td class="cmd">${esc(p.url || p.origin || "—")}</td>
      <td class="n">${fmt(p.sizeBytes)}</td>
      <td class="mono">${esc(p.sha256)}</td>
    </tr>`
    )
    .join("");
}

export function tunnelsTable(rows) {
  return (rows || [])
    .map(
      (t) => `<tr>
      <td class="ip">${esc(t.dstIp)}</td>
      <td class="n">${t.dstPort}</td>
      <td class="n">${fmt(t.hits)}</td>
      <td class="n">${fmt(t.uniqueActors)}</td>
      <td class="muted">${shortTime(t.lastSeen)}</td>
    </tr>`
    )
    .join("");
}

export function abuseTable(rows) {
  return (rows || [])
    .map(
      (r) => `<tr>
      <td class="ip">${esc(r.srcIp)}</td>
      <td><span class="tag">${esc(r.playbook)}</span></td>
      <td class="n">${r.priority ?? "—"}</td>
      <td class="n">${fmt(r.eventCount)}</td>
      <td class="muted">${esc((r.reasons || []).slice(0, 2).join("; "))}</td>
    </tr>`
    )
    .join("");
}

export function iocTable(rows) {
  return (rows || [])
    .map(
      (r) => `<tr>
      <td>${esc(r.type)}</td>
      <td class="ip">${esc(r.value)}</td>
      <td>${esc(r.cc || "")}</td>
      <td class="n">${fmt(r.count)}</td>
    </tr>`
    )
    .join("");
}

export function deobfList(rows) {
  return (rows || [])
    .map(
      (d) => `<div class="deobf">
      <div class="tag">${esc(d.technique)}</div>
      <div class="cmd raw">${esc(d.raw)}</div>
      <div class="cmd ok">→ ${esc(d.decoded)}</div>
    </div>`
    )
    .join("");
}

export function drawHeatmap(canvas, heat) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const kinds = [...new Set((heat || []).map((h) => h.kind))];
  const hours = 24;
  const cellW = canvas.width / hours;
  const cellH = canvas.height / Math.max(1, kinds.length);
  const max = Math.max(1, ...(heat || []).map((h) => h.n || 0));
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const by = {};
  for (const h of heat || []) {
    const hour = new Date(h.t).getUTCHours();
    by[`${hour}|${h.kind}`] = h.n;
  }
  kinds.forEach((kind, yi) => {
    for (let hour = 0; hour < hours; hour++) {
      const n = by[`${hour}|${kind}`] || 0;
      const a = n / max;
      ctx.fillStyle = `rgba(232, 93, 76, ${0.08 + a * 0.85})`;
      ctx.fillRect(hour * cellW + 1, yi * cellH + 1, cellW - 2, cellH - 2);
    }
  });
}

export function paintIntel(root = document, intel = INTEL) {
  const s = intel.summary || {};
  const score = threatScore(intel);
  const set = (id, html) => {
    const el = root.getElementById?.(id) || document.getElementById(id);
    if (el) el.innerHTML = html;
  };
  const text = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };

  text("s-events", fmt(s.eventCount));
  text("s-actors", fmt(s.actorCount));
  text("s-ips", fmt(s.uniqueIps));
  text("s-countries", fmt(s.countries));
  text("s-uptime", uptime(intel.uptimeSeconds || 0));
  text("s-upd", shortTime(intel.generatedAt));
  text("gauge-val", String(score));
  text("gauge-lbl", threatLabel(score));
  text("tl-meta", `${(intel.timeline || []).length} events`);
  text("sessions-meta", `${fmt(intel.sessionsTotal || (intel.sessions || []).length)} sessions`);
  text("mitre-meta", `${fmt(intel.mitre?.totalEvents)} events · ${intel.mitre?.windowHours || 24}h`);
  text("payloads-meta", `${fmt(intel.payloadsTotal)} tracked`);
  text("cap-total", fmt(intel.capture?.tracked));
  text("cap-fetched", fmt(intel.capture?.saved));
  text("cap-active", fmt(intel.capture?.fetching));
  text("cap-bytes", intel.capture?.bytes || "—");
  text("bz-uploaded", fmt(intel.bazaar?.stats?.totalUploaded));
  text("bz-pending", fmt(intel.bazaar?.stats?.pending));
  text("bz-dupes", fmt(intel.bazaar?.stats?.duplicates));

  set("geo-bars", geoBars(intel.topCountries));
  set("radar-bars", radarBars(intel.radar));
  set("cred-pw", credList(intel.wordlistPasswords, "password"));
  set("cred-us", credList(intel.wordlistUsers, "username"));
  set("bars-kind", barRows(intel.kindCounts));
  set("bars-playbook", barRows(intel.playbookCounts));
  set("bars-intent", barRows(intel.intentCounts));
  set("bars-source", barRows(intel.sourceCounts));
  set("actors-body", actorsTable(intel.actors));
  set("cmds-body", cmdsTable(intel.recentCommands));
  set("tl-feed", timelineRows(intel.timeline));
  set("mitre-grid", mitreCards(intel.mitre?.hits));
  set("sessions-list", sessionsList(intel.sessions));
  set("ttp-body", ttpTable(intel.ttp));
  set("payloads-body", payloadsTable(intel.payloads));
  set("tunnels-body", tunnelsTable(intel.tunnels));
  set("abuse-body", abuseTable(intel.abuseSuggest));
  set("ioc-body", iocTable(intel.ioc));
  set("deobf-list", deobfList(intel.deobf));
  set(
    "wl-preview",
    credList(
      [...(intel.wordlistUsers || []).slice(0, 5), ...(intel.wordlistPasswords || []).slice(0, 5)],
      "username"
    )
  );
  set(
    "graph-stats",
    `<div class="stat"><div class="n">${fmt(intel.graph?.nodes?.length)}</div><div class="l">nodes</div></div>
     <div class="stat"><div class="n">${fmt((intel.actors || []).length)}</div><div class="l">actors shown</div></div>
     <div class="stat"><div class="n">${fmt((intel.playbookCounts || []).length)}</div><div class="l">playbooks</div></div>`
  );
  set(
    "gauge-breakdown",
    `<div class="gb"><span>volume</span><b>${Math.min(25, Math.round((s.eventCount || 0) / 800))}</b></div>
     <div class="gb"><span>diversity</span><b>${Math.min(22, s.countries || 0)}</b></div>
     <div class="gb"><span>aggression</span><b>${Math.min(25, Math.round((intel.radar?.[0]?.rateHour || 0) / 8))}</b></div>
     <div class="gb"><span>weapons</span><b>${Math.min(20, Math.round((intel.actors?.[0]?.probeScore || 0) / 5))}</b></div>`
  );

  const canvas = document.getElementById("heatmap");
  if (canvas) drawHeatmap(canvas, intel.heatmap);

  // actor click → detail
  const detail = document.getElementById("actor-detail");
  const body = document.getElementById("actors-body");
  if (body && detail) {
    body.addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-actor]");
      if (!tr) return;
      const a = (intel.actors || []).find((x) => x.id === tr.getAttribute("data-actor"));
      if (!a) return;
      detail.hidden = false;
      document.getElementById("detail-title").textContent = a.ip;
      document.getElementById("detail-kv").innerHTML = [
        ["playbook", a.playbook],
        ["intent", a.intent],
        ["events", fmt(a.events)],
        ["probe", a.probeScore],
        ["client", a.sshClient],
        ["location", [a.city, a.country, a.cc].filter(Boolean).join(", ")],
        ["last", shortTime(a.lastSeen)],
        ["command", a.lastCommand || "—"],
      ]
        .map(([k, v]) => `<div><span>${k}</span><b>${esc(String(v ?? "—"))}</b></div>`)
        .join("");
    });
  }
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
