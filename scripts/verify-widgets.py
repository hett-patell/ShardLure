#!/usr/bin/env python3
"""Cross-check every dashboard widget against independent SQL ground truth.

Run ON the honeypot host, where the DB and the API are both reachable:

    curl -s localhost:8080/api/dashboard -o /tmp/d.json
    curl -s localhost:8080/api/intel     -o /tmp/i.json
    sudo python3 scripts/verify-widgets.py

Every widget number is recomputed from `events`/`actors` with a query written
independently of the application's own, so an agreeing pair is real evidence
rather than the same bug read twice. It exists because a whole class of defect
here is invisible to tests, vet and staticcheck: correct code computing the wrong
quantity. The threat gauge sat frozen at 52 for months, and the Brute-Force Radar
listed eight attackers that had been silent for weeks - both passing every test.


Live ingest means the API snapshot and the SQL query cannot be simultaneous, so
monotonic counters are compared with a drift allowance; the DELTA is printed so
drift can never be mistaken for agreement. Label SETS are compared exactly -
those cannot drift - while their counts get the same allowance.
"""
import json, sqlite3, datetime

DRIFT = 60          # events/sec * a few seconds of snapshot skew
con = sqlite3.connect("file:/var/lib/shardlure/shardlure.db?mode=ro", uri=True)
def q1(sql, *a):
    r = con.execute(sql, a).fetchone(); return r[0] if r else None
def qa(sql, *a): return [tuple(r) for r in con.execute(sql, a).fetchall()]

dash = json.load(open("/tmp/d.json")); intel = json.load(open("/tmp/i.json"))
R = []
def rec(ok, widget, field, got, want, note=""):
    R.append((ok, widget, field, got, want, note))
def num(widget, field, got, want, tol=DRIFT, note=""):
    ok = got is not None and want is not None and abs(got - want) <= tol
    d = "" if got is None or want is None else f"Δ{got-want:+d}"
    rec(ok, widget, field, got, want, (note + " " + d).strip())
def exact(widget, field, got, want, note=""):
    rec(got == want, widget, field, got, want, note)
def labels(widget, field, api_pairs, sql_pairs):
    a, s = dict(api_pairs), dict(sql_pairs)
    if set(a) != set(s):
        rec(False, widget, field + " labels", sorted(set(a)^set(s)), "identical sets", "")
        return
    worst = max((abs(a[k]-s[k]) for k in a), default=0)
    rec(worst <= DRIFT, widget, field, f"{len(a)} labels", "match", f"max Δ{worst}")

now = datetime.datetime.now(datetime.UTC)
since = (now - datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")

# ── Summary ───────────────────────────────────────────────────────────────
s = dash["summary"]
num("Summary", "eventCount", s["eventCount"], q1("SELECT COUNT(*) FROM events"))
num("Summary", "actorCount", s["actorCount"], q1("SELECT COUNT(*) FROM actors"), tol=5)
num("Summary", "uniqueIps", s["uniqueIps"], q1("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip<>''"), tol=5)
num("Summary", "sessionCount", s["sessionCount"], q1("SELECT COUNT(DISTINCT session_id) FROM events WHERE session_id<>''"))
exact("Summary", "countries", s["countries"], q1("""SELECT COUNT(DISTINCT json_extract(payload,'$.cc')) FROM ip_enrichment
      WHERE source='geo' AND json_extract(payload,'$.ok')=1 AND COALESCE(json_extract(payload,'$.cc'),'')<>''"""))
# EVENT-weighted by design (server.go:208) - not actor-weighted.
num("Summary", "fingerprintTotal", s["fingerprintTotal"],
    q1("SELECT COUNT(*) FROM events WHERE source='cowrie'"))
num("Summary", "fingerprinted", s["fingerprinted"],
    q1("SELECT COUNT(*) FROM events WHERE source='cowrie' AND COALESCE(hassh,'')<>''"))

# ── Honeypot ─────────────────────────────────────────────────────────────
exact("Honeypot", "cowrieUptime present", s.get("cowrieUptimeSeconds") is not None, True)
exact("Honeypot", "cowrieUptime >= 0", (s.get("cowrieUptimeSeconds") or -1) >= 0, True)

# ── Top source IPs ───────────────────────────────────────────────────────
api = [r["ip"] for r in dash["topIps"][:10]]
sql = [r[0] for r in qa("SELECT src_ip FROM events WHERE src_ip<>'' GROUP BY src_ip ORDER BY COUNT(*) DESC, src_ip LIMIT 10")]
exact("Top source IPs", "top10 ordering", api, sql)
labels("Top source IPs", "hits", [(r["ip"], r["hits"]) for r in dash["topIps"][:10]],
       qa("SELECT src_ip, COUNT(*) FROM events WHERE src_ip<>'' GROUP BY src_ip ORDER BY COUNT(*) DESC, src_ip LIMIT 10"))

# ── Top credentials ──────────────────────────────────────────────────────
labels("Top Credentials", "user hits", [(r["user"], r["hits"]) for r in dash["topUsers"][:10]],
       qa("""SELECT username, COUNT(*) FROM events WHERE username<>'' AND username<>'?'
             GROUP BY username ORDER BY COUNT(*) DESC, username LIMIT 10"""))

# ── Top commands ─────────────────────────────────────────────────────────
labels("Top commands", "cmd hits", [(r["command"], r["hits"]) for r in dash["topCommands"][:10]],
       qa("""SELECT command, COUNT(*) FROM events WHERE command<>''
             GROUP BY command ORDER BY COUNT(*) DESC, command LIMIT 10"""))

# ── Event kinds / Playbooks / Intent / Sources ────────────────────────────
labels("Event kinds", "kind counts", [(r["label"], r["hits"]) for r in intel["kindCounts"]],
       qa("SELECT kind, COUNT(*) FROM events GROUP BY kind"))
# Playbooks/Intent count ACTORS; Sources counts EVENTS (CountsBySource).
for widget, key, col in [("Playbooks","playbookCounts","playbook"),
                          ("Intent","intentCounts","intent")]:
    labels(widget, f"{col} counts", [(r["label"], r["hits"]) for r in intel[key]],
           qa(f"SELECT {col}, COUNT(*) FROM actors WHERE {col}<>'' GROUP BY {col}"))
labels("Sources", "source counts", [(r["label"], r["hits"]) for r in intel["sourceCounts"]],
       qa("SELECT source, COUNT(*) FROM events GROUP BY source"))

# ── Events/hour + heatmap ────────────────────────────────────────────────
# Per-BUCKET comparison, excluding the oldest (partial by design: the cutoff is
# an exact timestamp, not an hour boundary) and newest (still filling) buckets.
for widget, cells, kindful in [("Events/hour (72h)", dash["hourly"], False),
                                ("Activity heatmap", intel["heatmap"], True)]:
    edge = {min(c["t"] for c in cells), max(c["t"] for c in cells)}
    if kindful:
        truth = {(h, k): n for h, k, n in con.execute(
            "SELECT substr(ts,1,13),kind,COUNT(*) FROM events WHERE ts>=? GROUP BY 1,2",
            ((now - datetime.timedelta(hours=73)).strftime("%Y-%m-%dT%H:%M:%S"),))}
        key = lambda c: (datetime.datetime.fromtimestamp(c["t"], datetime.UTC).strftime("%Y-%m-%dT%H"), c["kind"])
    else:
        truth = {h: n for h, n in con.execute(
            "SELECT substr(ts,1,13),COUNT(*) FROM events WHERE ts>=? GROUP BY 1",
            ((now - datetime.timedelta(hours=73)).strftime("%Y-%m-%dT%H:%M:%S"),))}
        key = lambda c: datetime.datetime.fromtimestamp(c["t"], datetime.UTC).strftime("%Y-%m-%dT%H")
    bad = [key(c) for c in cells if c["t"] not in edge and abs(truth.get(key(c), -1) - c["n"]) > 3]
    exact(widget, f"{len(cells)} buckets match", bad, [], note="edges excluded")

# ── Threat gauge ─────────────────────────────────────────────────────────
t = dash["threat"]
num("Threat Level", "window events", t["events"], q1("SELECT COUNT(*) FROM events WHERE ts>=?", since))
num("Threat Level", "window uniqueIps", t["uniqueIps"],
    q1("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=?", since), tol=10)
comp = {c["key"]: c["raw"] for c in t["components"]}
num("Threat Level", "raw volume", comp["volume"], q1("SELECT COUNT(*) FROM events WHERE ts>=?", since))
num("Threat Level", "raw diversity", comp["diversity"],
    q1("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=?", since), tol=10)
num("Threat Level", "raw intrusion", comp["intrusion"],
    q1("SELECT COUNT(*) FROM events WHERE kind='accepted' AND ts>=?", since), tol=20)
num("Threat Level", "raw weaponization", comp["weaponization"],
    q1("SELECT COUNT(*) FROM events WHERE kind='command' AND ts>=?", since)
    + 3*q1("SELECT COUNT(*) FROM events WHERE kind IN ('file_download','file_upload') AND ts>=?", since), tol=30)
exact("Threat Level", "dashboard==intel block", dash["threat"], intel["threat"])

# ── Brute-Force Radar ────────────────────────────────────────────────────
dead, wrong = [], []
for r in intel["radar"]:
    n = q1("""SELECT COUNT(*) FROM events e JOIN actors a ON a.id=e.actor_id
              WHERE a.primary_ip=? AND e.ts>=?""", r["ip"], since)
    if not n: dead.append(r["ip"])
    elif abs(r["rateHour"] - n/24.0) > 2: wrong.append((r["ip"], round(r["rateHour"],1), round(n/24.0,1)))
exact("Brute-Force Radar", "all currently active", dead, [])
exact("Brute-Force Radar", "rate matches window", wrong, [])
exact("Brute-Force Radar", "ordered desc",
      [r["rateHour"] for r in intel["radar"]], sorted((r["rateHour"] for r in intel["radar"]), reverse=True))

# ── Attack geography ─────────────────────────────────────────────────────
g = intel["topCountries"]
exact("Attack Geography", "ordered desc", [r["hits"] for r in g], sorted((r["hits"] for r in g), reverse=True))
exact("Attack Geography", "all have cc", all(r.get("cc") for r in g), True)
tot = q1("SELECT COUNT(*) FROM events")
rec(sum(r["hits"] for r in g) <= tot, "Attack Geography", "sum <= events",
    sum(r["hits"] for r in g), f"<= {tot}")

# ── Sessions ─────────────────────────────────────────────────────────────
ss = dash["sessions"]
exact("Cowrie sessions", "all have cmdCount>0", all(x.get("cmdCount",0) > 0 for x in ss), True)
bad = []
for x in ss[:10]:
    n = q1("SELECT COUNT(*) FROM events WHERE session_id=? AND kind='command'", x["id"])
    if n != x["cmdCount"]: bad.append((x["id"], x["cmdCount"], n))
exact("Cowrie sessions", "cmdCount matches events", bad, [])

# ── Threat actors table ──────────────────────────────────────────────────
bad = []
for a in intel["actors"][:25]:
    row = con.execute("SELECT event_count, probe_score, attempts_per_hour FROM actors WHERE id=?", (a["id"],)).fetchone()
    if not row: bad.append((a["id"], "missing")); continue
    if abs(row[0]-a["events"]) > DRIFT: bad.append((a["id"], "events", a["events"], row[0]))
    if row[1] != a["probeScore"]: bad.append((a["id"], "probeScore", a["probeScore"], row[1]))
exact("Threat actors", "fields match actors row", bad, [])

# ── rateHour semantics (what the actor tables/chips display) ─────────────
# A low-volume actor's lifetime and windowed rates can land within a loose
# tolerance of each other (2 events over 55h vs 1 event in 24h differ by 0.0056),
# so "matches lifetime" only counts when it does NOT also match the windowed
# value. Without that, the check reports false positives.
lifetime, windowed = 0, 0
for a in intel["actors"][:40]:
    stored = q1("SELECT attempts_per_hour FROM actors WHERE id=?", a["id"])
    n = q1("SELECT COUNT(*) FROM events WHERE actor_id=? AND ts>=?", a["id"], since)
    isw = abs(a["rateHour"] - n/24.0) < 1e-9
    if isw: windowed += 1
    elif stored is not None and abs(a["rateHour"] - stored) < 1e-9: lifetime += 1
rec(lifetime == 0, "Threat actors", "rateHour is windowed",
    f"{lifetime}/40 lifetime", "0 lifetime", f"{windowed}/40 verified windowed")

# ── report ───────────────────────────────────────────────────────────────
p = [r for r in R if r[0]]; f = [r for r in R if not r[0]]
print("="*110); print(f"PASS {len(p)}   FAIL {len(f)}"); print("="*110)
for title, rows in (("FAILURES", f), ("PASSED", p)):
    if not rows: continue
    print(f"\n--- {title} ---")
    for ok, w, fl, got, want, note in rows:
        print(f"  {w:24s} {fl:26s} api={str(got)[:24]:>24s} sql={str(want)[:22]:>22s} {note}")
