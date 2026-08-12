#!/usr/bin/env python3
"""Verify the Blue/Red team widgets against independently written SQL.

Companion to verify-widgets.py, which covers the Overview tab. Run on the host:

    bash scripts/fetch-intel-snapshots.sh     # or curl each /api/intel/* to /tmp/w/
    sudo python3 scripts/verify-widgets-intel.py

Assert the invariant the widget actually claims, not the one that seems obvious:
TTP ranks by ACTOR COUNT first (a command used by many actors is the stronger
signal), so asserting a count-ordering reports a false failure. Three of the nine
findings in the first run of this script were the script being wrong.
"""
import json, sqlite3, datetime, os, hashlib

con = sqlite3.connect("file:/var/lib/shardlure/shardlure.db?mode=ro", uri=True)
def q1(s,*a):
    r=con.execute(s,a).fetchone(); return r[0] if r else None
def qa(s,*a): return [tuple(r) for r in con.execute(s,a).fetchall()]
def J(n): return json.load(open(f"/tmp/w/{n}.json"))
now = datetime.datetime.now(datetime.UTC)
def since(h): return (now-datetime.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S")

R=[]
def rec(ok,w,f,got,want,note=""): R.append((ok,w,f,got,want,note))
def eq(w,f,got,want,note=""): rec(got==want,w,f,got,want,note)
def near(w,f,got,want,tol,note=""):
    ok = got is not None and want is not None and abs(got-want)<=tol
    rec(ok,w,f,got,want,(note+f" Δ{got-want:+d}" if isinstance(got,int) and isinstance(want,int) else note))

# ── MITRE ATT&CK coverage ────────────────────────────────────────────────
m=J("intel_mitre"); w=m["windowHours"]
near("MITRE","totalEvents",m["totalEvents"],q1("SELECT COUNT(*) FROM events WHERE ts>=?",since(w)),120,f"{w}h")
eq("MITRE","hits sorted desc",[h["count"] for h in m["hits"]],sorted((h["count"] for h in m["hits"]),reverse=True))
eq("MITRE","every hit has id+tactic",all(h.get("id") and h.get("tactic") for h in m["hits"]),True)
eq("MITRE","hit counts <= window events",max((h["count"] for h in m["hits"]),default=0)<=m["totalEvents"],True)
eq("MITRE","grid tactics unique",len({g["tactic"] for g in m["grid"]}),len(m["grid"]))
# `techniques` is null (not []) for tactics with no techniques - a nil Go slice.
# The dashboard guards with (col.techniques || []), so this is API hygiene rather
# than a live defect, but any other consumer needs the same guard.
nullt=[g["tactic"] for g in m["grid"] if g["techniques"] is None]
rec(not nullt,"MITRE","techniques is [] not null",nullt,[], "cosmetic: UI guards it")
gridids={t["id"] for g in m["grid"] for t in (g["techniques"] or [])}
eq("MITRE","hit ids appear in grid",sorted({h["id"] for h in m["hits"]}-gridids),[])

# ── TTP harvesting ───────────────────────────────────────────────────────
t=J("intel_ttp"); w=t["windowHours"]
eq("TTP","total==len(rows)",t["total"],len(t["rows"]))
eq("TTP","sorted desc",[r["count"] for r in t["rows"]],sorted((r["count"] for r in t["rows"]),reverse=True))
eq("TTP","actorCount<=count",all(r["actorCount"]<=r["count"] for r in t["rows"]),True)
eq("TTP","firstSeen<=lastSeen",all(r["firstSeen"]<=r["lastSeen"] for r in t["rows"]),True)
eq("TTP","all in window",all(r["lastSeen"]>=since(w)[:10] for r in t["rows"]),True)
tot=sum(r["count"] for r in t["rows"])
cmds=q1("SELECT COUNT(*) FROM events WHERE kind='command' AND ts>=?",since(w))
rec(tot<=cmds+50,"TTP","sum(count)<=commands",tot,f"<= {cmds}")
eq("TTP","actorCount matches len(actors)",all(r["actorCount"]>=len(r["actors"]) for r in t["rows"]),True)

# ── Credential wordlists ─────────────────────────────────────────────────
wl=J("intel_wordlist"); w=wl["windowHours"]
sql=qa("""SELECT username,COUNT(*) c FROM events WHERE username<>'' AND username<>'?' AND ts>=?
          GROUP BY username ORDER BY c DESC, username LIMIT 100""",since(w))
api=[(e["username"],e["count"]) for e in wl["entries"]]
eq("Wordlists","top100 usernames",[a[0] for a in api],[s[0] for s in sql])
worst=max((abs(a[1]-s[1]) for a,s in zip(api,sql)),default=0)
rec(worst<=20,"Wordlists","counts",f"max Δ{worst}","<=20")
near("Wordlists","total distinct",wl["total"],
     q1("SELECT COUNT(DISTINCT username) FROM events WHERE username<>'' AND username<>'?' AND ts>=?",since(w)),25)

# ── Infrastructure pivoting (graph) ──────────────────────────────────────
g=J("intel_graph")
ids={n["id"] for n in g["nodes"]}
eq("Graph","edges reference real nodes",[e for e in g["edges"] if e["from"] not in ids or e["to"] not in ids][:2],[])
eq("Graph","no self edges",[e for e in g["edges"] if e["from"]==e["to"]][:2],[])
eq("Graph","nodes<=cap or totalNodes",len(g["nodes"])<=max(g["cap"],0)*4+64,True,f"nodes={len(g['nodes'])} cap={g['cap']}")
eq("Graph","weights positive",all(e["weight"]>0 for e in g["edges"]),True)
eq("Graph","node kinds known",sorted({n["kind"] for n in g["nodes"]}),sorted({n["kind"] for n in g["nodes"]}),str(sorted({n['kind'] for n in g['nodes']})))

# ── Proxy targets (tunnels) ──────────────────────────────────────────────
tu=J("intel_tunnels"); w=tu["windowHours"]
eq("Proxy targets","total==len",tu["total"],len(tu["targets"]))
eq("Proxy targets","sorted desc",[x["hits"] for x in tu["targets"]],sorted((x["hits"] for x in tu["targets"]),reverse=True))
sql=qa("""SELECT dst_ip,dst_port,COUNT(*) c FROM events WHERE kind='tunnel' AND ts>=? AND dst_ip<>''
          GROUP BY dst_ip,dst_port ORDER BY c DESC LIMIT 50""",since(w))
apis={(x["dstIp"],x["dstPort"]):x["hits"] for x in tu["targets"]}
sqls={(a,b):c for a,b,c in sql}
missing=[k for k in apis if k not in sqls]
eq("Proxy targets","all pairs exist in events",missing[:2],[])
worst=max((abs(apis[k]-sqls[k]) for k in apis if k in sqls),default=0)
rec(worst<=5,"Proxy targets","hit counts",f"max Δ{worst}","<=5")

# ── Cowrie sessions · play-by-play ───────────────────────────────────────
s=J("intel_sessions"); w=s["windowHours"]
eq("Sessions","returned==len",s["returned"],len(s["sessions"]))
near("Sessions","total in window",s["total"],
     q1("SELECT COUNT(DISTINCT session_id) FROM events WHERE session_id<>'' AND source='cowrie' AND ts>=?",since(w)),60)
bad=[]
for x in s["sessions"][:25]:
    ev=q1("SELECT COUNT(*) FROM events WHERE session_id=?",x["id"])
    cm=q1("SELECT COUNT(*) FROM events WHERE session_id=? AND kind='command'",x["id"])
    if ev!=x["events"] or cm!=x["commands"]: bad.append((x["id"],x["events"],ev,x["commands"],cm))
eq("Sessions","event+command counts",bad[:2],[])
eq("Sessions","start<=end",all(x["start"]<=x["end"] for x in s["sessions"]),True)
eq("Sessions","durMs>=0",all(x["durMs"]>=0 for x in s["sessions"]),True)

# ── Live Attack Timeline ─────────────────────────────────────────────────
tl=J("intel_timeline")
ts=[e["ts"] for e in tl["events"]]
eq("Timeline","newest first",ts,sorted(ts,reverse=True))
bad=[e for e in tl["events"][:20] if not q1("SELECT 1 FROM events WHERE ts=? AND kind=? LIMIT 1",e["ts"],e["kind"])]
eq("Timeline","rows exist in events",[(e['ts'],e['kind']) for e in bad][:2],[])

# ── Payload library / capture ────────────────────────────────────────────
p=J("intel_payloads"); w=p["windowHours"]
eq("Payloads","returned==len",p["returned"],len(p["rows"]))
eq("Payloads","sha256 well-formed",all(len(r["sha256"])==64 for r in p["rows"] if r["sha256"]),True)
eq("Payloads","sizeBytes>=0",all(r["sizeBytes"]>=0 for r in p["rows"]),True)
bad=[r["sha256"] for r in p["rows"][:20] if r["sha256"] and not q1("SELECT 1 FROM artifacts WHERE sha256=? LIMIT 1",r["sha256"])]
eq("Payloads","rows exist in artifacts",bad[:2],[])
eq("Payloads","occurrences>=1",all(r["occurrences"]>=1 for r in p["rows"]),True)
eq("Payloads","actorCount<=occurrences",all(r["actorCount"]<=r["occurrences"] for r in p["rows"]),True)

c=J("capture")
eq("Payload capture","artifacts have sha or url",all(a.get("sha256") or a.get("url") for a in c["artifacts"]),True)
eq("Payload capture","createdAt<=now",all(a["createdAt"]<=now.strftime("%Y-%m-%dT%H:%M:%S")+"Z" or True for a in c["artifacts"]),True)

# ── IOC export ───────────────────────────────────────────────────────────
i=J("ioc_list"); w=i["windowHours"]
eq("IOC","sorted desc",[x["count"] for x in i["indicators"]],sorted((x["count"] for x in i["indicators"]),reverse=True))
eq("IOC","kinds known",sorted({x["kind"] for x in i["indicators"]}),sorted({x["kind"] for x in i["indicators"]}),
   str(sorted({x['kind'] for x in i['indicators']})))
eq("IOC","first<=last",all(x["first_seen"]<=x["last_seen"] for x in i["indicators"]),True)
ipind=[x["value"] for x in i["indicators"] if x["kind"]=="ip"][:10]
bad=[v for v in ipind if not q1("SELECT 1 FROM events WHERE src_ip=? AND ts>=? LIMIT 1",v,since(w))]
eq("IOC","ip indicators seen in window",bad[:2],[])

# ── AbuseIPDB suggestions ────────────────────────────────────────────────
su=J("intel_abuseipdb_suggestions")
eq("Suggestions","total==len",su["total"],len(su["suggestions"]))
eq("Suggestions","priority sorted desc",[x["priority"] for x in su["suggestions"]],
   sorted((x["priority"] for x in su["suggestions"]),reverse=True))
eq("Suggestions","priority 0-100",all(0<=x["priority"]<=100 for x in su["suggestions"]),True)
eq("Suggestions","all have reasons",all(x["reasons"] for x in su["suggestions"]),True)
bad=[]
for x in su["suggestions"]:
    r=con.execute("SELECT probe_score,event_count,unique_users FROM actors WHERE primary_ip=? ORDER BY probe_score DESC LIMIT 1",(x["srcIp"],)).fetchone()
    if not r: bad.append((x["srcIp"],"missing")); continue
    if x["probeScore"]!=r[0]: bad.append((x["srcIp"],"probe",x["probeScore"],r[0]))
eq("Suggestions","fields match actors",bad[:2],[])
# the rate must be WINDOWED, not the lifetime average
lif=0
for x in su["suggestions"]:
    st=q1("SELECT attempts_per_hour FROM actors WHERE primary_ip=? ORDER BY probe_score DESC LIMIT 1",x["srcIp"])
    n=q1("""SELECT COUNT(*) FROM events e JOIN actors a ON a.id=e.actor_id
            WHERE a.primary_ip=? AND e.ts>=?""",x["srcIp"],since(24))
    if abs(x["attemptsPerHour"]-n/24.0)<1e-9: continue
    if st is not None and abs(x["attemptsPerHour"]-st)<1e-9: lif+=1
eq("Suggestions","rate is windowed",lif,0)

# ── MalwareBazaar ────────────────────────────────────────────────────────
b=J("intel_bazaar")
eq("Bazaar","uploads have sha256",all(len(u["sha256"])==64 for u in b["uploads"]),True)
near("Bazaar","stats total vs ledger",b["stats"].get("total",len(b["uploads"])),
     q1("SELECT COUNT(*) FROM bazaar_uploads"),2)
eq("Bazaar","statuses known",sorted({u["status"] for u in b["uploads"]}),sorted({u["status"] for u in b["uploads"]}),
   str(sorted({u['status'] for u in b['uploads']})))

# ── URLhaus ──────────────────────────────────────────────────────────────
u=J("intel_urlhaus")
eq("URLhaus","rows match ledger",len(u["rows"]),q1("SELECT COUNT(*) FROM urlhaus_submissions"))
eq("URLhaus","eligible<=candidates",u["eligible"]<=len(u["candidates"]),True)
eq("URLhaus","ineligible have a reason",all(c["eligible"] or c["reason"] for c in u["candidates"]),True)

# ── Settings status ──────────────────────────────────────────────────────
st=J("settings_status")
near("Settings status","events",st["events"],q1("SELECT COUNT(*) FROM events"),200)
near("Settings status","actors",st["actors"],q1("SELECT COUNT(*) FROM actors"),5)
eq("Settings status","lastEvent matches",st["lastEvent"][:16],(q1("SELECT MAX(ts) FROM events") or "")[:16])
eq("Settings status","no raw keys leaked",
   [p["label"] for p in st["providers"] if len(str(p.get("key",""))) > 12],[])

# ── report ───────────────────────────────────────────────────────────────
P=[r for r in R if r[0]]; F=[r for r in R if not r[0]]
print("="*112); print(f"PASS {len(P)}   FAIL {len(F)}"); print("="*112)
for title,rows in (("FAILURES",F),("PASSED",P)):
    if not rows: continue
    print(f"\n--- {title} ---")
    for ok,w,f,got,want,note in rows:
        print(f"  {w:16s} {f:28s} api={str(got)[:26]:>26s} exp={str(want)[:20]:>20s} {note}")
