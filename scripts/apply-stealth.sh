#!/usr/bin/env bash
# Apply ShardLure stealth persona to Cowrie — run on VPS or pipe: ssh arm 'bash -s' < scripts/apply-stealth.sh
set -euo pipefail

COWRIE_HOME="${COWRIE_HOME:-/var/lib/shardlure/cowrie}"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo ".")"
PERSONA="${PERSONA_DIR:-${SCRIPT_DIR}/../install/persona}"
if [[ ! -d "$PERSONA" && -d "${HOME}/ShardLure/shardlure/install/persona" ]]; then
  PERSONA="${HOME}/ShardLure/shardlure/install/persona"
fi

echo "[stealth] cowrie=$COWRIE_HOME persona=$PERSONA"

# --- honeyfs persona (looks like a boring prod Ubuntu box) ---
if [[ -d "$PERSONA/honeyfs" ]]; then
  echo "[stealth] syncing honeyfs persona"
  sudo rsync -a "$PERSONA/honeyfs/" "$COWRIE_HOME/honeyfs/"
else
  echo "[stealth] inline honeyfs (persona dir missing)"
  sudo mkdir -p "$COWRIE_HOME/honeyfs/etc" "$COWRIE_HOME/honeyfs/proc"
  echo 'prod-app-server-01' | sudo tee "$COWRIE_HOME/honeyfs/etc/hostname" >/dev/null
  echo 'Ubuntu 22.04.4 LTS' | sudo tee "$COWRIE_HOME/honeyfs/etc/issue.net" >/dev/null
fi

# --- txtcmds: realistic command output stubs (anti-fingerprinting) ---
if [[ -d "$PERSONA/txtcmds" ]]; then
  echo "[stealth] syncing txtcmds persona (anti-fingerprint stubs)"
  TXTCMDS_DST="$COWRIE_HOME/share/cowrie/txtcmds"
  sudo mkdir -p "$TXTCMDS_DST"
  sudo rsync -a "$PERSONA/txtcmds/" "$TXTCMDS_DST/"
else
  echo "[stealth] no txtcmds dir in persona — skipping"
fi

# --- time persona: regenerate time-sensitive files against the live clock ---
# Frozen uptime/last/who + /proc/uptime are a honeypot tell vs Cowrie's live
# `date`. Runs AFTER the txtcmds rsync so it overwrites the just-synced stubs.
if [[ -f "$PERSONA/gen-time-persona.py" ]]; then
  echo "[stealth] refreshing time-sensitive persona against live clock"
  sudo python3 "$PERSONA/gen-time-persona.py" "$COWRIE_HOME" \
    || echo "[stealth] WARN: time-persona generator failed; time files may be stale (fingerprintable)"
fi

# --- userdb: realistic weak creds, no *:* honeypot catch-alls ---
if [[ -f "$PERSONA/userdb.txt" ]]; then
  sudo cp "$PERSONA/userdb.txt" "$COWRIE_HOME/etc/userdb.txt"
else
  sudo tee "$COWRIE_HOME/etc/userdb.txt" >/dev/null <<'EOF'
root:x:root
root:x:123456
ubuntu:x:ubuntu
admin:x:admin
deploy:x:deploy
oracle:x:oracle
EOF
fi
sudo chown cowrie:cowrie "$COWRIE_HOME/etc/userdb.txt"

# --- cowrie.cfg: consistent banner, kernel, hostname; hide sensor name ---
sudo python3 <<PY
from pathlib import Path

cowrie_home = Path("${COWRIE_HOME}")
cfg_path = cowrie_home / "etc/cowrie.cfg"
persona_cfg = Path("${PERSONA}") / "cowrie-stealth.cfg"

stealth = persona_cfg.read_text() if persona_cfg.exists() else """
[honeypot]
hostname = prod-app-server-01
sensor_name = prod-app-server-01

[shell]
arch = linux-x64-lsb
kernel_name = Linux
kernel_version = 5.15.0-94-generic
kernel_build_string = #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_8.9p1 Ubuntu-3ubuntu0.6, OpenSSL 3.0.2 15 Mar 2022

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
"""

def parse_ini(text):
    sections = {}
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            cur = s.lower()
            sections.setdefault(cur, {})
            continue
        if cur and "=" in s:
            k, v = s.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections

def merge(base_text, overlay_text):
    base = parse_ini(base_text)
    over = parse_ini(overlay_text)
    for sec, kv in over.items():
        base.setdefault(sec, {}).update(kv)
    base.setdefault("[ssh]", {})["listen_endpoints"] = "tcp:22:interface=0.0.0.0"
    base.setdefault("[honeypot]", {})
    for k in ("log_path", "data_path", "download_path"):
        if k not in base["[honeypot]"]:
            default = {
                "log_path": str(cowrie_home / "var/log/cowrie"),
                "data_path": str(cowrie_home / "var/lib/cowrie"),
                "download_path": str(cowrie_home / "var/lib/cowrie/downloads"),
            }[k]
            base["[honeypot]"][k] = default
    base.setdefault("[output_jsonlog]", {})
    base["[output_jsonlog]"].setdefault("enabled", "true")
    base["[output_jsonlog]"].setdefault("logfile", str(cowrie_home / "var/log/cowrie/cowrie.json"))
    lines = []
    for sec, kv in base.items():
        lines.append(sec)
        for k, v in kv.items():
            lines.append(f"{k} = {v}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

existing = cfg_path.read_text() if cfg_path.exists() else ""
cfg_path.write_text(merge(existing, stealth))
print("wrote", cfg_path)
PY

# --- fresh SSH host keys (default Cowrie keys are in threat-intel feeds) ---
echo "[stealth] regenerating SSH host keys"
KEYDIR="$COWRIE_HOME/var/lib/cowrie"
sudo mkdir -p "$KEYDIR"
sudo rm -f "$KEYDIR"/ssh_host_*key "$KEYDIR"/ssh_host_*key.pub
sudo ssh-keygen -t ed25519 -f "$KEYDIR/ssh_host_ed25519_key" -N "" -q
sudo ssh-keygen -t ecdsa -f "$KEYDIR/ssh_host_ecdsa_key" -N "" -q
sudo ssh-keygen -t rsa -b 4096 -f "$KEYDIR/ssh_host_rsa_key" -N "" -q
sudo chown cowrie:cowrie "$KEYDIR"/ssh_host_*key "$KEYDIR"/ssh_host_*key.pub 2>/dev/null || true
sudo chmod 600 "$KEYDIR"/ssh_host_*key

sudo chown -R cowrie:cowrie "$COWRIE_HOME/honeyfs" "$COWRIE_HOME/etc" "$COWRIE_HOME/var"

# --- Cowrie source patches (anti-fingerprint shell fixes) ---
ORCHESTRATOR="$PERSONA/apply-patches.py"
if [[ ! -f "$ORCHESTRATOR" ]]; then
  echo "[stealth] ERROR: Cowrie patch orchestrator missing: $ORCHESTRATOR" >&2
  exit 1
fi
echo "[stealth] preflighting and applying Cowrie source patches"
sudo python3 "$ORCHESTRATOR" "$COWRIE_HOME"

echo "[stealth] restart cowrie"
sudo systemctl restart cowrie
sleep 2
systemctl is-active cowrie
echo "[stealth] done — prod-app-server-01 persona active"
echo "  test: ssh -p 22 root@127.0.0.1  (password: root)"
echo "  dashboard should stay on tailscale only (block public 8080 in Oracle NSG)"
