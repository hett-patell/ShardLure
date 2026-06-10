#!/usr/bin/env bash
# Pipe to VPS — avoids corrupted files on the remote.
# Usage: ssh arm 'bash -s' < scripts/vps-finish.sh
set -euo pipefail

cd "${HOME}/ShardLure/shardlure"

echo "[vps-finish] repairing corrupted text files"
python3 <<'PY'
from pathlib import Path

root = Path(".").resolve()
exts = {".go", ".mod", ".sum", ".py", ".sh", ".yaml", ".yml", ".md"}
names = {"go.mod", "go.sum", "Makefile"}
fixed = 0
for p in sorted(root.rglob("*")):
    if not p.is_file():
        continue
    if p.suffix not in exts and p.name not in names:
        continue
    b = p.read_bytes()
    if not b:
        continue
    if b"\x00" not in b and not b.startswith((b"\xff\xfe", b"\xfe\xff")):
        continue
    if b.startswith(b"\xff\xfe"):
        s = b[2:].decode("utf-16-le", errors="ignore")
    elif b.startswith(b"\xfe\xff"):
        s = b[2:].decode("utf-16-be", errors="ignore")
    else:
        s = b.replace(b"\x00", b"").decode("utf-8", errors="ignore")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if not s.endswith("\n"):
        s += "\n"
    p.write_text(s, encoding="utf-8", newline="\n")
    fixed += 1
    print("fixed", p.relative_to(root))
print(f"repaired {fixed} file(s)")
PY

cat > go.mod <<'GOMOD'
module github.com/networkshard/shardlure

go 1.22

require (
	github.com/charmbracelet/bubbles v0.20.0
	github.com/charmbracelet/bubbletea v1.2.4
	github.com/charmbracelet/lipgloss v1.0.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.34.5
)
GOMOD

go mod tidy
go build -o /tmp/shardlure ./cmd/shardlure
echo "built /tmp/shardlure ($(wc -c < /tmp/shardlure) bytes)"

sudo python3 <<'PY'
import os
import shutil
import subprocess
import sys
from pathlib import Path

DATA = Path("/var/lib/shardlure")
CONFIG = DATA / "shardlure.yaml"
COWRIE_HOME = DATA / "cowrie"
COWRIE_LOG = COWRIE_HOME / "var/log/cowrie/cowrie.json"
BIN = Path("/usr/local/bin/shardlure")
SYSTEMD = Path("/etc/systemd/system")
honeypot_port = int(os.environ.get("SHARDLURE_HONEYPOT_PORT", "22"))
admin_port = int(os.environ.get("SHARDLURE_ADMIN_PORT", "2222"))
dash_port = int(os.environ.get("SHARDLURE_DASH_PORT", "8080"))

admin_ips = []
if os.environ.get("SHARDLURE_ADMIN_IPS"):
    admin_ips.extend(x.strip() for x in os.environ["SHARDLURE_ADMIN_IPS"].split(",") if x.strip())
if shutil.which("tailscale"):
    cp = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, check=False)
    for line in (cp.stdout or "").splitlines():
        if line.strip():
            admin_ips.append(line.strip())
            break
admin_ips = list(dict.fromkeys(admin_ips))
if not admin_ips:
    # No admin IP could be determined (no SHARDLURE_ADMIN_IPS, no Tailscale).
    # An empty admin_ips list just means no IPs are exempted from the honeypot
    # accounting — that's a safe default. (Previously this fell back to a
    # hardcoded personal Tailscale IP, which was wrong for every other host.)
    print("warning: no admin IPs detected (set SHARDLURE_ADMIN_IPS to exempt your own IP)", file=sys.stderr)

DATA.mkdir(parents=True, exist_ok=True)
lines = [f"data_dir: {DATA}", "admin_ips:"] + [f"  - {ip}" for ip in admin_ips]
lines += [
    "ssh:", f"  admin_port: {admin_port}", f"  honeypot_port: {honeypot_port}",
    "dashboard:", f"  port: {dash_port}",
    "journal:", "  unit: ssh",
    "cowrie:", f"  home: {COWRIE_HOME}", f"  json_log: {COWRIE_LOG}",
    "geoip:", "  enabled: true", "  insecure_http: true",
    "capture:",
    "  enabled: true",
    f"  evidence_dir: {DATA / 'evidence'}",
    "  quarantine_fetch: true",
    "  max_bytes: 52428800",
    "  timeout_sec: 45",
]
CONFIG.write_text("\n".join(lines) + "\n")
shutil.copy2("/tmp/shardlure", BIN)
BIN.chmod(0o755)

cowrie_exec = f"/usr/bin/authbind --deep {COWRIE_HOME}/venv/bin/python3 {COWRIE_HOME}/bin/cowrie start -n"
(SYSTEMD / "cowrie.service").write_text(f"""[Unit]
Description=Cowrie SSH honeypot (ShardLure)
After=network.target
[Service]
Type=simple
User=cowrie
WorkingDirectory={COWRIE_HOME}
ExecStart={cowrie_exec}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
""")
(SYSTEMD / "shardlure-live.service").write_text(f"""[Unit]
Description=ShardLure live dashboard + telemetry ingest
After=network.target cowrie.service
Wants=cowrie.service
[Service]
Type=simple
Environment=SHARDLURE_CONFIG={CONFIG}
ExecStart={BIN} live :{dash_port} --tailscale --cowrie={COWRIE_LOG}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
""")
for cmd in (
    ["systemctl", "daemon-reload"],
    ["systemctl", "enable", "cowrie.service", "shardlure-live.service"],
    ["systemctl", "restart", "cowrie.service"],
    ["systemctl", "restart", "shardlure-live.service"],
):
    subprocess.run(cmd, check=True)
dash_host = admin_ips[0] if admin_ips else "127.0.0.1"
print("dashboard: http://%s:%d" % (dash_host, dash_port))
PY

systemctl is-active cowrie shardlure-live
