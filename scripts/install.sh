#!/usr/bin/env bash
set -euo pipefail

# ShardLure installer — detects host arch, downloads the right binary
# from GitHub releases, and sets up systemd services.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/hett-patell/ShardLure/main/scripts/install.sh | bash -s -- [options]
#
# Options:
#   --tag v1            Release tag (default: latest, detected via GitHub API)
#   --no-cowrie         Skip cowrie honeypot installation
#   --cowrie-branch BR  Branch/tag to clone cowrie from (default: auto-detect
#                       remote HEAD, falling back to main then master)
#   --honeypot-port 22  SSH port for the honeypot listener (default: 2222, admin SSH stays on 22)
#   --dash-port 8080    Dashboard port (default: 8080)
#   --data-dir /var/lib/shardlure  Data directory (default: /var/lib/shardlure)
#   --token TOKEN       Dashboard auth token (SHARDLURE_DASH_TOKEN env var)

REPO="hett-patell/ShardLure"
TAG="${TAG:-}"
COWRIE="${COWRIE:-1}"
COWRIE_BRANCH="${COWRIE_BRANCH:-}"
HONEYPOT_PORT="${HONEYPOT_PORT:-2222}"
ADMIN_PORT="${ADMIN_PORT:-22}"
DASH_PORT="${DASH_PORT:-8080}"
DATA_DIR="${DATA_DIR:-/var/lib/shardlure}"
DASH_TOKEN="${DASH_TOKEN:-}"

ABIN="shardlure-linux-amd64"
declare -A ARCH_MAP
ARCH_MAP[x86_64]=$ABIN
ARCH_MAP[amd64]=$ABIN
ARCH_MAP[aarch64]=shardlure-linux-arm64
ARCH_MAP[arm64]=shardlure-linux-arm64

log() { printf '\033[1;36m[shardlure-install]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[shardlure-install]\033[0m %s\n' "$*" >&2; exit 1; }

# -- parse CLI overrides --------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)          TAG="$2"; shift 2 ;;
    --no-cowrie)    COWRIE=0; shift ;;
    --cowrie-branch) COWRIE_BRANCH="$2"; shift 2 ;;
    --honeypot-port) HONEYPOT_PORT="$2"; shift 2 ;;
    --dash-port)    DASH_PORT="$2"; shift 2 ;;
    --data-dir)     DATA_DIR="$2"; shift 2 ;;
    --token)        DASH_TOKEN="$2"; shift 2 ;;
    *)              err "unknown option: $1" ;;
  esac
done

if [[ $(id -u) -ne 0 ]]; then
  err "must run as root (use sudo or pipe to sudo bash)"
fi

# -- architecture detection ------------------------------------------------
ARCH=$(uname -m)
BIN_NAME="${ARCH_MAP[$ARCH]:-}"
if [[ -z "$BIN_NAME" ]]; then
  err "unsupported architecture: $ARCH (supported: x86_64, aarch64)"
fi
log "detected architecture: $ARCH → $BIN_NAME"

# -- tag resolution --------------------------------------------------------
if [[ -z "$TAG" ]]; then
  log "resolving latest release tag…"
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | grep -Po '"tag_name": *"\K[^"]+' || true)
  if [[ -z "$TAG" ]]; then
    err "could not resolve latest tag from GitHub API (network issue or no releases). Pass --tag explicitly."
  fi
fi
log "release: $TAG"

# -- download binary -------------------------------------------------------
URL="https://github.com/$REPO/releases/download/$TAG/$BIN_NAME"
DEST="/usr/local/bin/shardlure"
log "downloading $URL …"
curl -fsSL "$URL" -o /tmp/shardlure-dl 2>/tmp/shardlure-curl.err
if [[ $? -ne 0 || ! -s /tmp/shardlure-dl ]]; then
  err "download failed (URL: $URL). $(cat /tmp/shardlure-curl.err 2>/dev/null || true)"
fi

# Download the checksum manifest and verify the binary before installing
# as root. If the checksum file is missing (e.g. manually cut release
# without CI), print a warning but continue — better than blocking a
# deployment. If it exists, enforce a strict match.
CHKSUM_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"
curl -fsSL "$CHKSUM_URL" -o /tmp/shardlure-sums 2>/dev/null
if [[ -s /tmp/shardlure-sums ]]; then
  # Anchor the match: line must END with two spaces + exact BIN_NAME so a
  # release that ships e.g. shardlure-linux-arm64 alongside
  # shardlure-linux-arm64-musl can't accidentally match the wrong row.
  expected=$(grep -F "  $BIN_NAME" /tmp/shardlure-sums | awk -v b="$BIN_NAME" '$2==b {print $1}' | head -1)
  actual=$(sha256sum /tmp/shardlure-dl | awk '{print $1}')
  if [[ -z "$expected" ]]; then
    rm -f /tmp/shardlure-sums
    log "WARNING: no checksum entry for $BIN_NAME in SHA256SUMS — binary not verified"
  elif [[ "$expected" != "$actual" ]]; then
    err "checksum mismatch for $BIN_NAME. Expected: $expected, got: $actual. Do not proceed — the binary may be tampered."
  else
    log "checksum verified: $BIN_NAME ($actual)"
  fi
  rm -f /tmp/shardlure-sums
else
  log "WARNING: SHA256SUMS not found at $CHKSUM_URL — binary not verified"
fi

chmod +x /tmp/shardlure-dl
install -m 755 /tmp/shardlure-dl "$DEST"
rm -f /tmp/shardlure-dl /tmp/shardlure-curl.err
log "installed $DEST ($(wc -c < "$DEST") bytes)"

# -- config ----------------------------------------------------------------
mkdir -p "$DATA_DIR" "$DATA_DIR/captures" "$DATA_DIR/evidence" "$DATA_DIR/payloads"

# Detect tailscale IP for admin_ips
ADMIN_IPS=""
if command -v tailscale &>/dev/null; then
  TSIP=$(tailscale ip -4 2>/dev/null | head -1 || true)
  if [[ -n "$TSIP" ]]; then
    ADMIN_IPS="$TSIP"
    log "detected tailscale IP: $TSIP"
  fi
fi
if [[ -z "$ADMIN_IPS" ]]; then
  ADMIN_IPS="127.0.0.1"
fi

cat > "$DATA_DIR/shardlure.yaml" <<YAML
data_dir: $DATA_DIR
admin_ips:
  - $ADMIN_IPS
ssh:
  admin_port: $ADMIN_PORT
  honeypot_port: $HONEYPOT_PORT
dashboard:
  port: $DASH_PORT
  home_lat: 19.0760
  home_lon: 72.8777
  home_city: Mumbai
  home_country: India
  home_cc: IN
journal:
  unit: ssh
cowrie:
  home: $DATA_DIR/cowrie
  json_log: $DATA_DIR/cowrie/var/log/cowrie/cowrie.json
capture:
  enabled: true
  evidence_dir: $DATA_DIR/evidence
  quarantine_fetch: true
  max_bytes: 52428800
  timeout_sec: 45
geoip:
  enabled: true
  insecure_http: true
YAML
log "config written to $DATA_DIR/shardlure.yaml"

# -- systemd services ------------------------------------------------------
COWRIE_HOME="$DATA_DIR/cowrie"
COWRIE_LOG="$COWRIE_HOME/var/log/cowrie/cowrie.json"

# The cowrie.service unit is written AFTER cowrie itself is installed, since
# the ExecStart path depends on the cowrie layout (old: bin/cowrie shell
# script, new: venv/bin/cowrie console_script created by 'pip install -e .').
# The shardlure-live unit can be written now since it doesn't depend on cowrie's
# internal layout.

ENV=""
if [[ -n "$DASH_TOKEN" ]]; then
  ENV="Environment=SHARDLURE_DASH_TOKEN=$DASH_TOKEN"
fi

# Only depend on cowrie.service when we'll actually install cowrie. Otherwise
# systemd emits 'Failed to add dependency' warnings for a unit that doesn't
# exist.
if [[ "$COWRIE" -eq 1 ]]; then
  COWRIE_DEP="After=network.target cowrie.service
Wants=cowrie.service"
else
  COWRIE_DEP="After=network.target"
fi

cat > /etc/systemd/system/shardlure-live.service <<SVC
[Unit]
Description=ShardLure live dashboard + telemetry ingest
$COWRIE_DEP
[Service]
Type=simple
$ENV
ExecStart=$DEST -config $DATA_DIR/shardlure.yaml live :$DASH_PORT --tailscale --cowrie=$COWRIE_LOG
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVC

log "shardlure-live systemd unit written (cowrie unit deferred until cowrie install completes)"

# -- cowrie installation ---------------------------------------------------
if [[ "$COWRIE" -eq 1 ]]; then
  if [[ -d "$COWRIE_HOME/.git" ]]; then
    log "cowrie already present at $COWRIE_HOME, skipping clone"
  else
    if ! id cowrie &>/dev/null; then
      useradd -r -s /bin/false -d "$COWRIE_HOME" cowrie
    fi

    # Dependencies
    if command -v apt-get &>/dev/null; then
      apt-get update -qq
      apt-get install -y -qq python3-venv python3-dev build-essential libssl-dev libffi-dev authbind git 2>/dev/null
    elif command -v dnf &>/dev/null; then
      dnf install -y python3 python3-devel gcc openssl-devel libffi-devel authbind git 2>/dev/null
    fi

    # Resolve cowrie branch. Upstream renamed master -> main in 2024, and
    # forks may still ship master. Try in order:
    #   1. user override via --cowrie-branch / $COWRIE_BRANCH
    #   2. remote HEAD (via ls-remote --symref)
    #   3. main
    #   4. master
    COWRIE_REPO="https://github.com/cowrie/cowrie.git"
    if [[ -z "$COWRIE_BRANCH" ]]; then
      COWRIE_BRANCH=$(git ls-remote --symref "$COWRIE_REPO" HEAD 2>/dev/null \
                      | awk '/^ref:/ {sub("refs/heads/","",$2); print $2; exit}')
    fi
    CANDIDATES=()
    [[ -n "$COWRIE_BRANCH" ]] && CANDIDATES+=("$COWRIE_BRANCH")
    CANDIDATES+=(main master)

    cloned=0
    for br in "${CANDIDATES[@]}"; do
      log "installing cowrie (trying branch: $br)…"
      if git clone --depth 1 --branch "$br" "$COWRIE_REPO" "$COWRIE_HOME" 2>/dev/null; then
        COWRIE_BRANCH="$br"
        cloned=1
        break
      fi
      # Clean up partial clone before retrying with the next candidate.
      rm -rf "$COWRIE_HOME"
    done
    if [[ $cloned -ne 1 ]]; then
      err "could not clone cowrie from $COWRIE_REPO (tried: ${CANDIDATES[*]}). Pass --cowrie-branch explicitly or --no-cowrie to skip."
    fi
    python3 -m venv "$COWRIE_HOME/venv"
    "$COWRIE_HOME/venv/bin/pip" install -q --upgrade pip setuptools wheel

    # Cowrie's install model changed: the modern (post-2024) layout uses
    # 'pip install -e .' (creates a console_script at venv/bin/cowrie),
    # while older tags ship a bin/cowrie launcher driven by
    # 'pip install -r requirements.txt'. Prefer the modern path, fall back
    # to the legacy one.
    if [[ -f "$COWRIE_HOME/pyproject.toml" ]]; then
      "$COWRIE_HOME/venv/bin/pip" install -q -e "$COWRIE_HOME" \
        || "$COWRIE_HOME/venv/bin/pip" install -q -r "$COWRIE_HOME/requirements.txt"
    else
      "$COWRIE_HOME/venv/bin/pip" install -q -r "$COWRIE_HOME/requirements.txt"
    fi

    # Authbind — allow cowrie user to bind to low ports
    touch /etc/authbind/byport/"$HONEYPOT_PORT"
    chown cowrie:cowrie /etc/authbind/byport/"$HONEYPOT_PORT"
    chmod 500 /etc/authbind/byport/"$HONEYPOT_PORT"

    chown -R cowrie:cowrie "$COWRIE_HOME"
    log "cowrie installed at $COWRIE_HOME"
  fi
fi

# -- write cowrie.service now that we know the entry-point layout ----------
# Probe order:
#   1. venv/bin/cowrie  (modern: console_script from 'pip install -e .')
#   2. bin/cowrie       (legacy: shell wrapper invoking twistd)
# In legacy mode, twistd needs PYTHONPATH and an explicit python interpreter,
# matching the previous behavior of the script.
COWRIE_EXEC=""
if [[ -x "$COWRIE_HOME/venv/bin/cowrie" ]]; then
  # Modern layout. AUTHBIND_ENABLED=yes is read by the cowrie launcher and
  # tells it to invoke twistd via authbind when binding low ports.
  COWRIE_EXEC="Environment=AUTHBIND_ENABLED=yes
ExecStart=/usr/bin/authbind --deep $COWRIE_HOME/venv/bin/cowrie start -n"
elif [[ -x "$COWRIE_HOME/bin/cowrie" ]]; then
  # Legacy layout.
  COWRIE_EXEC="ExecStart=/usr/bin/authbind --deep $COWRIE_HOME/venv/bin/python3 $COWRIE_HOME/bin/cowrie start -n"
fi

if [[ "$COWRIE" -eq 1 ]]; then
  if [[ -z "$COWRIE_EXEC" ]]; then
    err "could not locate cowrie entry point at $COWRIE_HOME/venv/bin/cowrie or $COWRIE_HOME/bin/cowrie. The clone may have failed or upstream layout changed again."
  fi
  cat > /etc/systemd/system/cowrie.service <<SVC
[Unit]
Description=Cowrie SSH honeypot (ShardLure)
After=network.target
[Service]
Type=simple
User=cowrie
WorkingDirectory=$COWRIE_HOME
$COWRIE_EXEC
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVC
  log "cowrie systemd unit written"
fi

# -- start services --------------------------------------------------------
systemctl daemon-reload
UNITS=("shardlure-live.service")
[[ "$COWRIE" -eq 1 ]] && UNITS+=("cowrie.service")
systemctl enable "${UNITS[@]}" 2>/dev/null || true
if [[ "$COWRIE" -eq 1 ]]; then
  if systemctl is-active --quiet cowrie.service; then
    systemctl restart cowrie.service
  else
    systemctl start cowrie.service
  fi
fi
if systemctl is-active --quiet shardlure-live.service; then
  log "restarting shardlure-live.service…"
  systemctl restart shardlure-live.service
else
  log "starting shardlure-live.service…"
  systemctl start shardlure-live.service
fi

sleep 2
echo
systemctl is-active "${UNITS[@]}" 2>&1 || true
echo
log "dashboard: http://$ADMIN_IPS:$DASH_PORT"
if [[ -n "$DASH_TOKEN" ]]; then
  log "auth token: (set, ${#DASH_TOKEN} chars)"
fi
log "done."
