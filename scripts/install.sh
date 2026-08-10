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
#   --cowrie-branch REF Explicit Cowrie branch/tag/commit override. The ref is
#                       resolved once to a commit (default: this release's pin)
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
ARCH_MAP[armv7l]=shardlure-linux-armv7
ARCH_MAP[armhf]=shardlure-linux-armv7

log() { printf '\033[1;36m[shardlure-install]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[shardlure-install]\033[0m %s\n' "$*" >&2; exit 1; }

initialize_data_paths() {
  local data_dir_physical

  if ! mkdir -p -- "$DATA_DIR"; then
    err "could not create data directory: $DATA_DIR"
  fi
  if ! data_dir_physical=$(cd -P -- "$DATA_DIR" && pwd -P); then
    err "could not resolve data directory: $DATA_DIR"
  fi
  DATA_DIR="$data_dir_physical"
  COWRIE_HOME="$DATA_DIR/cowrie"
  COWRIE_LOG="$COWRIE_HOME/var/log/cowrie/cowrie.json"
  if ! mkdir -p -- "$DATA_DIR/captures" "$DATA_DIR/evidence" "$DATA_DIR/payloads"; then
    err "could not create data subdirectories beneath $DATA_DIR"
  fi
}

resolve_cowrie_commit() {
  local pin_lines pin_bytes ref_output
  local direct_commit="" direct_ref=""
  local peeled_commit="" peeled_ref=""
  local override_commit=""

  COWRIE_REPO="${COWRIE_REPO:-https://github.com/cowrie/cowrie.git}"
  if [[ -z "$COWRIE_BRANCH" ]]; then
    # install.sh is commonly piped directly from GitHub, so the pin cannot
    # be read from a local checkout. Fetch it from the exact ShardLure release
    # selected above; never fall back to Cowrie's moving HEAD/main/master.
    COWRIE_PIN_URL="https://raw.githubusercontent.com/$REPO/$TAG/install/cowrie.commit"
    if ! curl -fsSL "$COWRIE_PIN_URL" -o "$DL_COWRIE_PIN"; then
      err "could not download the Cowrie pin for ShardLure $TAG from $COWRIE_PIN_URL"
    fi
    pin_lines=$(wc -l < "$DL_COWRIE_PIN")
    pin_bytes=$(wc -c < "$DL_COWRIE_PIN")
    COWRIE_COMMIT="$(<"$DL_COWRIE_PIN")"
    if [[ "$pin_lines" -ne 1 || "$pin_bytes" -ne 41 || ! "$COWRIE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
      err "invalid Cowrie pin at $COWRIE_PIN_URL: expected exactly one lowercase 40-hex SHA"
    fi
    return
  fi

  # A literal SHA is already immutable. Branch/tag overrides are accepted
  # only when the remote resolves them unambiguously once; annotated tags use
  # their single peeled commit rather than the tag object.
  if [[ "$COWRIE_BRANCH" =~ ^[0-9a-f]{40}$ ]]; then
    override_commit="$COWRIE_BRANCH"
  else
    if ! ref_output=$(git ls-remote "$COWRIE_REPO" "$COWRIE_BRANCH" "${COWRIE_BRANCH}^{}" 2>/dev/null); then
      err "Cowrie override '$COWRIE_BRANCH' could not be resolved from $COWRIE_REPO"
    fi
    if [[ -z "$ref_output" ]]; then
      err "Cowrie override '$COWRIE_BRANCH' must resolve to exactly one commit"
    fi

    while IFS=$'\t' read -r candidate_commit candidate_ref; do
      if [[ ! "$candidate_commit" =~ ^[0-9a-f]{40}$ || -z "$candidate_ref" ]]; then
        err "Cowrie override '$COWRIE_BRANCH' returned an invalid remote ref"
      fi
      if [[ "$candidate_ref" == *'^{}' ]]; then
        if [[ -n "$peeled_commit" ]]; then
          err "Cowrie override '$COWRIE_BRANCH' must resolve to exactly one commit"
        fi
        peeled_commit="$candidate_commit"
        peeled_ref="$candidate_ref"
      else
        if [[ -n "$direct_commit" ]]; then
          err "Cowrie override '$COWRIE_BRANCH' must resolve to exactly one commit"
        fi
        direct_commit="$candidate_commit"
        direct_ref="$candidate_ref"
      fi
    done <<< "$ref_output"

    if [[ -n "$peeled_commit" ]]; then
      if [[ -z "$direct_ref" || "$peeled_ref" != "${direct_ref}^{}" ]]; then
        err "Cowrie override '$COWRIE_BRANCH' must resolve to exactly one commit"
      fi
      override_commit="$peeled_commit"
    elif [[ -n "$direct_commit" ]]; then
      override_commit="$direct_commit"
    else
      err "Cowrie override '$COWRIE_BRANCH' must resolve to exactly one commit"
    fi
  fi
  COWRIE_OVERRIDE_COMMIT="$override_commit"
  COWRIE_COMMIT="$COWRIE_OVERRIDE_COMMIT"
}

validate_existing_cowrie_checkout() {
  local COWRIE_EXISTING_COMMIT
  local cowrie_safe_directory
  if [[ -L "$COWRIE_HOME" ]]; then
    err "Cowrie target must not be a symlink: $COWRIE_HOME"
  fi
  if ! cowrie_safe_directory=$(cd -P -- "$COWRIE_HOME" && pwd -P); then
    err "could not read Cowrie HEAD at $COWRIE_HOME; refusing to alter the existing checkout"
  fi
  if ! COWRIE_EXISTING_COMMIT=$(git -c safe.directory="$cowrie_safe_directory" -C "$cowrie_safe_directory" rev-parse --verify HEAD 2>/dev/null); then
    err "could not read Cowrie HEAD at $COWRIE_HOME; refusing to alter the existing checkout"
  fi
  if [[ "$COWRIE_EXISTING_COMMIT" != "$COWRIE_COMMIT" ]]; then
    err "existing Cowrie commit $COWRIE_EXISTING_COMMIT does not match required commit $COWRIE_COMMIT; refusing to fetch, reset, or delete it"
  fi
  COWRIE_HOME="$cowrie_safe_directory"
  log "cowrie already matches required commit $COWRIE_COMMIT; preserving existing checkout and dirty files; installer-managed cowrie.cfg may still be updated"
}

checkout_fresh_cowrie() {
  local cowrie_parent
  local cowrie_parent_physical
  local cowrie_parent_identity
  local cowrie_parent_current
  local cowrie_parent_current_identity
  local cowrie_final_name
  local cowrie_final_path
  local cowrie_staging
  local cowrie_staging_identity
  local cowrie_staging_current_identity
  local cowrie_published_identity
  local COWRIE_CHECKED_OUT_COMMIT

  cowrie_parent=$(dirname -- "$COWRIE_HOME")
  if [[ ! -d "$cowrie_parent" ]]; then
    err "cowrie target parent does not exist: $cowrie_parent"
  fi
  if ! cowrie_parent_physical=$(cd -P -- "$cowrie_parent" && pwd -P); then
    err "could not resolve Cowrie target parent: $cowrie_parent"
  fi
  if ! cowrie_parent_identity=$(stat -c '%d:%i' -- "$cowrie_parent_physical"); then
    err "could not identify Cowrie target parent: $cowrie_parent"
  fi
  cowrie_final_name=$(basename -- "$COWRIE_HOME")
  cowrie_final_path="$cowrie_parent_physical/$cowrie_final_name"
  if [[ -e "$cowrie_final_path" || -L "$cowrie_final_path" ]]; then
    err "cowrie target exists or is a symlink: $COWRIE_HOME. Move it aside or use --no-cowrie."
  fi
  if ! cowrie_staging=$(mktemp -d -- "$cowrie_parent_physical/.cowrie-install.XXXXXXXXXX"); then
    err "could not create a private Cowrie staging checkout beneath $cowrie_parent"
  fi
  if ! cowrie_staging_identity=$(stat -c '%d:%i' -- "$cowrie_staging"); then
    err "could not identify Cowrie staging checkout at $cowrie_staging; refusing to delete it"
  fi

  log "installing cowrie at immutable commit $COWRIE_COMMIT…"
  if ! git -C "$cowrie_staging" init -q \
    || ! git -C "$cowrie_staging" remote add origin "$COWRIE_REPO" \
    || ! git -C "$cowrie_staging" fetch --depth 1 origin "$COWRIE_COMMIT" \
    || ! git -C "$cowrie_staging" checkout --detach "$COWRIE_COMMIT"; then
    err "could not fetch and check out pinned Cowrie commit $COWRIE_COMMIT; staging checkout left at $cowrie_staging"
  fi
  if ! COWRIE_CHECKED_OUT_COMMIT=$(git -C "$cowrie_staging" rev-parse --verify HEAD); then
    err "could not verify pinned Cowrie commit $COWRIE_COMMIT; staging checkout left at $cowrie_staging"
  fi
  if [[ "$COWRIE_CHECKED_OUT_COMMIT" != "$COWRIE_COMMIT" ]]; then
    err "Cowrie object $COWRIE_COMMIT did not resolve to that exact commit; staging checkout left at $cowrie_staging"
  fi

  if [[ -L "$cowrie_staging" || ! -d "$cowrie_staging" ]] \
    || ! cowrie_staging_current_identity=$(stat -c '%d:%i' -- "$cowrie_staging") \
    || [[ "$cowrie_staging_current_identity" != "$cowrie_staging_identity" ]]; then
    err "Cowrie staging checkout changed unexpectedly at $cowrie_staging; refusing to publish or delete it"
  fi
  if ! cowrie_parent_current=$(cd -P -- "$cowrie_parent" && pwd -P) \
    || [[ "$cowrie_parent_current" != "$cowrie_parent_physical" ]] \
    || ! cowrie_parent_current_identity=$(stat -c '%d:%i' -- "$cowrie_parent_current") \
    || [[ "$cowrie_parent_current_identity" != "$cowrie_parent_identity" ]]; then
    err "Cowrie target parent changed during installation; refusing to publish or delete staging checkout $cowrie_staging"
  fi
  if ! mv -T --no-clobber -- "$cowrie_staging" "$cowrie_final_path"; then
    if [[ -e "$cowrie_final_path" || -L "$cowrie_final_path" ]]; then
      err "cowrie target appeared during installation: $COWRIE_HOME; refusing to overwrite it; verified staging checkout left at $cowrie_staging"
    fi
    err "could not atomically publish Cowrie checkout at $COWRIE_HOME; verified staging checkout left at $cowrie_staging"
  fi
  if [[ -e "$cowrie_staging" || -L "$cowrie_staging" ]]; then
    if [[ -e "$cowrie_final_path" || -L "$cowrie_final_path" ]]; then
      err "cowrie target appeared during installation: $COWRIE_HOME; refusing to overwrite it; verified staging checkout left at $cowrie_staging"
    fi
    err "atomic Cowrie publish left staging checkout at $cowrie_staging; refusing to alter either path"
  fi
  if ! cowrie_published_identity=$(stat -c '%d:%i' -- "$cowrie_final_path") \
    || [[ "$cowrie_published_identity" != "$cowrie_staging_identity" ]]; then
    err "published Cowrie checkout identity could not be verified at $COWRIE_HOME; refusing to alter it"
  fi
  if ! cowrie_parent_current=$(cd -P -- "$cowrie_parent" && pwd -P) \
    || [[ "$cowrie_parent_current" != "$cowrie_parent_physical" ]] \
    || ! cowrie_parent_current_identity=$(stat -c '%d:%i' -- "$cowrie_parent_current") \
    || [[ "$cowrie_parent_current_identity" != "$cowrie_parent_identity" ]]; then
    err "Cowrie target parent changed after publication; verified checkout remains at $cowrie_final_path; refusing further installation"
  fi
  COWRIE_HOME="$cowrie_final_path"
}

# Tests source the pure checkout functions above. Return before argument
# parsing, root checks, downloads, package installation, or filesystem writes.
if [[ "${SHARDLURE_INSTALL_SOURCE_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

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
  err "unsupported architecture: $ARCH (supported: x86_64, amd64, aarch64, arm64, armv7l, armhf)"
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
# Unpredictable mktemp paths: this script typically runs as root, and writing
# to fixed names in world-writable /tmp would let a local user pre-plant a
# symlink and have root clobber (or execute) an arbitrary file.
DL_BIN="$(mktemp /tmp/shardlure-dl.XXXXXX)"
DL_SUMS="$(mktemp /tmp/shardlure-sums.XXXXXX)"
DL_ERR="$(mktemp /tmp/shardlure-curlerr.XXXXXX)"
DL_COWRIE_PIN="$(mktemp /tmp/shardlure-cowrie-pin.XXXXXX)"
trap 'rm -f "$DL_BIN" "$DL_SUMS" "$DL_ERR" "$DL_COWRIE_PIN"' EXIT
log "downloading $URL …"
# `if !` form: under set -e a bare failing curl would abort before our
# friendly error message could print.
if ! curl -fsSL "$URL" -o "$DL_BIN" 2>"$DL_ERR" || [[ ! -s "$DL_BIN" ]]; then
  err "download failed (URL: $URL). $(cat "$DL_ERR" 2>/dev/null || true)"
fi

# Download the checksum manifest and verify the binary before installing
# as root. If the checksum file is missing (e.g. manually cut release
# without CI), print a warning but continue — better than blocking a
# deployment. If it exists, enforce a strict match. (`|| true` because under
# set -e a missing manifest would otherwise abort instead of warning.)
CHKSUM_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"
curl -fsSL "$CHKSUM_URL" -o "$DL_SUMS" 2>/dev/null || true
if [[ -s "$DL_SUMS" ]]; then
  # Anchor the match: line must END with two spaces + exact BIN_NAME so a
  # release that ships e.g. shardlure-linux-arm64 alongside
  # shardlure-linux-arm64-musl can't accidentally match the wrong row.
  expected=$(grep -F "  $BIN_NAME" "$DL_SUMS" | awk -v b="$BIN_NAME" '$2==b {print $1}' | head -1)
  actual=$(sha256sum "$DL_BIN" | awk '{print $1}')
  if [[ -z "$expected" ]]; then
    log "WARNING: no checksum entry for $BIN_NAME in SHA256SUMS — binary not verified"
  elif [[ "$expected" != "$actual" ]]; then
    err "checksum mismatch for $BIN_NAME. Expected: $expected, got: $actual. Do not proceed — the binary may be tampered."
  else
    log "checksum verified: $BIN_NAME ($actual)"
  fi
else
  log "WARNING: SHA256SUMS not found at $CHKSUM_URL — binary not verified"
fi

install -m 755 "$DL_BIN" "$DEST"
log "installed $DEST ($(wc -c < "$DEST") bytes)"

# -- config ----------------------------------------------------------------
initialize_data_paths

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

# The unit embeds SHARDLURE_DASH_TOKEN via Environment=; systemd units are
# world-readable by default (0644), so any local user could read the token.
# Lock the unit to root-only when a token is present.
if [[ -n "$DASH_TOKEN" ]]; then
  chmod 600 /etc/systemd/system/shardlure-live.service
fi

log "shardlure-live systemd unit written (cowrie unit deferred until cowrie install completes)"

# -- cowrie installation ---------------------------------------------------
if [[ "$COWRIE" -eq 1 ]]; then
  # Resolve the required immutable commit before inspecting an existing
  # checkout. This prevents an existing .git directory from bypassing either
  # the release pin or an explicit operator override.
  #
  # git is also needed to validate an existing cowrie-owned checkout. Install
  # the normal Cowrie dependencies first so fresh explicit refs can be resolved
  # on hosts where git was not already present.
  if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-venv python3-dev build-essential libssl-dev libffi-dev authbind git 2>/dev/null
  elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-devel gcc openssl-devel libffi-devel authbind git 2>/dev/null
  fi

  resolve_cowrie_commit

  if [[ -d "$COWRIE_HOME/.git" ]]; then
    validate_existing_cowrie_checkout
  else
    checkout_fresh_cowrie

    if ! id cowrie &>/dev/null; then
      useradd -r -s /bin/false -d "$COWRIE_HOME" cowrie
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

  # -- cowrie.cfg override --------------------------------------------------
  # Without this, cowrie falls back to cowrie.cfg.dist defaults: port 2222
  # regardless of --honeypot-port, and a jsonlog path we'd only tail
  # correctly by coincidence. cowrie.cfg is read as an override on top of
  # cowrie.cfg.dist, so a minimal managed file is enough. Only write it when
  # absent or when we own it (marker), so hand-edits survive re-runs.
  COWRIE_CFG="$COWRIE_HOME/etc/cowrie.cfg"
  CFG_MARKER="# managed by shardlure install.sh"
  if [[ ! -f "$COWRIE_CFG" ]] || grep -qF "$CFG_MARKER" "$COWRIE_CFG"; then
    cat > "$COWRIE_CFG" <<CFG
$CFG_MARKER
# Hand-edit freely, but remove the marker line above so re-running the
# installer does not overwrite your changes.

[ssh]
listen_endpoints = tcp:$HONEYPOT_PORT:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = $COWRIE_HOME/var/log/cowrie/cowrie.json
CFG
    chown cowrie:cowrie "$COWRIE_CFG"
    log "cowrie.cfg written (ssh port $HONEYPOT_PORT, jsonlog enabled)"
  else
    log "cowrie.cfg exists and is not managed by this installer — leaving it alone."
    log "  ensure it contains: [ssh] listen_endpoints = tcp:$HONEYPOT_PORT:interface=0.0.0.0"
    log "  and [output_jsonlog] logfile = $COWRIE_HOME/var/log/cowrie/cowrie.json"
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
    err "could not locate cowrie entry point at $COWRIE_HOME/venv/bin/cowrie or $COWRIE_HOME/bin/cowrie. The checkout may have failed or upstream layout changed again."
  fi
  cat > /etc/systemd/system/cowrie.service <<SVC
[Unit]
Description=Cowrie SSH honeypot (ShardLure)
After=network.target
[Service]
Type=simple
User=cowrie
WorkingDirectory=$COWRIE_HOME
# TZ=UTC is load-bearing: cowrie's jsonlog output stamps 'timestamp' with a
# 'Z' (Zulu) suffix only when TZ=UTC at process start; without it a non-UTC
# host logs LOCAL time mislabeled as UTC and skews all ShardLure analytics.
Environment=TZ=UTC
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
