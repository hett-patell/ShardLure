#!/usr/bin/env bash
# Only the provisioning step of the hosted integration workflow creates the
# marker. Never manufacture it here to bypass an unsuitable host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == Linux ]] || {
  echo 'Refusing installer integration outside a disposable GitHub-hosted Linux VM.' >&2
  exit 1
}
[[ "$EUID" == 0 ]] || { echo 'Guest integration requires sudo inside the disposable VM.' >&2; exit 1; }
python3 scripts/integration/test_installation.py --check-guest
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server openssh-client authbind git python3-venv python3-dev python3-pip build-essential libssl-dev libffi-dev iproute2 curl ca-certificates
python3 -u scripts/integration/test_installation.py --binary "$1" --report "$2"
