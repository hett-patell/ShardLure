# ShardLure

[![Release](https://img.shields.io/github/v/release/hett-patell/ShardLure?color=blue)](https://github.com/hett-patell/ShardLure/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/networkshard/shardlure)](https://goreportcard.com/report/github.com/networkshard/shardlure)
[![Stars](https://img.shields.io/github/stars/hett-patell/ShardLure?style=social)](https://github.com/hett-patell/ShardLure/stargazers)

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/68c62b67-de22-48d8-8360-78c6e28d5640" />
<br></br>

**Attacker identity engine for SSH honeypot telemetry.** Aka: it makes the bots think they hit a real prod box, then puts their entire playbook on blast.

ShardLure clusters SSH bots by **playbook fingerprint** (OpenSSH journal lines) or **HASSH** (Cowrie sessions), not just IP. Same actor on three IPs? Still one actor. Different actor with the same address? Different rows. The vibe is "username taste profile, not who's-at-the-door." It ships with a VPS installer, Cowrie integration, live ingest, a forensic TUI, and a web dashboard that spins a globe at you.

```text
attacker -> port 22 (Cowrie) -> JSON/journal ingest -> SQLite actors -> dashboard
you      -> port 2222 (SSH)   -> real admin access via keys/Tailscale
```

## Contents

- [Features](#features)
- [Setup Guide](#setup-guide)
- [Local Development](#local-development)
- [Commands](#commands)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Persona And Bait](#persona-and-bait)
- [IP Reputation Enrichment](#ip-reputation-enrichment)
- [Threat Intel Sharing (MalwareBazaar)](#threat-intel-sharing-malwarebazaar)
- [Architecture](#architecture)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Roadmap](#roadmap)

## Features

- **Dual ingest:** OpenSSH journal exports and Cowrie JSON logs. No vendor lock-in, no SaaS dashboard reading your shame.
- **Actor clustering:** journal actors by source IP, Cowrie actors by HASSH. Botnets get sorted by their *vibe* (HASSH + username corpus), not just where their NAT slingshot lands.
- **Intent classification:** probe, proxy, deploy, mixed, or unknown. The "deploy" ones are the spicy ones — that's curl-bash-into-tmp energy.
- **Live mode:** tails Cowrie + journal straight into a globe dashboard. Real-time slay.
- **VPS bootstrap:** installs Cowrie, moves real SSH to a private port, writes systemd units, starts everything. One command, no yak shaving.
- **Stealth persona:** Ubuntu-style banner, fake `prod-app-server-01` hostname, regenerated host keys so you don't get fingerprinted as "obvious honeypot #4892."
- **Bait files:** fake `.env`, AWS creds, DB creds, deploy keys, nginx site. Looks legit, is poison.
- **Deploy-safe sync:** tar-over-SSH because `scp` of Go/Python sources mysteriously turns them into UTF-16. We do not gaslight you about this — see Troubleshooting.
- **Incremental Cowrie ingest:** tracks file offset + inode, so a 100MB cowrie.json doesn't get re-scanned every 5 seconds. Your I/O thanks us.
- **Idempotent everything:** re-running ingest dedupes events instead of duping them. Past you can't bully present you.
- **Dragon theme:** purpose-built SOC dashboard with sidebar navigation, Chakra Petch typography, blood-red/molten-gold palette, flat panels, sharp geometry. No glass-morphism — this is a wartime console.
- **Dashboard widgets:** threat-level gauge, attack geography, brute-force radar, top credentials, live attack timeline. All fed by real-time API polling.
- **One-click MalwareBazaar upload:** share captured payloads to abuse.ch directly from the payload inspector modal. No CLI required.
- **Seven-provider IP enrichment:** look up any attacker IP against AbuseIPDB, VirusTotal, GreyNoise, Shodan, AlienVault OTX, IPQualityScore, and IPinfo in parallel — normalized verdict + score + tags, cached 24h. Two work with no API key.
- **Persistent geo cache:** IP geolocation results are stored in SQLite and survive restarts. No more "resolving…" on every page load.

## Setup Guide

A complete walkthrough for standing up ShardLure on a fresh Ubuntu/Debian VPS
(it also supports dnf/yum and pacman hosts). Budget ~10 minutes, most of it
Cowrie's pip install.

### Before you start — the one rule that matters

**Keep your current SSH session open until you've verified the new admin port
works.** The installer moves real SSH off port 22 so Cowrie can squat there.

You don't need to set up keys yourself first — the installer walks you through
it. It is paranoid on your behalf:

- If no SSH key is found on the server, it **pauses and lets you paste your
  public key in**, installs it into the right account with correct
  permissions, and only then moves SSH. (No key, no paste → it aborts *without*
  touching sshd, so you can't lock yourself out.)
- After moving SSH it **pauses at a verify gate**: open a second terminal,
  confirm `ssh -p <admin-port>` works, and only then type `yes` to continue.
- The original sshd config is backed up and **auto-rolled-back** if the new one
  fails `sshd -t`.

Print your laptop's public key when prompted (make one first if needed):

```bash
ssh-keygen -t ed25519          # only if you don't already have a key
cat ~/.ssh/id_ed25519.pub      # paste this when the installer asks
```

### Step 1 — Get the code onto the VPS

```bash
git clone https://github.com/hett-patell/shardlure.git
cd shardlure
```

> **Transferring sources yourself?** Use the tar-pipe deploy (`make deploy` /
> `bash scripts/push-sources.sh arm`), **not** `scp` — some `scp`/editor
> pipelines silently re-encode Go/Python to UTF-16 and the build dies with
> "null bytes". See [Troubleshooting](#nul-bytes-or-utf-16-corruption).

### Step 2 — Run the installer

```bash
sudo python3 scripts/shardlure.py run
```

It walks you through everything, in order:

1. **Intro + confirm** — shows what it's about to change and waits for your OK.
2. **Install dependencies** (git, python venv toolchain, authbind, Go) via your
   distro's package manager.
3. **Prompt for three ports** (validated; defaults shown below).
4. **Detect your admin IPs** — Tailscale IP + your current SSH client IP are
   auto-added to `admin_ips` (so you never classify *yourself* as an attacker);
   you can add more.
5. **Check / install your SSH key** — if the server has no key yet, it pauses
   and lets you paste your public key in, installing it with correct perms.
6. **Move real SSH** to the admin port via a drop-in at
   `/etc/ssh/sshd_config.d/99-shardlure-admin.conf` (key-only, root password
   login disabled). The original config is backed up to
   `/etc/ssh/sshd_config.shardlure-bak`.
7. **Verify gate** — pauses for you to confirm `ssh -p <admin-port>` works in a
   second terminal before going further (type `yes` to continue, `abort` to stop).
8. **Create the `cowrie` system user**, clone + build Cowrie into
   `/var/lib/shardlure/cowrie`, apply the stealth persona, regenerate host keys,
   and plant bait files.
9. **Build the `shardlure` binary** to `/usr/local/bin/shardlure`.
10. **Write** `/var/lib/shardlure/shardlure.yaml`.
11. **Open firewall ports** (only if `ufw` is already active).
12. **Install + start** two systemd services: `cowrie.service` and
    `shardlure-live.service`.

| Setting | Default | Purpose |
| --- | --- | --- |
| Honeypot port | `22` | Cowrie listener for attackers |
| Admin SSH port | `2222` | Real SSH, key-only |
| Dashboard port | `8080` | Live dashboard |

### Step 3 — Verify SSH before you log out (do not skip)

From a **second terminal**, confirm the new admin port works:

```bash
ssh -p 2222 user@your-vps        # use whatever admin port you chose
```

Only close your original session once that succeeds. (If something went wrong,
the original sshd was auto-restored — but verify anyway.)

### Step 4 — Check services and open the dashboard

```bash
sudo python3 scripts/shardlure.py status
systemctl status cowrie shardlure-live
journalctl -u shardlure-live -f       # watch live ingest
```

Open the dashboard at `http://<tailscale-ip>:8080`. **Keep `8080` off the public
internet** — port `22` is the bait, your dashboard is not bait, do not get those
confused. Tailscale or an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 ...`) is the
right way to reach it.

For defense in depth, set a token the dashboard requires on every request:

```bash
# Add to the shardlure-live systemd unit's [Service] section, then daemon-reload + restart:
Environment=SHARDLURE_DASH_TOKEN=your-long-random-token
```

Then reach the dashboard with `?token=…` (page load) or an `Authorization: Bearer …`
header (API calls — the token is never accepted in an `/api` URL, to keep it out
of access logs).

> **Fail-closed bind:** without a token, ShardLure **refuses to start** if the
> dashboard would bind a *public* address — loopback, private, and Tailscale
> (`100.64.0.0/10`) binds are allowed (with a warning). Either keep it private or
> set `SHARDLURE_DASH_TOKEN`.

### Step 5 (optional) — Enable IP reputation enrichment & MalwareBazaar sharing

Add provider API keys as `Environment=` lines in the `shardlure-live` unit (see
[IP Reputation Enrichment](#ip-reputation-enrichment) and
[Threat Intel Sharing](#threat-intel-sharing-malwarebazaar)). Two enrichment
providers (Shodan, GreyNoise) work with no key at all.

### Resume Setup

If setup was interrupted after Cowrie/SSH changes:

```bash
sudo python3 scripts/shardlure.py finish
```

### Plant Bait Files

```bash
sudo python3 scripts/shardlure.py plant-bait
```

Verify from the honeypot shell:

```bash
ls -la /opt/app/
cat /opt/app/.env
```

## Local Development

```bash
git clone https://github.com/hett-patell/shardlure.git
cd shardlure
go mod tidy
make build

./shardlure ingest journal testdata/sample.journal --replace
./shardlure ingest cowrie /var/lib/shardlure/cowrie/var/log/cowrie/cowrie.json --replace
./shardlure actors
./shardlure actor show 188.84.0.25
./shardlure dashboard
./shardlure web :8080 --tailscale
./shardlure live :8080 --cowrie=/path/cowrie.json --tailscale
```

The binary can also launch the VPS wrapper:

```bash
sudo ./shardlure run
```

## Commands

### Go CLI

| Command | Description |
| --- | --- |
| `ingest journal <file> [--replace]` | Parse journal auth lines and build actors |
| `ingest cowrie <file> [--replace]` | Parse Cowrie JSON logs and build actors |
| `actors [--limit=N]` | List actors by last seen |
| `actor show <id\|ip>` | Show one actor profile |
| `dashboard`, `dash`, `tui` | Open the forensic TUI |
| `web [:8080] [--tailscale]` | Serve the web dashboard |
| `live [:8080] [--cowrie=PATH] [--interval=5s] [--no-journal] [--tailscale]` | Run live ingest and dashboard |
| `run` | Start the VPS wrapper |
| `status` | Print event and actor counts |
| `ioc` | Export a small IOC slice |
| `share bazaar [--dry-run] [--limit N] [--sha SHA] [--since DURATION] [--anonymous] [--status]` | Upload captured payloads to MalwareBazaar (abuse.ch) |
| `version` | Print version |

### Installer

| Command | Description |
| --- | --- |
| `run`, `setup` | Full VPS bootstrap |
| `finish` | Resume after partial setup |
| `plant-bait`, `bait` | Inject bait files into Cowrie's virtual filesystem |
| `start`, `stop`, `status` | Manage services |
| `uninstall [--purge]` | Reverse the install: restore SSH, remove services + binary. `--purge` also deletes the data dir and `cowrie` user. See [Uninstall](#uninstall). |

## CI

GitHub Actions runs on push and pull request:

- `go mod verify`
- `go vet ./...`
- `go test -coverprofile=coverage.out ./...`
- `go build -o shardlure ./cmd/shardlure`

## Configuration

The installer writes `/var/lib/shardlure/shardlure.yaml`. You can also copy `shardlure.yaml.example`:

```yaml
data_dir: /var/lib/shardlure

admin_ips:
  - 100.x.x.x   # Tailscale IP or trusted admin workstation

ssh:
  admin_port: 2222
  honeypot_port: 22

dashboard:
  port: 8080
  # Change these to your VPS/operator location for the globe origin.
  home_lat: 19.0760
  home_lon: 72.8777
  home_city: Mumbai
  home_country: India
  home_cc: IN

journal:
  unit: ssh

cowrie:
  home: /var/lib/shardlure/cowrie
  json_log: /var/lib/shardlure/cowrie/var/log/cowrie/cowrie.json
```

Use `-config /path/shardlure.yaml` or `SHARDLURE_CONFIG` to override the path.

Do not commit your real config. `admin_ips` may reveal private network details such as Tailscale IPs.

## Deployment

<img width="1918" height="964" alt="image" src="https://github.com/user-attachments/assets/9a86570e-bda5-4cc0-a095-a4c49c391281" />

Use tar pipe deployment instead of direct `scp` for source files:

```bash
make deploy
# or
bash scripts/push-sources.sh arm
```

On the VPS:

```bash
cd ~/ShardLure/shardlure
bash scripts/fix-go-sources.sh
sudo cp /tmp/shardlure /usr/local/bin/shardlure
sudo python3 scripts/shardlure.py finish
```

### Manual Journal Export

```bash
sudo journalctl -u ssh -S "30 days ago" -o short-iso --no-pager \
  | grep -E 'Invalid user|Failed password|Failed publickey|Accepted ' \
  > ~/journal-ssh-30d.log

shardlure ingest journal ~/journal-ssh-30d.log --replace
```

## Persona And Bait

`install/persona/` includes a simple production-server disguise and decoy files.

| Virtual path | Bait |
| --- | --- |
| `/opt/app/.env` | Fake DB, Redis, JWT, Stripe, and AWS values |
| `/opt/app/config/database.yml` | Fake Postgres credentials |
| `/home/ubuntu/.aws/credentials` | Fake AWS deploy profile |
| `/home/deploy/.ssh/id_rsa` | Fake deploy key |
| `/var/backups/nightly/db_credentials.txt` | Fake backup credentials |

All credentials are intentionally fake. Regenerate bait values per deployment so multiple honeypots are not fingerprinted by identical decoys.

## IP Reputation Enrichment

The intel console's enrichment panel looks up any attacker IP against multiple
threat-intel providers in parallel, normalizes each into a verdict
(malicious / suspicious / benign / unknown) + score + tags, and caches results
for 24h in SQLite so you don't burn free-tier rate limits. Every provider is
opt-in via an environment variable; missing keys render as "not configured"
rather than failing the panel. Two providers are keyless and work out of the
box.

| Provider | Env var | Key? | Signal |
| --- | --- | --- | --- |
| AbuseIPDB | `SHARDLURE_ABUSEIPDB_KEY` | yes | Abuse-confidence score + report history |
| VirusTotal | `SHARDLURE_VT_KEY` | yes | Multi-engine detections |
| GreyNoise (community) | `SHARDLURE_GREYNOISE_KEY` | no (optional) | Internet-noise classification |
| Shodan InternetDB | — | no | Open ports, CPEs, known CVEs, host tags |
| AlienVault OTX | `SHARDLURE_OTX_KEY` | yes | Community pulse reputation + campaign tags |
| IPQualityScore | `SHARDLURE_IPQS_KEY` | yes | Fraud score + proxy / VPN / TOR / bot flags |
| IPinfo | `SHARDLURE_IPINFO_KEY` | yes | ASN / org / geo + privacy (hosting/proxy/vpn/tor) flags |

Set whichever keys you have (in your shell or the systemd unit) before running
`web` or `live`. Results are fail-open: a provider that errors or lacks a key
never blocks the others.

## Threat Intel Sharing (MalwareBazaar)

`shardlure share bazaar` submits captured payloads to [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/). Each upload is automatically classified (ELF arch, static-vs-dynamic linkage, scripting language, and a short list of well-known family fingerprints — RedTail, Mirai, Komari, Traffmonetizer, XMRig, c3pool) and tagged. abuse.ch's server-side analysis (YARA, ClamAV, telfhash) then bolts on the heavy-duty signatures.

**Setup**

1. Sign up at <https://auth.abuse.ch/> and copy your Auth-Key.
2. Edit `shardlure.yaml`:

    ```yaml
    intel:
      bazaar:
        api_key: "your-auth-key-here"
        tags: ["shardlure", "honeypot"]
        max_bytes: 33554432       # 32 MiB
        freshness_days: 10        # abuse.ch fair-use: fresh samples only
    ```

3. Dry-run first to inspect what would ship:

    ```bash
    shardlure share bazaar --dry-run --limit 10
    ```

4. When the output looks right, drop `--dry-run`:

    ```bash
    shardlure share bazaar --limit 10
    ```

Re-running is safe: every sha256 we successfully submit (including `file_already_known` responses) is recorded in `bazaar_uploads` and skipped on the next run.

You can also share payloads from the web dashboard: open the payload inspector modal on any captured artifact and click **Share to MalwareBazaar**. Set `SHARDLURE_BAZAAR_KEY` in your environment or systemd unit for this to work. The Red Team tab's MalwareBazaar panel shows upload history, family classification, and pending counts.

**Flags**

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dry-run` | false | print classification + destination without POSTing |
| `--limit N` | 10 | cap per-run uploads (0 = unbounded) |
| `--sha SHA` | – | upload only this specific sample (bypasses freshness) |
| `--since DUR` | 240h | only consider artifacts captured within this window |
| `--anonymous` | false | submit without attribution to your account |
| `--status` | – | list past uploads from `bazaar_uploads` instead of uploading |

**Why MalwareBazaar?** It's the de-facto sharing hub for honeypot-captured Linux malware. Their submission policy (no PUPs/adware, no file infectors, samples must be <10 days old) is enforced both client-side (the share subcommand respects `freshness_days`) and server-side. Repeated violations get accounts banned — see `internal/intel/bazaar/client.go` for the fatal-status handling that halts the run on `user_blacklisted`.

## Architecture

```text
+-------------+     +--------------+     +-------------+
|  Cowrie :22 | --> | cowrie.json  | --> |             |
+-------------+     +--------------+     |   SQLite    |
                                         |   actors    | --> web :8080
+-------------+     +--------------+     |   events    |     TUI
| journal ssh | --> |  tail/seed   | --> |             |
+-------------+     +--------------+     +-------------+
```

- **Journal actors:** `journal:<src_ip>`, clustered by username playbook (their attempted-username distribution is their personality).
- **Cowrie actors:** `cowrie:<hassh>`, clustered by HASSH fingerprint (TLS-but-for-SSH client identity hash).
- **Admin IPs:** explicitly excluded from clustering so you don't accidentally classify yourself as a "fast_dictionary_spray" actor.

## Security Notes

- Verify `ssh -p 2222 user@host` in a second terminal **before** closing your original session. "I'll fix it in the morning" SSH stories never end well.
- Keep the dashboard on Tailscale or another private network. Exposing the dashboard to the internet is what we call self-doxxing.
- Set `SHARDLURE_DASH_TOKEN` for dashboard defense in depth (constant-time compared, sent as `Authorization: Bearer …` or `X-ShardLure-Token`).
- External geolocation is opt-in (`SHARDLURE_GEO_HTTP=1`). Use `SHARDLURE_IPAPI_KEY` for HTTPS lookups via ip-api Pro (recommended). Plaintext `http://ip-api.com` only if you also set `SHARDLURE_GEO_INSECURE_HTTP=1` (leaks attacker IPs to the network path).
- Cowrie SSH host keys are regenerated during install so you don't share a fingerprint with every other lazy honeypot on Shodan.
- Keep bait credentials fake. Yes really. Do not get clever and put "almost real" creds in there.
- The SQLite database is chmod'd to `0600` automatically — it can contain attacker-supplied passwords, which sometimes overlap with their *actually reused* real ones. Treat the file like a loaded gun.

## Troubleshooting

### NUL Bytes Or UTF-16 Corruption

Symptoms (your editor/transfer pipeline silently re-encoded your source files):

- `SyntaxError: null bytes`
- `cannot execute binary file`
- `unexpected NUL in input`

This is not a you-problem, it's a tooling-problem. Fix:

```bash
bash scripts/push-sources.sh arm
```

Avoid direct `scp` for Go/Python sources in this project. We are not in our `scp` era.

### Cowrie PTY Or Shell Fails

Ensure `cowrie.cfg` points at the real Cowrie data path:

```ini
data_path = /var/lib/shardlure/cowrie/src/cowrie/data
state_path = /var/lib/shardlure/cowrie/var/lib/cowrie

[shell]
filesystem = /var/lib/shardlure/cowrie/src/cowrie/data/fs.pickle
```

### `plant-bait` Reports Existing Files

This is harmless on rerun. `do_load` indicates the file content was loaded.

### `fsctl ls` Does Not Work

`fsctl` does not implement `ls`. Verify bait through the honeypot shell or inspect `honeyfs`:

```bash
ls /var/lib/shardlure/cowrie/honeyfs/opt/app/
```
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/e62fe09e-e9fb-4d4e-891e-342298640e08" />

## Uninstall

Tearing ShardLure down means undoing everything the installer did: restoring
real SSH to port 22, removing the two systemd services and the binary, and
(optionally) deleting Cowrie, the captured-intel database, and the `cowrie`
user. There are two ways to do it — the built-in command (recommended) and a
fully manual walkthrough if you'd rather see every step.

> **The same golden rule as install:** SSH gets reconfigured. Keep a working
> session open and verify connectivity on the restored port **before** you log
> out. The uninstaller restores SSH *first*, before touching anything else,
> precisely so a half-finished teardown can't strand you.

### Option A — the `uninstall` command (recommended)

```bash
# Stops + removes services and the binary, restores the original sshd_config,
# removes the authbind/ufw rules — but KEEPS your data (DB, evidence, config):
sudo python3 scripts/shardlure.py uninstall

# Same, but ALSO delete /var/lib/shardlure (Cowrie clone, captured payloads,
# the SQLite intel DB) and remove the 'cowrie' system user:
sudo python3 scripts/shardlure.py uninstall --purge
```

What it does, in order (SSH first, on purpose):

1. **Restore SSH** — copy `/etc/ssh/sshd_config.shardlure-bak` back over
   `/etc/ssh/sshd_config`, delete the `99-shardlure-admin.conf` drop-in, run
   `sshd -t`, and only then reload. If the validated config fails the test it
   **aborts the reload** rather than risk your running sshd.
2. **Remove services** — stop, disable, and delete `cowrie.service` and
   `shardlure-live.service`; `daemon-reload`.
3. **Remove the binary** — `/usr/local/bin/shardlure`.
4. **Remove the authbind byport file** (only created when the honeypot port is
   < 1024).
5. **Firewall** — delete the honeypot and dashboard `ufw allow` rules. The
   **admin SSH rule is left in place on purpose** so you can't lock yourself out.
6. **Data** — kept by default; deleted only with `--purge` (along with the
   `cowrie` user).

> **Custom ports?** The firewall/authbind cleanup needs to know which ports you
> used. If you didn't install on the defaults (22/2222/8080), pass them via
> environment variables so the right rules are removed (SSH restore + service +
> binary removal are port-independent and always correct regardless):
>
> ```bash
> sudo SHARDLURE_HONEYPOT_PORT=22 SHARDLURE_ADMIN_PORT=2222 SHARDLURE_DASH_PORT=8080 \
>   python3 scripts/shardlure.py uninstall --purge
> ```

After it finishes, **verify SSH from a second terminal** on the restored port
(by default 22 once Cowrie is gone) before closing your session.

### Option B — manual teardown

Do this if the script isn't available or you want to inspect each step. Run as
root.

```bash
# 1. Restore real SSH FIRST (so you can't get locked out).
sudo cp /etc/ssh/sshd_config.shardlure-bak /etc/ssh/sshd_config   # if the backup exists
sudo rm -f /etc/ssh/sshd_config.d/99-shardlure-admin.conf
sudo sshd -t && sudo systemctl reload ssh                          # only reload if -t passes
#   No backup? Re-enable the original Port line by hand in /etc/ssh/sshd_config,
#   then `sudo sshd -t && sudo systemctl reload ssh`. VERIFY in a 2nd terminal.

# 2. Stop, disable, and remove the systemd services.
sudo systemctl stop shardlure-live.service cowrie.service
sudo systemctl disable shardlure-live.service cowrie.service
sudo rm -f /etc/systemd/system/shardlure-live.service /etc/systemd/system/cowrie.service
sudo systemctl daemon-reload
sudo systemctl reset-failed

# 3. Remove the binary.
sudo rm -f /usr/local/bin/shardlure

# 4. Remove the authbind byport file (only if your honeypot port was < 1024).
sudo rm -f /etc/authbind/byport/22       # use your honeypot port

# 5. Revert firewall rules (skip the admin SSH port!).
sudo ufw delete allow 22/tcp             # honeypot port
sudo ufw delete allow 8080/tcp           # dashboard port
#   Leave the admin SSH port (e.g. 2222) allowed until you've confirmed SSH on 22.

# 6. Delete Cowrie, captured intel, and the cowrie user (DESTRUCTIVE — skip to keep data).
sudo rm -rf /var/lib/shardlure
sudo userdel -r cowrie
```

> `apt`/`dnf`/`pacman` packages installed as dependencies (git, python venv,
> authbind, Go, build tools) are **not** removed by either method — they're
> shared system packages and removing them could break unrelated things. Remove
> them yourself only if you're sure nothing else needs them.

### What's left behind (and is safe to keep)

- Installed OS packages (see above).
- Any extra `ufw` rules you added by hand.
- Without `--purge`: `/var/lib/shardlure` and the `cowrie` user — your captured
  intel survives so you can archive it. Treat the SQLite DB like a loaded gun
  (it holds attacker-supplied passwords) and `shred`/securely delete it when done.

## Roadmap

- [x] Cowrie JSON ingest (HASSH, commands, payloads)
- [x] Stealth persona and bait file planting
- [x] Live journal tail and Cowrie append ingest
- [x] Configurable dashboard home point
- [x] Incremental Cowrie ingest (offset + inode tracking, no more O(file) per tick)
- [x] Idempotent journal append (dedup against existing events)
- [x] Graceful shutdown on SIGINT/SIGTERM (so Ctrl-C is no longer a war crime)
- [x] DB chmod 0600 + sshd-config auto-rollback on failed reload
- [x] MalwareBazaar payload sharing (CLI + one-click dashboard upload)
- [x] Dragon theme — full SOC dashboard redesign with sidebar nav
- [x] Dashboard widgets: threat gauge, geography, credentials, brute-force radar, live timeline
- [x] Persistent geo cache (SQLite-backed, survives restarts)
- [x] MalwareBazaar dashboard widget (stats + upload history + family classification)
- [x] Incremental cowrie actor rebuild (per-tick cost is O(touched), not O(all history))
- [x] Seven IP-reputation providers (AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, IPQualityScore, IPinfo)
- [x] Dashboard auth token forwarded on every request + cross-page navigation
- [x] One-command uninstall (`uninstall [--purge]`) with SSH-restore-first safety
- [x] Full-window analytics — MITRE/TTP/IOC/graph/deobf cover the whole selected window (not a recent sample), with capped widgets disclosing "N of M"
- [ ] GeoLite2 MMDB enrichment (escape the ip-api.com rate limits arc)
- [ ] Real-time WebSocket feed (current dashboard polls every 5s, which is fine but mid)

## FAQ (Frequently Asked Vibes)

**Q: Does this make my server safer?**
A: Marginally. It moves real SSH to a private port (good) and runs a fake one (interesting). The main value is *intel*: you learn what botnets are doing to boxes that look like yours.

**Q: Will I get cool maps?**
A: Yes. There is a globe. It rotates. Blood-red arcs converge on your home point like you're in a 2007 hacker movie. The intel console has a threat gauge, brute-force radar, and attack geography panel.

**Q: Is this production-ready?**
A: It's "single-VPS, one-operator, runs-on-my-laptop" ready. If you want a fleet, you'll want to front the SQLite with something less single-writer. PRs welcome.

**Q: Why Go + Python?**
A: Cowrie is Python. The ingest, classifier, and dashboard are Go because parsing a million journal lines in Python on a 1-vCPU droplet is suffering. The Python is *only* the installer.

**Q: The bait files. Are they convincing?**
A: They're convincing to bots. A human auditing them for 30 seconds would clock the fake Stripe keys. That's fine — bots are the customer here.

## License

MIT - see [LICENSE](LICENSE).

---

## The Shard ecosystem

| Repo | What it does |
|---|---|
| [ShardLure](https://github.com/hett-patell/ShardLure) | SSH honeypot + threat-intel dashboard |
| [ShardC2](https://github.com/hett-patell/ShardC2) | Red-team C2 framework in Go |
| [ShardFlow](https://github.com/hett-patell/ShardFlow) | Layer-2 LAN workbench (ARP, drop, throttle) |
| [ShardShell](https://github.com/hett-patell/ShardShell) | PHP post-exploitation shell |
| [ShardPass](https://github.com/hett-patell/ShardPass) | Minimal TOTP authenticator (Chrome MV3) |
| [ShardPet](https://github.com/hett-patell/ShardPet) | Pixel-Pokémon browser extension |
