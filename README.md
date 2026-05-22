# ShardLure
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
- [Quick Start](#quick-start)
- [Local Development](#local-development)
- [Commands](#commands)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Persona And Bait](#persona-and-bait)
- [Architecture](#architecture)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
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

## Quick Start

On a fresh Ubuntu/Debian VPS. Bring your SSH key, leave your password auth at the door.

```bash
git clone https://github.com/hett-patell/shardlure.git
cd shardlure
sudo python3 scripts/shardlure.py run
```

The installer is paranoid on your behalf: it refuses to move SSH off port 22 if it can't find an `authorized_keys`, and it rolls the sshd config back automatically if the new one fails `sshd -t`. No accidental "locked myself out at 2am" lore.

The installer asks for:

| Setting | Default | Purpose |
| --- | --- | --- |
| Honeypot port | `22` | Cowrie listener for attackers |
| Admin SSH port | `2222` | Real SSH, key-only |
| Dashboard port | `8080` | Live dashboard |

After setup:

```bash
sudo python3 scripts/shardlure.py status
systemctl status cowrie shardlure-live
```

Open the dashboard at `http://<tailscale-ip>:8080`. Keep `8080` off the public internet — port `22` is the bait, your dashboard is not bait, do not get those confused.

For an extra dashboard guard, set `SHARDLURE_DASH_TOKEN` before running `web` or `live`.

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
| `version` | Print version |

### Installer

| Command | Description |
| --- | --- |
| `run`, `setup` | Full VPS bootstrap |
| `finish` | Resume after partial setup |
| `plant-bait`, `bait` | Inject bait files into Cowrie's virtual filesystem |
| `start`, `stop`, `status` | Manage services |

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
- External geolocation is opt-in. Set `SHARDLURE_GEO_HTTP=1` to allow ip-api.com lookups. Off by default because phoning home is not a feature.
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

## Roadmap

- [x] Cowrie JSON ingest (HASSH, commands, payloads)
- [x] Stealth persona and bait file planting
- [x] Live journal tail and Cowrie append ingest
- [x] Configurable dashboard home point
- [x] Incremental Cowrie ingest (offset + inode tracking, no more O(file) per tick)
- [x] Idempotent journal append (dedup against existing events)
- [x] Graceful shutdown on SIGINT/SIGTERM (so Ctrl-C is no longer a war crime)
- [x] DB chmod 0600 + sshd-config auto-rollback on failed reload
- [ ] GeoLite2 MMDB enrichment (escape the ip-api.com rate limits arc)
- [ ] Real-time WebSocket feed (current dashboard polls every 5s, which is fine but mid)

## FAQ (Frequently Asked Vibes)

**Q: Does this make my server safer?**
A: Marginally. It moves real SSH to a private port (good) and runs a fake one (interesting). The main value is *intel*: you learn what botnets are doing to boxes that look like yours.

**Q: Will I get cool maps?**
A: Yes. There is a globe. It rotates. Red arcs converge on your home point like you're in a 2007 hacker movie.

**Q: Is this production-ready?**
A: It's "single-VPS, one-operator, runs-on-my-laptop" ready. If you want a fleet, you'll want to front the SQLite with something less single-writer. PRs welcome.

**Q: Why Go + Python?**
A: Cowrie is Python. The ingest, classifier, and dashboard are Go because parsing a million journal lines in Python on a 1-vCPU droplet is suffering. The Python is *only* the installer.

**Q: The bait files. Are they convincing?**
A: They're convincing to bots. A human auditing them for 30 seconds would clock the fake Stripe keys. That's fine — bots are the customer here.

## License

MIT - see [LICENSE](LICENSE).
