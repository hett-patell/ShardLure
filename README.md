# ShardLure
<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/68c62b67-de22-48d8-8360-78c6e28d5640" />
<br></br>

**Attacker identity engine for SSH honeypot telemetry.**

ShardLure clusters bots by **playbook fingerprint** (journal auth lines) or **HASSH** (Cowrie sessions), not just IPs. It ships with a one-command VPS installer, a forensic TUI, and a live globe dashboard so you can watch `root:root` attempts with a little dignity.

```text
Attacker hits port 22 (Cowrie)
        ↓
JSON log + journal tail
        ↓
SQLite actors/events
        ↓
Live web UI + forensic TUI
```

```text
You SSH into port 2222 (real SSH, key-only)
        ↓
Admin access + Tailscale dashboard on :8080
```

---

## Features

- Dual ingest from OpenSSH journal exports and Cowrie JSON logs
- Actor clustering using username playbooks or HASSH fingerprints
- Intent classification:
  - probe
  - proxy
  - deploy
  - mixed
- Live mode with auto-refresh dashboard
- One-command VPS bootstrap installer
- Stealth Ubuntu 22.04 honeypot persona
- Fake bait secrets and credentials in Cowrie virtual FS
- Safe deploy workflow using tar-over-SSH

---

## Quick Start (VPS Honeypot)

On a fresh Ubuntu or Debian VPS:

```bash
git clone https://github.com/hett-patell/shardlure.git
cd shardlure
sudo python3 scripts/shardlure.py run
```

The installer prompts for:

| Setting | Default | Purpose |
|---|---|---|
| Honeypot port | `22` | Cowrie listener |
| Admin SSH port | `2222` | Real SSH access |
| Dashboard port | `8080` | Live globe dashboard |

The installer automatically:

- Detects your Tailscale IP
- Installs Cowrie
- Migrates real SSH
- Configures services

Services started:

- `cowrie.service`
- `shardlure-live.service`

After setup:

```bash
sudo python3 scripts/shardlure.py status
systemctl status cowrie shardlure-live
```

Dashboard:

```text
http://<tailscale-ip>:8080
```

Keep port `8080` private. Expose only the honeypot port publicly.

---

## Resume After Partial Install

If the Go build fails during setup:

```bash
sudo python3 scripts/shardlure.py finish
```

---

## Plant Bait Files

```bash
sudo python3 scripts/shardlure.py plant-bait
```

Or:

```bash
sudo bash scripts/plant-bait.sh
```

Verify inside the honeypot shell:

```bash
ssh root@<public-ip>
```

Password is stored in:

```text
install/persona/userdb.txt
```

Then verify bait:

```bash
ls -la /opt/app/
cat /opt/app/.env
```

---

## Local Development

```bash
git clone https://github.com/hett-patell/shardlure.git
cd shardlure

go mod tidy
make build
```

Example commands:

```bash
./shardlure ingest journal testdata/sample.journal --replace

./shardlure ingest cowrie \
  /var/lib/shardlure/cowrie/var/log/cowrie/cowrie.json \
  --replace

./shardlure actors
./shardlure actor show 188.84.0.25

./shardlure dashboard
./shardlure web :8080 --tailscale

./shardlure live :8080 \
  --cowrie=/path/cowrie.json \
  --tailscale
```

Or run the installer wrapper:

```bash
sudo ./shardlure run
```

---

## Commands

### Go Binary

| Command | Description |
|---|---|
| `ingest journal <file> [--replace]` | Parse SSH journal logs |
| `ingest cowrie <file> [--replace]` | Parse Cowrie JSON logs |
| `actors [--limit=N]` | List actors |
| `actor show <id\|ip>` | Show actor details |
| `dashboard` / `dash` / `tui` | Launch forensic TUI |
| `web [:8080] [--tailscale]` | Launch live dashboard |
| `live [:8080] [...]` | Live ingest + dashboard |
| `run` | Run VPS installer |
| `status` | Show counts and service state |
| `ioc` | Export top indicators |
| `version` | Print version |

### Python Installer (`scripts/shardlure.py`)

| Command | Description |
|---|---|
| `run` / `setup` | Full VPS bootstrap |
| `finish` | Resume failed setup |
| `plant-bait` / `bait` | Inject fake secrets |
| `start` / `stop` / `status` | Service management |

---

## Configuration

Copy:

```text
shardlure.yaml.example
```

to:

```text
/var/lib/shardlure/shardlure.yaml
```

Example config:

```yaml
data_dir: /var/lib/shardlure

admin_ips:
  - 100.x.x.x

ssh:
  admin_port: 2222
  honeypot_port: 22

dashboard:
  port: 8080

cowrie:
  json_log: /var/lib/shardlure/cowrie/var/log/cowrie/cowrie.json
```

Override config with:

```bash
-config /path/shardlure.yaml
```

or:

```bash
SHARDLURE_CONFIG=/path/file
```

---

## Deploy to VPS

Use tar-over-SSH instead of `scp`.

```bash
make deploy
```

Or:

```bash
bash scripts/push-sources.sh arm
```

After upload:

```bash
cd ~/ShardLure/shardlure

bash scripts/fix-go-sources.sh

sudo cp /tmp/shardlure /usr/local/bin/shardlure

sudo python3 scripts/shardlure.py finish
```

---

## Export Journal Logs

```bash
sudo journalctl -u ssh \
  -S "30 days ago" \
  -o short-iso \
  --no-pager \
  | grep -E 'Invalid user|Failed password|Failed publickey|Accepted ' \
  > ~/journal-ssh-30d.log
```

Import logs:

```bash
shardlure ingest journal ~/journal-ssh-30d.log --replace
```

---

## Stealth Persona and Bait

`install/persona/` contains decoy infrastructure and fake secrets.

| Virtual Path | Contents |
|---|---|
| `/opt/app/.env` | Fake DB, Redis, JWT, Stripe, AWS creds |
| `/opt/app/config/database.yml` | Fake Postgres passwords |
| `/home/ubuntu/.aws/credentials` | Fake AWS deploy profile |
| `/home/deploy/.ssh/id_rsa` | Fake SSH deploy key |
| `/var/backups/nightly/db_credentials.txt` | Fake backup credentials |

All credentials are intentionally fake.

Never place real secrets inside bait files.

---

## Architecture

```text
+-------------+     +--------------+     +-------------+
|  Cowrie :22 | --> | cowrie.json  | --> |             |
+-------------+     +--------------+     |   SQLite    |
                                         | actors/events |
+-------------+     +--------------+     |             |
| journal ssh | --> |  tail/seed   | --> |             |
+-------------+     +--------------+     +-------------+
                                                  ↓
                                        Dashboard + TUI
```

### Actor Types

- `journal:<src_ip>`
  - Clustered by username playbook
- `cowrie:<hassh>`
  - Clustered by HASSH fingerprint

Admin IPs are excluded from clustering.

---

## Security Notes

- Verify SSH access on port `2222` before closing your current session.
- Keep dashboard access restricted to Tailscale.
- Regenerate Cowrie SSH host keys during install.
- Never use real credentials in bait files.

---

## Troubleshooting

### `scp` or `rsync` Corrupts Files

Symptoms:

- `SyntaxError: null bytes`
- `cannot execute binary file`

Fix:

```bash
bash scripts/push-sources.sh
```

Avoid copying Go/Python sources with `scp`.

---

### Cowrie PTY or Shell Fails

Ensure `cowrie.cfg` contains:

```ini
data_path = /var/lib/shardlure/cowrie/src/cowrie/data
state_path = /var/lib/shardlure/cowrie/var/lib/cowrie

[shell]
filesystem = /var/lib/shardlure/cowrie/src/cowrie/data/fs.pickle
```

---

### `plant-bait` Shows "already exists"

Safe to ignore on reruns.

---

### `fsctl ls` Does Not Work

`fsctl` has no `ls` command.

Verify bait manually:

```bash
ls /var/lib/shardlure/cowrie/honeyfs/opt/app/
```

Or through honeypot SSH access.

---
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/e62fe09e-e9fb-4d4e-891e-342298640e08" />

## Roadmap

- [x] Cowrie JSON ingest
- [x] HASSH fingerprinting
- [x] Stealth persona + bait planting
- [x] Live journal + Cowrie ingest
- [ ] GeoLite2 MMDB enrichment
- [ ] Configurable dashboard home point

---

## License

MIT License. See `LICENSE`.
