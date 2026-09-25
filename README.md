# Mirraura

A **shadow honeypot**. Instead of letting an untrusted file run on the real
device, Mirraura detonates it inside a throwaway, network-isolated Docker
container, watches what it actually does, and returns a verdict —
`Normal`, `Suspicious`, `Compromised` or `Inconclusive` — with a confidence
number and the exact list of behaviors that produced it.

It runs two independent detection paths into the same verdict engine:

1. **Upload-triggered** — you upload a file, it detonates in a fresh
   container that is destroyed afterwards.
2. **Continuous monitoring** — a persistent container stands in for "the
   real device" and is polled every 10 seconds. A `Compromised` verdict
   disconnects it from its network for real; only a human can reconnect it.

Every verdict is appended to a hash-chained audit log, so an edited entry
breaks the chain and is detectable.

## Architecture

| Component | Language | Responsibility |
| --- | --- | --- |
| `backend/` | Go | Container/network lifecycle per run, REST API, WebSocket feed, auth and sessions, the 10s monitoring ticker |
| `verdict-engine/` | Python (FastAPI) | Known-bad hash lookup, weighted behavioral scoring, the audit log |
| `sensor/` | Rust | Runs inside the shadow container, traces the sample with `strace`, emits canonical events |
| `monitored-endpoint/` | Python | Poll-and-diff agent in the always-on container (processes, connections, `/etc`) |
| `frontend/` | React + TypeScript | Dashboard: login, upload, live feed, verdict, audit log, hash approvals |

nginx serves the dashboard and reverse-proxies `/api` to the backend, so
everything is one origin and only the frontend port is published.

## Prerequisites

- Docker, with Docker Compose (Docker Desktop on Windows/macOS)
- About 4 GB of free disk space for the images

## Quick start

```bash
git clone https://github.com/Kirthan-Choudhary-A/Mirraura.git
cd Mirraura
cp .env.example .env
# set MIRRAURA_ADMIN_PASSWORD in .env — 12+ characters, no default
./setup.sh
```

`setup.sh` validates the admin password, builds the shadow image, and brings
up the stack. The first build takes several minutes because the Go, Rust and
frontend code all compile.

Open <http://localhost:5173> and sign in with the credentials from `.env`.

<details>
<summary>Windows (PowerShell)</summary>

Clone with line-ending conversion off, or the shell scripts break inside the
Linux containers (`bad interpreter`, `\r: command not found`):

```powershell
git clone -c core.autocrlf=false https://github.com/Kirthan-Choudhary-A/Mirraura.git
cd Mirraura
copy .env.example .env
# set MIRRAURA_ADMIN_PASSWORD in .env
docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
docker compose up --build
```

Those last two commands are what `setup.sh` runs, so Git Bash is optional.
</details>

Stop with `Ctrl+C`, then `docker compose down`. Add `-v` to also wipe the
audit log and known-bad hashes.

## Accounts

There is no public sign-up — this is a security tool. The admin account
comes from `.env`:

| Variable | Meaning |
| --- | --- |
| `MIRRAURA_ADMIN_USER` | Admin username (default `admin`) |
| `MIRRAURA_ADMIN_PASSWORD` | Required, 12+ characters, no default |
| `MIRRAURA_USERS_PATH` | Optional path to extra users, e.g. `/app/users.json` |

Two roles:

- **admin** — everything, including approving/rejecting known-bad hashes and
  reconnecting an isolated endpoint.
- **analyst** — read-only plus uploads; approval and reconnect return 403.

To add an analyst, generate a bcrypt hash and add it to `users.json` in the
repo root (bind-mounted to `/app/users.json`), then set
`MIRRAURA_USERS_PATH=/app/users.json`:

```bash
go run ./backend/cmd/hashpw 'their-password'
```

```json
[{ "username": "asha", "bcrypt_hash": "$2a$10$...", "role": "analyst" }]
```

Sessions are a random token in an `HttpOnly` cookie, held in memory, and
expire after 8 hours of inactivity — a backend restart signs everyone out.
Failed logins are rate-limited per IP.

## Demo walkthrough

Upload the files in `samples/` through the dashboard. Each one is built to
trip a specific rule:

| Sample | What it does | Rule it triggers |
| --- | --- | --- |
| `harmless.sh` | Prints text, writes to `/tmp` | None — the baseline `Normal` case |
| `spawn_and_write.sh` | Runs `touch`/`cat`, writes under `/etc` | `child_process` + `sensitive_write` |
| `connect_odd_port.sh` | Opens a TCP connection to port 31337 | `odd_port` |
| `samples/eicar.txt` | The EICAR antivirus test string | Known-bad hash — short-circuits to `Compromised` |

The EICAR file is deliberately not committed; antivirus deletes it on sight.
Read `samples/EICAR.md` to recreate it before that demo.

Continuous monitoring needs no upload. To make the monitored endpoint look
compromised, give it something worth reporting:

```bash
docker exec mirraura-monitored-endpoint sh -c 'for i in $(seq 1 8); do touch /etc/evil-$i; done'
```

Within one poll cycle the dashboard should show the events, a verdict, and —
if the score clears 0.6 — the isolation banner with a **Reconnect** button.

## How scoring works

`verdict-engine/rule_scorer.py` adds a fixed weight per rule that fires:

| Rule | Weight | Fires when |
| --- | --- | --- |
| `child_process` | 0.30 | A process is spawned (the sample's own shell is excluded) |
| `sensitive_write` | 0.25 | A write under `/etc/`, `/bin/`, `/usr/`, `/boot/` or `/sbin/` |
| `odd_port` | 0.20 | A connection to any port other than 80 or 443 |
| `rapid_file_changes` | 0.25 | More than 5 file writes or deletes |

The total is capped at 1.0 and mapped to a label: no telemetry →
`Inconclusive`; 0.0 → `Normal`; below 0.6 → `Suspicious`; 0.6 and above →
`Compromised`. Each rule that fires adds a plain-English line to the causal
chain, which is what the dashboard shows instead of a bare yes/no.

A known-bad SHA-256 match short-circuits all of this to `Compromised` at
confidence 1.0, but only for hashes a human has **approved** — auto-proposed
hashes sit as `pending` and affect nothing until then.

## API

All routes require the session cookie except `/api/health` and
`/api/login`. Admin-only routes are marked.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness |
| `POST` | `/api/login` / `/api/logout` | Sign in, sign out |
| `GET` | `/api/me` | Current username and role |
| `POST` | `/api/samples` | Upload and detonate a file, returns the verdict |
| `GET` | `/api/verdicts`, `/api/verdicts/{id}` | Audit log entries |
| `GET` | `/api/audit/verify` | Hash-chain integrity check |
| `GET` | `/api/live` | WebSocket: events, verdicts, isolation state |
| `GET` | `/api/monitor/status` | Whether the endpoint is isolated |
| `POST` | `/api/monitor/reconnect` | Reconnect an isolated endpoint (admin) |
| `GET`/`POST` | `/api/hashes` | List or propose known-bad hashes |
| `POST` | `/api/hashes/{hash}/approve\|reject` | Decide a pending hash (admin) |

## Development

```bash
cd backend        && go test ./...
cd verdict-engine && pytest
cd sensor         && cargo test
cd frontend       && npm install && npm test && npm run lint && npm run build
cd monitored-endpoint && pytest
```

`npm run dev` gives a Vite dev server; it needs the stack up for `/api` to
resolve.

### Replaying a candidate scorer

`revalidate.py` replays the hand-authored fixtures in
`verdict-engine/revalidation_fixtures/` plus archived real captures against
a candidate scorer, and reports accuracy on the fixtures and verdict drift
on the captures:

```bash
docker compose exec verdict-engine python revalidate.py --candidate revalidation_candidates/my_scorer.py
```

Candidates must live in `revalidation_candidates/` because that directory is
bind-mounted into the container. The candidate's module-level code runs with
your privileges, so only point it at a file you wrote. Nothing is promoted
automatically; a human folds a good change into `rule_scorer.py`.

`train.py` fits a scikit-learn logistic regression over the same four
features on synthetic data and ships as `trained_scorer.py` — a candidate
for the loop above, never the live scorer.

## Known limitations

Deliberate, and worth knowing before you read too much into a verdict:

- **Linux samples only.** The shadow image is Linux, so Windows
  executables, Office macros and PDFs cannot be detonated.
- **Four rules, four syscalls.** The sensor traces `execve`, `open`,
  `openat` and `connect`, so deletions, renames and UDP (including DNS) are
  invisible, and anything outside the four rules scores as `Normal`.
- **Evadable by design at this scale.** A sample that sleeps past the 15s
  trace window, or fingerprints the container first, comes back clean.
- **Exact-hash matching only.** No YARA, fuzzy hashing or threat-intel
  lookup; one changed byte defeats the known-bad list.
- **Monitoring is a 10s snapshot diff.** Anything that starts and exits
  between polls is missed, and the poller excludes its own toolchain by
  name.
- **The trained classifier is trained on synthetic data** labeled from an
  invented weighting. It shows the pipeline works, not real-world accuracy.
- **The backend mounts the Docker socket.** Compromising the backend means
  compromising the host — this is a research tool, not something to expose
  to a network.
- Storage is flat files (JSONL/JSON) with no rotation, and sessions are
  in-memory.

## Docs

- `docs/concepts.md` — every concept and technology used, and why
- `docs/superpowers/specs/` — design specs per feature
- `docs/superpowers/plans/` — the build plans those specs were implemented from
