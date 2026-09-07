# Mirraura — Design (Sub-project 1)

Status: approved for implementation planning
Date: 2026-09-07
Scope: initial build (Sub-project 1). Sub-project 2 (finishing phase, ~3 weeks after) is scoped separately at the end of this doc and is NOT built now.

## 1. Problem & Context

Academic security project (team of several, solo coder). Core idea: a **shadow honeypot** — a live shadow copy of a monitored system that inspects untrusted files/traffic in parallel with the real device, so nothing is blocked or slowed down while it's being judged — combined with a **behavioral verdict engine** that scores what it sees with an explicit confidence level and a step-by-step causal chain, instead of a black-box yes/no.

Mentor requires a polyglot stack (3-4 languages, each used where it's suited) and Python specifically.

## 2. Goals (this build)

- End-to-end, real, demoable loop: upload a file → shadow container spun up → file detonated inside it → behavior captured → verdict produced with confidence + causal chain → verdict written to a tamper-evident audit log → all of this visible live on a dashboard.
- Every technology choice must be explainable in one or two sentences (see companion `docs/concepts.md`).

## 3. Non-goals (explicitly cut from this build, deferred to sub-project 2)

- Real device fingerprint cloning — the shadow container uses the same base image as "real," not a cloned fingerprint.
- Multi-OS sensors — Linux containers only.
- Rust sensor agent — sensor is a Python script for now.
- Continuous behavioral monitoring of the "real" device — only the trigger-based (upload) path is live.
- Human-approval gate UI — rule/verdict changes are logged but not gated behind an approval screen yet.
- Trained ML classifier — verdict engine uses an explicit, transparent rule-based scorer (see §6). This is a deliberate v1: it produces the exact same output shape (label + confidence + causal chain) a trained model would, so swapping in a real classifier later is a phase-2 upgrade, not a redesign.

## 4. Architecture

```
React frontend (TypeScript)
        │  upload file / view live verdicts, audit log
        ▼
Go backend (orchestrator + API)
        │  on upload:
        │   1. create throwaway Docker network ("dummy network")
        │   2. start shadow container from base image ("shadow node")
        │   3. copy the file into it, execute it
        │   4. start Python sensor script in the container
        ▼
Python sensor (runs inside shadow container)
        │  polls process list / filesystem events / network connections
        │  emits canonical events over stdout/socket to backend
        ▼
Go backend forwards events to:
        ▼
Python verdict engine (separate process/service)
        │  hash lookup (SHA-256 vs known-bad set)
        │  rule-based behavior scorer → verdict + confidence + causal chain
        ▼
Audit log (append-only, hash-chained JSON lines file)
        ▼
Go backend pushes verdict to frontend over WebSocket, tears down shadow container + network
```

## 5. Canonical Event Schema

Every sensor observation, regardless of source, is normalized to:

```json
{
  "event_id": "uuid",
  "device_id": "shadow-<container-id>",
  "event_type": "process_spawn | file_write | file_delete | network_connect",
  "process_ref": {"pid": 1234, "name": "...", "parent_pid": 1},
  "network_ref": {"dst_ip": "...", "dst_port": 0, "protocol": "tcp"},
  "file_ref": {"path": "...", "action": "write|delete|create"},
  "timestamp": "ISO8601",
  "baseline_deviation_score": 0.0
}
```

`network_ref`/`file_ref`/`process_ref` are populated only when relevant to `event_type`.

## 6. Verdict Engine

**Static check:** SHA-256 of the uploaded sample checked against a local known-bad hash set (JSON file for now). Hit → immediate `Compromised`, confidence 1.0, causal chain = `["sample hash matches known-bad entry <hash>"]`.

**Behavioral check (if no hash hit):** a small set of weighted rules evaluated over the event stream from the shadow container, e.g.:

| Rule | Weight |
|---|---|
| Spawned unexpected child process | +0.3 |
| Wrote to a system/sensitive path | +0.25 |
| Outbound connection to a non-standard/unlisted port | +0.2 |
| Deleted or modified >N files rapidly | +0.25 |

Weights sum into a confidence score (capped at 1.0). Verdict label:
- No telemetry captured at all (sensor produced zero events — e.g. it crashed or the sample didn't run) → `Inconclusive`, confidence 0.0.
- Telemetry captured, no rule fired → `Normal`, confidence 0.0.
- Any rule(s) fired, total confidence `> 0.0` and `< 0.6` → `Suspicious`.
- Total confidence `>= 0.6` → `Compromised`.

The causal chain is literally the ordered list of rules that fired, each naming the triggering event.

**Output verdict schema:**

```json
{
  "verdict_id": "uuid",
  "sample_hash": "sha256",
  "verdict": "Normal | Suspicious | Compromised | Inconclusive",
  "confidence": 0.0,
  "causal_chain": ["rule/event descriptions in order"],
  "timestamp": "ISO8601",
  "prev_log_hash": "sha256 of previous audit log entry"
}
```

## 7. Audit Log

Append-only JSON-lines file. Each entry's stored hash = `SHA256(entry_json + prev_entry_hash)`, so any edit to an earlier entry breaks every hash after it — a lightweight hash chain, not a blockchain. Good enough for the "tamper-evident" story without needing real distributed-ledger infrastructure.

## 8. API Surface (Go backend)

- `POST /api/samples` — upload a file, triggers the full loop, returns `sample_hash` + `verdict_id` once done.
- `GET /api/verdicts` — list of past verdicts (reads audit log).
- `GET /api/verdicts/:id` — one verdict with full causal chain.
- `WS /api/live` — pushes verdict + event-stream updates as they happen, for the dashboard.

## 9. Frontend (React + TypeScript)

- Upload screen (drag a file in).
- Live event feed for the current run (streams from the shadow container in near-real-time).
- Verdict result panel: label, confidence meter, causal chain listed step by step.
- Audit log table (past runs, hash-chain visibly intact).

## 10. Testing

- Python: unit tests on the rule scorer (given a synthetic event list, assert verdict/confidence/causal chain) and on the hash-chain audit log (tamper a middle entry, assert the chain verification fails).
- Go: integration test that spins up a container against a known-safe test image and asserts teardown happens even on error.
- End-to-end manual test script: the 3-4 synthetic "malicious-looking" scripts (see §11) each mapped to an expected verdict, run before the demo as a checklist.

## 11. Demo Sample Set (safe, synthetic)

- EICAR test file → known-bad hash hit → `Compromised`, confidence 1.0.
- A script that spawns a child process and writes to `/etc/` → behavioral rules fire → `Compromised` or `Suspicious`.
- A script that opens a connection to a non-standard port only → single rule fires → `Suspicious`.
- A harmless script (e.g. prints text, writes to `/tmp/`) → no rules fire → `Normal`.

## 12. Tech Stack & Why (summary — full explanations in `docs/concepts.md`)

- **Go** — backend orchestrator: Docker SDK, concurrency for managing container lifecycle + WebSocket fan-out.
- **Python** — verdict engine (rule scorer, hash chain) and the in-container sensor script: fastest to write correct data-shuffling/scoring logic, and it's the mentor-required language.
- **TypeScript + React** — dashboard.
- **Docker** — provides the "dummy network" (a Docker network) and "shadow node" (a container), without needing real VM/hypervisor infrastructure.

## 13. Portability (run on any teammate's device)

**Requirement:** any teammate with Docker installed can clone the repo and run the full project with one command — no manual language/runtime installs, no machine-specific paths.

- **`docker-compose.yml` at the repo root** defines every service: `backend` (Go), `verdict-engine` (Python), `frontend` (React, served via a small static/dev server), plus the shadow-container base image is built from a `Dockerfile` checked into the repo (not pulled from an untracked local image).
- **One command to run:** `docker compose up --build`. That's the whole setup story for the demo.
- **Config via `.env`** — a checked-in `.env.example` lists every required variable (ports, known-bad hash file path, etc.); nothing is hardcoded to one machine.
- **Only host prerequisite:** Docker (+ Docker Compose, bundled with Docker Desktop). The backend needs access to the host's Docker socket to spin up shadow containers, which `docker-compose.yml` mounts explicitly.
- **No absolute paths / no machine-specific assumptions** anywhere in code — everything relative to the repo root or configured via env vars.

This also means the "dummy network" and "shadow node" containers are created *by* the already-running backend container talking to the host Docker daemon — same mechanism in dev, on a teammate's laptop, or in the demo.

## 14. Sub-project 2 (finishing phase, ~3 weeks — scoped later in detail)

- Continuous behavioral monitoring service on the "real" container (baseline deviation scoring, independent of upload trigger).
- Human-approval gate: new/changed rules sit in a "pending" state until approved in the UI before they affect live verdicts.
- Re-validation loop: replay archived event captures against an updated rule set/model, report before/after detection rate ("red-to-green flip").
- Rust rewrite of the sensor agent (swap-in replacement for the Python sensor, same event schema out).
- Optional: real trained classifier (e.g. logistic regression/small tree model over behavioral features) replacing/augmenting the rule scorer, trained on captured event logs from your own synthetic runs.
