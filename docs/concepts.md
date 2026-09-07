# Mirraura — Concepts & Tech Notes (review prep)

Plain-English notes on every concept and technology used, so you can explain the "what" and "why" without fumbling. Organized so you can read top to bottom as a script, or jump to whatever the examiner asks about.

**This file is a living document.** Every time a new tool, library, or language gets added to the project, add an entry for it here — what it is, why it was chosen over the alternatives. This is the doc teammates read to get oriented, so keep it current as the project grows.

## About This Project

Mirraura is a security-research project: a **shadow honeypot** that detonates an untrusted uploaded file inside a throwaway Docker container (instead of the real device), watches what it does, and scores the behavior with a confidence level and a plain-English explanation — not just a yes/no.

**Current architecture:**
- A **Go** backend orchestrates the Docker lifecycle (spin up a network + container per upload, run the sample, tear down) and exposes the API/WebSocket the frontend talks to.
- A **Python** verdict engine (FastAPI) does the actual scoring: a known-bad hash lookup plus a weighted rule-based behavioral scorer, and owns the tamper-evident audit log.
- A **Python** sensor runs inside the shadow container, traces the sample's syscalls via `strace`, and reports what it saw in a common event format.
- A **React + TypeScript** dashboard shows the live event feed, the verdict, and the audit log in real time.
- Everything ships as one **Docker Compose** stack (`docker compose up --build`) so it runs identically on any teammate's machine.

See "The loop, in one sentence each" at the bottom of this file for the full request-to-verdict walkthrough, and the design spec (`docs/superpowers/specs/2026-09-07-mirraura-design.md`) for the complete requirements this was built against.

## Core security concepts

**Shadow honeypot** — A research concept (Anagnostakis et al.) where, instead of a honeypot that just sits there waiting to be attacked, you run a live *shadow copy* of the real system that inspects anything untrusted *in parallel* with the real device. The real device is never blocked waiting for a verdict — it keeps working while the shadow copy takes the risk. Only if the shadow copy's verdict comes back bad does the real device get protected/blocked. That's the "shadow" — a parallel mirror, not a passive trap.
*In Mirraura:* the shadow container plays this role. The uploaded file is detonated there, not on the real device.

**Dummy network** — A throwaway, isolated network segment created just for one inspection run, so anything the shadow node does (make connections, get infected) can't reach the real network. In Mirraura this is a Docker network created per run and torn down afterward.

**Canonical event schema** — Every sensor, no matter what it's watching (a process starting, a file being written, a network connection opening), reports its observation in the *same* shape (`event_type`, `timestamp`, `process_ref`, etc.). This matters because it means the verdict engine doesn't need to know or care which sensor produced an event — it just reads the common schema. This is the same idea SIEM tools use with OCSF (Open Cybersecurity Schema Framework); Mirraura defines its own small version of that idea.

**Verdict + confidence scoring** — Instead of a binary "malicious/not malicious," every judgment gets a label (`Normal / Suspicious / Compromised / Inconclusive`) *and* a numeric confidence (0.0–1.0). This is more honest — a real detection system is rarely 100% sure, and expressing that explicitly is more defensible than pretending certainty.

**Causal chain** — The ordered list of specific reasons *why* a verdict was reached (e.g. "spawned unexpected child process", "wrote to /etc/"). This is what makes the system's decision explainable rather than a black box — you can point to exactly which observed behavior drove the score, which is the headline "AI safety / explainability" feature for the report.

**Content-addressed hashing (SHA-256)** — Every sample is identified by the SHA-256 hash of its bytes, not a filename. Two identical files always get the same hash, so "have we seen this before" becomes a simple lookup, and results are reproducible — anyone can re-hash the same file and get the same identifier.

**Immutable / hash-chained audit log** — Every verdict is appended to a log file, and each entry's stored hash is computed from *its own content plus the previous entry's hash*. If anyone edits an old entry, its hash changes, which breaks every hash after it — so tampering is detectable. This is the same core idea blockchains use (a hash chain), without needing real distributed-ledger infrastructure — just one append-only file.

**Rule-based scorer (v1) vs. trained ML classifier (later)** — Mirraura's verdict engine uses hand-written, weighted rules ("spawned child process: +0.3") instead of a trained model. This is a deliberate choice, not a shortcut you have to hide: with only synthetic demo samples, there isn't enough real data to train something meaningful yet, and a transparent rule set is *more* explainable, not less. It outputs the exact same shape (label + confidence + causal chain) a trained model would, so it's a clean drop-in replacement later — which becomes your "phase 2" story: replace the scorer with a trained classifier and show the detection rate improve.

**Human-approval gate** (phase 2) — No automatically-generated rule or model update goes live on its own; a human has to review and approve it first. This mirrors a real security principle: never let an automated system silently change what it considers "safe" without oversight.

**Re-validation loop** (phase 2) — After updating the scorer/model, you replay old recorded runs through it and check whether it now catches things it used to miss. That before/after comparison ("X% of previously-missed samples now detected") is a concrete, demoable improvement metric.

## Languages — what and why

**Go (backend orchestrator, `backend/`)** — Genuinely good at exactly what the orchestrator needs: talking to the Docker API to spin up/tear down containers and networks, and handling many concurrent things (multiple runs, a live WebSocket feed to the frontend) without much ceremony. Compiles to a single binary — convenient for a demo, no runtime to install on the machine that runs it.

**Python (verdict engine + in-container sensor, `verdict-engine/`, `sensor/`)** — Fast to write correct data-processing/scoring logic in, the natural language for anything ML-adjacent (so a phase-2 trained classifier slots in with no rewrite), and the language the mentor expects to see used.

**TypeScript + React (frontend, `frontend/`)** — A standard, well-supported way to build a live dashboard (file upload, a real-time event feed, verdict display, audit log table) with strong typing so the UI's data shapes stay honest against the backend's schemas.

## Tools & libraries — what and why

**Docker** — Provides both the "dummy network" (a Docker network) and the "shadow node" (a container) without needing real virtual machines or hypervisor setup. Makes the whole loop scriptable and demoable on a single laptop.

**Docker Compose (portability)** — A single YAML file (`docker-compose.yml`, `name: mirraura`) describing every service and how they connect. Anyone with Docker installed runs `docker compose up --build` (via `setup.sh`, which also builds the shadow image first) and gets the identical setup — same versions, same config, no per-teammate manual installs. This is what makes the project run identically on any machine.

**strace (sensor, inside the shadow container)** — A standard Linux tool that logs every syscall a process makes. The sensor runs the sample under `strace -f -e trace=execve,openat,connect` so it sees process spawns, file writes, and network connections without writing a custom kernel-level instrumentation layer — a well-understood, battle-tested way to observe behavior cheaply.

**FastAPI (verdict engine, Python)** — Chosen over a bare Flask app because it validates incoming/outgoing JSON against typed models (Pydantic) automatically, which is exactly what a service defining a strict canonical event/verdict schema wants — a malformed request gets rejected with a clear error instead of silently corrupting a verdict.

**Pydantic (verdict engine, Python)** — FastAPI's typed-model layer; this is *where* the canonical event/verdict schema actually lives in code (`verdict-engine/schemas.py`) — one source of truth that both validates requests and serializes responses.

**pytest (Python testing, `verdict-engine/`, `sensor/`)** — The standard Python test runner; used with plain `assert` statements and, for the audit log, `tmp_path`/`conftest.py` fixtures so tests never touch real state on disk.

**gorilla/websocket (Go)** — The standard, well-known Go WebSocket library (Go's standard library doesn't include WebSocket support) — used for the live event feed to the dashboard.

**docker/docker (Go)** — The official Docker Engine SDK for Go; used instead of hand-rolling raw HTTP calls to the Docker socket, since container/network lifecycle management (create, start, exec, copy files in, teardown) is exactly what it's built for.

**Vite + Vitest (frontend)** — Vite for a fast dev server and build (React + TypeScript template); Vitest (Vite-native test runner) for the one meaningful frontend unit test (the API client's request/response shapes) — no separate test-runner config needed since it shares Vite's setup.

**WebSocket (protocol, used by gorilla/websocket + the browser's native `WebSocket` API)** — A persistent two-way connection between backend and frontend, so the dashboard shows events and verdicts *as they happen* during a run instead of the user having to refresh.

## The loop, in one sentence each

1. **Trigger** — user uploads a file through the frontend.
2. **Isolate** — backend creates a throwaway Docker network and a shadow container.
3. **Detonate** — the file is copied into the shadow container and executed there, never on the real device.
4. **Observe** — a Python sensor inside the container watches process/file/network activity and emits canonical events.
5. **Score** — the Python verdict engine checks the file's hash against known-bad samples, then scores behavior against weighted rules.
6. **Explain** — the verdict comes with a confidence number and the exact list of reasons (causal chain).
7. **Record** — the verdict is appended to a hash-chained audit log, so it can't be silently altered later.
8. **Show** — the frontend displays the live event feed, the verdict, and the audit log.
9. **Teardown** — the shadow container and network are destroyed.
