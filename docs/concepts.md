# Mirraura — Concepts & Tech Notes (review prep)

Plain-English notes on every concept and technology used, so you can explain the "what" and "why" without fumbling. Organized so you can read top to bottom as a script, or jump to whatever the examiner asks about.

**This file is a living document.** Every time a new tool, library, or language gets added to the project, add an entry for it here — what it is, why it was chosen over the alternatives. This is the doc teammates read to get oriented, so keep it current as the project grows.

## About This Project

Mirraura is a security-research project: a **shadow honeypot** that detonates an untrusted uploaded file inside a throwaway Docker container (instead of the real device), watches what it does, and scores the behavior with a confidence level and a plain-English explanation — not just a yes/no.

Mirraura actually ships **two** independent detection paths that both feed the same verdict engine: the upload-triggered shadow honeypot described above, and an always-on continuous-monitoring path (see "Continuous behavioral monitoring — concepts" below) that watches a persistent container the whole time it's running, not just at a single upload moment.

**Current architecture:**
- A **Go** backend orchestrates the Docker lifecycle (spin up a network + container per upload, run the sample, tear down) and exposes the API/WebSocket the frontend talks to. It also runs a second, independent path: a background ticker that polls a persistent `mirraura-monitored-endpoint` container every 10 seconds, scores what it finds with the same verdict engine, and — on a `Compromised` verdict — disconnects that container from its network for real (containment), with reconnection only ever triggered by a human via the dashboard.
- A **Python** verdict engine (FastAPI) does the actual scoring: a known-bad hash lookup plus a weighted rule-based behavioral scorer, and owns the tamper-evident audit log. It scores both paths identically — it has no idea whether a batch of events came from a one-shot upload or a continuous-monitoring poll cycle.
- A **Python** sensor runs inside the shadow container, traces the sample's syscalls via `strace`, and reports what it saw in a common event format.
- A **Python** poller (`monitored-endpoint/poller.py`) runs inside the always-on monitored container, snapshotting processes/connections/files every cycle and diffing against the previous cycle to find what's new — see "Continuous behavioral monitoring" below for why this is a different capture mechanism than `strace`.
- A **React + TypeScript** dashboard shows the live event feed, the verdict, and the audit log in real time, plus an isolation banner and a "Reconnect" control for the continuous-monitoring path.
- Everything ships as one **Docker Compose** stack (`docker compose up --build`) so it runs identically on any teammate's machine.

See "The loop, in one sentence each" and "The continuous-monitoring loop, in one sentence each" at the bottom of this file for the two request-to-verdict walkthroughs, and the design spec (`docs/superpowers/specs/2026-09-07-mirraura-design.md`) for the complete requirements this was built against.

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

## Continuous behavioral monitoring — concepts (Sub-project 2, item 1)

**Continuous behavioral monitoring** — Not everything a system does happens at a single, clearly-marked "download" moment — a device can also just start acting strangely on its own (a background process that shouldn't be there, an unexpected outbound connection). A continuous monitoring layer doesn't wait for a trigger; it watches a device the whole time it's running and feeds what it sees into the *same* verdict engine that scores uploaded files. This closes the gap between "we checked this one file" and "we know this device is still behaving normally."
*In Mirraura:* a persistent `mirraura-monitored-endpoint` container stands in for "the real device," polled every 10 seconds, scored by the exact same rule-based scorer the shadow node already uses — no new scoring logic, just a new source of events.

**Poll-and-diff (snapshot diffing)** — Instead of tracing every syscall in real time (expensive, and complex to set up correctly for a long-running, ever-changing set of processes), you take a snapshot of what's running/connected/present *right now*, compare it to the previous snapshot, and only report what's genuinely *new*. It's a much lighter-weight way to notice change over time — the same principle a lot of real monitoring agents use (poll every N seconds, diff, alert on the delta) instead of instrumenting everything continuously.
*In Mirraura:* `poller.py` watches **three** things every cycle inside the monitored container — processes (`ps`), network connections (`ss`), and new top-level files under `/etc` (a plain `os.listdir`) — diffs each against the previous cycle's saved state file, and emits a canonical event only for what's new. This third leg matters more than it looks: the verdict engine's `sensitive_write` and `rapid_file_changes` rules are what make a `Compromised` verdict (and therefore real network isolation) reachable from continuous monitoring at all — a run that only ever reports new processes/connections can climb into `Suspicious` territory but not past it. A quiet cycle with nothing new produces zero events — and zero events means the cycle is skipped entirely rather than manufacturing a hollow "Inconclusive" verdict every 10 seconds.

**Cold-start baseline** — The very first poll after a monitored container starts up has no "previous snapshot" to diff against — every process, connection, and file that's already there (init, the shell, whatever the base image ships with) would otherwise look indistinguishable from something that just appeared. Reporting all of that as "new" on cycle one would trip the scorer into an immediate, spurious `Compromised`/isolation before the device has done anything at all.
*In Mirraura:* `poller.py` detects the first run (no saved state file yet), saves that first snapshot as the baseline, and returns without emitting any events or scoring anything. Diffing — and therefore detection — only starts from the *second* poll cycle onward, once there's something real to compare against.

**Self-process exclusion** — A poller that watches "what processes are running" will, by definition, see itself: its own `python3` interpreter plus the `ps`/`ss` subprocesses it shells out to each cycle. Without filtering those out, every single poll cycle would report its own toolchain as "newly spawned processes," permanently drowning real signal in self-generated noise.
*In Mirraura:* `differ.py`'s `POLLER_OWN_PROCESSES` set (`python3`, `ps`, `ss`) excludes those names from the diff by name. It's a deliberately cheap approach with a named ceiling (see the `ponytail:` comment above it in `differ.py`) — an attacker-spawned process that happens to share one of those names would also be silently excluded — but for this build, filtering by name is enough to keep the poller from talking about itself.

**Containment / network isolation** — Detecting a compromise is only half the point; the other half is stopping it from spreading before a human even looks at it. Network isolation means cutting the suspicious device's route to everything else on the network — but you (the operator) don't lose the ability to inspect it, because inspection tooling can go through a separate management channel instead of the device's own network path.
*In Mirraura:* on a `Compromised` verdict, the backend disconnects the monitored container from its dedicated Docker network via the Docker API — real containment, not just a dashboard warning. `docker exec` still works on the isolated container afterward, since exec goes through the Docker daemon's socket, not the container's own (now-cut) network interface — so monitoring continues even while the device is contained.

**Human-triggered recovery (no auto-reconnect)** — Any system that can automatically lock something down needs an equally deliberate way to undo it — otherwise one false positive permanently breaks the thing you were protecting. The fix isn't to make containment less aggressive; it's to make *un*-containing something require a human decision every single time, with nothing — no timer, no automatic condition — that reverses it on its own.
*In Mirraura:* the only way an isolated container gets reconnected is a person clicking "Reconnect" on the dashboard, which calls `POST /api/monitor/reconnect`. Both the isolate action and the reconnect action get written to the same tamper-evident audit log as every other verdict — the containment decision is as accountable as the detection that triggered it.

**Content-addressed identity for non-file inputs** — Content-addressed hashing (already used for uploaded files) normally means "hash the file's bytes" so identical content always gets the same identifier. Continuous monitoring doesn't have a single file to hash — it has a batch of behavior events. Applying the same principle to *something else reproducible* (the event batch itself) keeps the "every judgment is content-addressed" property true even when there's no literal file involved.
*In Mirraura:* each poll cycle's batch of new events is SHA-256 hashed, and that hash is passed to the verdict engine as `sample_hash` — same field, same meaning ("exactly what was judged"), just applied to a different kind of input than a file upload.

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

**procps (`ps`) / iproute2 (`ss`) (continuous monitoring, inside `monitored-endpoint`)** — Standard Linux utilities for listing running processes and open network connections/sockets, respectively. Present in essentially every Linux distribution already — no custom monitoring agent needed, just shell out to tools that already know how to answer "what's running right now" and "what's connected right now."
*In Mirraura:* `poller.py` runs both once per poll cycle and diffs their output against the previous cycle's saved snapshot to find what's new — this is the whole capture mechanism for continuous monitoring, deliberately simpler than the shadow node's `strace`-based tracing since there's no single command to trace here, just an always-running device to watch.

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

This is the upload-triggered path specifically. A second, independent loop — continuous monitoring — runs the whole time the stack is up, whether or not anyone ever uploads a file. It's covered separately below since it's a different trigger, a different capture mechanism, and a different (real, not throwaway) container.

## The continuous-monitoring loop, in one sentence each

1. **Stand up** — a persistent `mirraura-monitored-endpoint` container runs the whole time the stack is up, standing in for "the real device."
2. **Tick** — every 10 seconds, the Go backend's ticker calls into the container to run one poll cycle.
3. **Baseline or diff** — the poller snapshots processes/connections/`/etc` files; on the very first cycle it just saves that as the baseline, otherwise it diffs against the previous cycle's saved snapshot.
4. **Emit** — genuinely new processes, connections, or files become canonical events, with the poller's own toolchain filtered out.
5. **Skip if quiet** — a cycle with zero new events is dropped without scoring anything, since silence is the expected steady state here.
6. **Score** — a non-empty batch is content-addressed (SHA-256 of the event batch) and scored by the exact same verdict engine and rule set the shadow-honeypot path uses.
7. **Contain, if warranted** — a `Compromised` verdict disconnects the monitored container from its Docker network via the Docker API, a real containment action, not just a dashboard warning.
8. **Show** — the frontend shows the live event feed, the verdict, and an isolation banner when the container is cut off.
9. **Recover, on human say-so** — nothing reconnects the container automatically; only a person clicking "Reconnect" on the dashboard does, and both the isolate and reconnect actions are written to the same tamper-evident audit log as every verdict.
