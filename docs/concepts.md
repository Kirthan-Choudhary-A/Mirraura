# Mirraura — Concepts & Tech Notes (review prep)

Plain-English notes on every concept and technology used, so you can explain the "what" and "why" without fumbling. Organized so you can read top to bottom as a script, or jump to whatever the examiner asks about.

## Core security concepts

**Shadow honeypot** — A research concept (Anagnostakis et al.) where, instead of a honeypot that just sits there waiting to be attacked, you run a live *shadow copy* of the real system that inspects anything untrusted *in parallel* with the real device. The real device is never blocked waiting for a verdict — it keeps working while the shadow copy takes the risk. Only if the shadow copy's verdict comes back bad does the real device get protected/blocked. That's the "shadow" — a parallel mirror, not a passive trap.
*In Mirraura:* the shadow container plays this role. The uploaded file is detonated there, not on the real device.

**Dummy network** — A throwaway, isolated network segment created just for one inspection run, so anything the shadow node does (make connections, get infected) can't reach the real network. In Mirraura this is a Docker network created per run and torn down afterward.

**Canonical event schema** — Every sensor, no matter what it's watching (a process starting, a file being written, a network connection opening), reports its observation in the *same* shape (`event_type`, `timestamp`, `process_ref`, etc.). This matters because it means the verdict engine doesn't need to know or care which sensor produced an event — it just reads the common schema. This is the same idea SIEM tools use with OCSF (Open Cybersecurity Schema Framework); Mirraura defines its own small version of that idea.

**Verdict + confidence scoring** — Instead of a binary "malicious/not malicious," every judgment gets a label (`Normal / Suspicious / Compromised / Inconclusive`) *and* a numeric confidence (0.0–1.0). This is more honest — a real detection system is rarely 100% sure, and expressing that explicitly is more defensible than pretending certainty.

**Causal chain** — The ordered list of specific reasons *why* a verdict was reached (e.g. "spawned unexpected child process", "wrote to /etc/"). This is what makes the system's decision explainable rather than a black box — you can point to exactly which observed behavior drove the score, which is the headline "AI safety / explainability" feature for the report.

**Content-addressed hashing (SHA-256)** — Every sample is identified by the SHA-256 hash of its bytes, not a filename. Two identical files always get the same hash, so "have we seen this before" becomes a simple lookup, and results are reproducible — anyone can re-hash the same file and get the same identifier.

**Immutable / hash-chained audit log** — Every verdict is appended to a log file, and each entry's stored hash is computed from *its own content plus the previous entry's hash*. If anyone edits an old entry, its hash changes, which breaks every hash after it — so tampering is detectable. This is the same core idea blockchains use (a hash chain), without needing real distributed-ledger infrastructure — just one append-only file.

**Rule-based scorer (v1) vs. trained ML classifier (later)** — The prototype's verdict engine uses hand-written, weighted rules ("spawned child process: +0.3") instead of a trained model. This is a deliberate choice, not a shortcut you have to hide: with only synthetic demo samples, there isn't enough real data to train something meaningful yet, and a transparent rule set is *more* explainable, not less. It outputs the exact same shape (label + confidence + causal chain) a trained model would, so it's a clean drop-in replacement later — which becomes your "phase 2" story: replace the scorer with a trained classifier and show the detection rate improve.

**Human-approval gate** (phase 2) — No automatically-generated rule or model update goes live on its own; a human has to review and approve it first. This mirrors a real security principle: never let an automated system silently change what it considers "safe" without oversight.

**Re-validation loop** (phase 2) — After updating the scorer/model, you replay old recorded runs through it and check whether it now catches things it used to miss. That before/after comparison ("X% of previously-missed samples now detected") is a concrete, demoable improvement metric.

## Tech stack

**Go (backend orchestrator)** — Chosen because it's genuinely good at exactly what the orchestrator needs: talking to the Docker API to spin up/tear down containers and networks, and handling many concurrent things (multiple runs, a live WebSocket feed to the frontend) without much ceremony. It compiles to a single binary, which is also just convenient for a demo.

**Python (verdict engine + in-container sensor)** — Chosen because it's fast to write correct data-processing/scoring logic in, it's the natural language for anything ML-adjacent (so the phase-2 trained classifier slots in with no rewrite), and it's what your mentor expects to see.

**TypeScript + React (frontend)** — A standard, well-supported way to build a live dashboard (file upload, a real-time event feed, verdict display, audit log table) with strong typing so the UI's data shapes stay honest against the backend's schemas.

**Docker (infrastructure, not a "language" but worth explaining)** — Provides both the "dummy network" (a Docker network) and the "shadow node" (a container) without needing real virtual machines or hypervisor setup. It's what makes the whole loop scriptable and demoable on a single laptop in the time available.

**WebSocket** — A persistent two-way connection between backend and frontend, used so the dashboard shows events and verdicts *as they happen* during a run, instead of the user having to refresh a page.

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
