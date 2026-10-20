# Automatic Download Interception — Design Spec

**Timeline: 3 days to a working demo.** This spec is deliberately tight — scope was cut hard against that deadline, not against ambition.

## Goal

A background daemon running directly on the VM (not containerized) watches the user's home directory and removable media for new files. The moment a file is fully written, it is quarantined and detonated through Mirraura's existing pipeline automatically — no manual upload. Depending on the verdict, the file is released back to where it was going, held for a human to decide, or blocked outright.

## Scope

In scope (3-day build):
- The interceptor daemon itself (new `interceptor/` Go binary, runs on host).
- A new backend endpoint for the daemon to submit files, reusing the existing detonation pipeline.
- A `quarantined_files` table + admin approve/reject endpoints for the "hold" case.
- A dashboard section to review held files (pattern-matched off the existing hash-approval UI).
- gVisor as an opt-in shadow-container runtime (one config field, feature-flagged — degrades to the default runtime if gVisor isn't installed on the demo VM).

Already satisfied, no work needed: the enterprise write-up's "egress guardrails" ask (drop all non-DNS outbound during detonation) is already exceeded by existing code — `dockermanager.go`'s `CreateShadowNetwork` already creates the per-run network with `Internal: true`, meaning **zero** outbound routing at all, not just non-DNS. Nothing to build here; worth stating plainly in docs so it isn't rebuilt by mistake.

Out of scope for the 3-day build (explicitly deferred, not forgotten): YARA static triage, fuzzy hashing, a real async task queue (Redis/NATS), eBPF sensor rewrite, anti-evasion masking, Firecracker/microVMs. These get one paragraph in the final docs as the honest "where this goes next" story, matching the project's existing pattern of documented, deliberate limitations.

## Architecture

The daemon is the one piece that must run on bare host, not in a container: it needs to see the VM's real filesystem events and real mount events, which a containerized process would only see through privileged bind-mounts that reintroduce the complexity this design avoids. Everything else it talks to is the existing Dockerized stack, over HTTP, through the same nginx `/api/` path the frontend already uses.

```
┌─────────────────────────────────────────────────────────┐
│ VM host (bare, not containerized)                        │
│                                                            │
│  interceptor daemon                                       │
│   - watches $HOME (recursive, skips dotdirs + its own     │
│     quarantine dir) via fsnotify                          │
│   - polls /proc/mounts for new removable media, sweeps    │
│     its whole contents once on mount                      │
│   - debounces each path (~750ms of silence = "done        │
│     writing"), moves it into ~/.mirraura-quarantine/       │
│   - worker pool (2-3 workers) submits quarantined files    │
│     one at a time -- the burst-batching fix, no new infra  │
└──────────────────────┬──────────────────────────────────┘
                        │ POST /api/intercept (bearer token)
                        │ GET  /api/intercept/{id}/status (poll, held files only)
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Docker Compose stack (unchanged except noted)             │
│  nginx → backend → (existing detonation pipeline,         │
│                      refactored into a shared function)   │
│                   → verdict-engine → Postgres              │
└─────────────────────────────────────────────────────────┘
```

## Backend changes

**Refactor, no behavior change:** extract the body of `samplesHandler` (from writing the tmp file through scoring) into a shared function:

```go
func detonateAndScore(ctx context.Context, dm *DockerManager, verdictEngineURL string, hub Broadcaster, data []byte, filename, source, actor string) (*Verdict, error)
```

`samplesHandler` becomes a thin wrapper that reads the multipart file, resolves `actor` from the session, and calls this. This is the only change to the existing upload path — same tests, same behavior, just DRY so the new path doesn't duplicate detonation logic.

**New endpoint: `POST /api/intercept`** — not session-gated (there's no logged-in human on the other end); gated instead by a bearer token (`Authorization: Bearer <INTERCEPTOR_TOKEN>`, a new env var, same shared-secret pattern already used between internal services). Body: multipart, `sample` file field (same as today) plus an `original_path` form field. Calls `detonateAndScore(..., actor="interceptor")`, then maps the verdict to a decision:

| Verdict | Decision | What the daemon does |
|---|---|---|
| `Normal` | `release` | Move the file back to `original_path` immediately. |
| `Suspicious` / `Inconclusive` | `hold` | Leave it quarantined; insert a `quarantined_files` row; daemon polls for a decision. |
| `Compromised` | `block` | Leave it quarantined (never restored); fire a desktop notification. |

Response: `{"verdict": {...}, "decision": "release"|"hold"|"block", "quarantine_id": <int, present only for "hold">}`.

**New table, `quarantined_files`** (backend-owned, same migration pattern as `sessions`/`users`):
```sql
CREATE TABLE quarantined_files (
  id BIGSERIAL PRIMARY KEY,
  sample_hash TEXT NOT NULL,
  filename TEXT NOT NULL,
  original_path TEXT NOT NULL,
  verdict_label TEXT NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')) DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ
);
```
Only written for `hold` outcomes — `release`/`block` never need a row since the daemon acts immediately without waiting on anything.

**New admin endpoints** (session-gated, admin-only, same pattern as hash approval):
- `GET /api/intercept/pending` — list pending rows, for the dashboard.
- `POST /api/intercept/{id}/approve` — `status → approved`, `decided_at = now()`.
- `POST /api/intercept/{id}/reject` — `status → rejected`, `decided_at = now()`.

**New daemon-facing endpoint** (bearer-token-gated): `GET /api/intercept/{id}/status` — `{"status": "pending"|"approved"|"rejected"}`. The daemon polls this every ~5s for any file it's holding.

Every decision (release/hold/block, and later approve/reject) gets written to the existing audit log via the existing `logAction` helper, actor `"interceptor"` for the automatic ones and the admin's own username for approve/reject — same accountability story the rest of the project already has.

## Interceptor daemon (`interceptor/`, new Go module)

- **Watching:** `fsnotify` (well-established Go library), walked recursively from `$HOME` at startup, with a new watch added whenever a new directory is created. Skips any directory whose name starts with `.` (covers `.cache`, `.config`, `.mozilla`, `.local`, and — critically — its own quarantine directory, which must never be watched or it'll try to intercept the files it just quarantined).
- **Removable media:** polls `/proc/mounts` every ~2s for new entries under `/media` or `/mnt`; on a new mount, walks its entire existing contents once and submits every file found (so an already-infected USB drive gets swept, not just files added after the fact).
- **Debounce/stabilize:** `fsnotify` doesn't expose a clean "file fully written" signal, so each write event resets a per-path timer; after ~750ms of silence on that path, it's treated as stable and handed to the worker pool. This also does double duty as a cheap burst control — a flurry of writes from one archive extraction settles out before anything gets submitted.
- **Worker pool:** a buffered channel + 2-3 goroutines, each pulling one stable file path at a time: move to `~/.mirraura-quarantine/` (atomic rename, same filesystem), POST to `/api/intercept`, act on the response (release/hold/block), `notify-send` on the final outcome either way. This is the whole "don't let a 40-file zip extraction launch 40 containers at once" fix — no new queue infrastructure, just bounded concurrency.
- **Config:** `BACKEND_URL` (the nginx-fronted URL, e.g. `http://localhost:5173`) and `INTERCEPTOR_TOKEN` (shared secret, set once in `.env` and read by both the backend and the daemon).
- **Running as "inbuilt OS software":** a systemd unit (`mirraura-interceptor.service`) so it starts automatically and runs in the background without a terminal open — this is what makes "it just runs" actually true for the demo, not just the daemon existing.

## gVisor (opt-in shadow-container runtime)

One new env var, `SHADOW_RUNTIME` (default empty). Threaded into `StartShadowContainer`'s `container.HostConfig{Runtime: shadowRuntime}` — an empty string means "use the Docker daemon's configured default," so this is a no-op until both gVisor is installed on the VM *and* the env var is set to `runsc`. Documented as an optional hardening step, not a hard requirement — if gVisor isn't installed on the demo VM, the stack behaves exactly as it does today.

## Error handling

- Backend unreachable when the daemon tries to submit a file: retry with backoff, file stays in quarantine (fails safe — never silently released on a network error).
- A file whose detonation itself fails (sensor crash, timeout): treated as `Inconclusive` → `hold`, same as today's existing `timedOut` handling in `detonateAndScore`.
- Daemon crash/restart: quarantine directory is the daemon's own durable state — anything already moved there but not yet submitted gets picked back up by a startup sweep of the quarantine directory itself (same code path as a removable-media sweep).

## Testing

- Backend: unit tests for `detonateAndScore` (already covered by today's `samples_test.go`, extended for the new call site), the new `/api/intercept` handler (token auth, decision mapping), and the `quarantined_files` approve/reject handlers — same Postgres-backed test pattern already used throughout.
- Daemon: unit tests for the debounce/stabilize logic and the dotdir-exclusion rule (pure functions, no real filesystem needed); one real-filesystem integration test using a temp `$HOME` to confirm a written file actually gets picked up and moved to quarantine.
- End-to-end (manual, for the demo itself): drop each existing sample (`harmless.sh`, `spawn_and_write.sh`, `connect_odd_port.sh`, `eicar.txt`) into a watched directory and confirm the expected decision (release/hold/block) happens without any dashboard interaction.

## Docs

`docs/concepts.md` gets a new entry for the interceptor daemon and `fsnotify` (new dependency), per the project's own same-change convention. README gets a new "Automatic interception" section covering the systemd install step, since that's a real setup action a reader needs, not just a code change.
