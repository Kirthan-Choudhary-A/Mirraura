# Mirraura — Continuous Behavioral Monitoring (Sub-project 2, item 1)

Status: approved for implementation planning
Date: 2026-09-08
Scope: first item of the Sub-project 2 finishing phase. Builds on the completed prototype (Go backend, Python verdict engine, sensor, React frontend, all merged to `main`).

## 1. Problem & Context

The current system only inspects files on upload: a shadow container is spun up per file, detonated, scored, and torn down. There is no persistent "real device" being watched — the spec's original design calls for an always-on behavioral monitoring layer, independent of the upload trigger, feeding into the same verdict engine. This sub-project builds that layer.

## 2. Goals

- A persistent, always-up container ("the monitored endpoint") stands in for the real device.
- Its behavior is polled periodically and scored by the *existing* rule-based verdict engine — no new scoring logic.
- A `Compromised` verdict triggers real containment: the container is disconnected from its network.
- A human can undo containment with one action (Reconnect) — no automatic un-isolation, ever.
- Every isolate/reconnect action is recorded in the existing tamper-evident audit log.
- Events and verdicts from this flow appear in the same dashboard feed as upload-triggered ones.

## 3. Non-goals

- No new capture mechanism beyond periodic poll-and-diff (no continuous/system-wide `strace`).
- No automatic reconnect, no retry/backoff policy, no alerting beyond the dashboard.
- No new scoring model — reuses the verdict-engine's `/score` endpoint and rule weights exactly as built.
- No multi-instance/HA concerns — a single in-memory isolation flag on the one backend instance is sufficient.

## 4. Architecture

```
docker-compose (always up)
  monitored-endpoint container ──┐  (on its own network: mirraura-monitor-net)
                                  │
Go backend, ticker every ~10s:   │
  1. docker exec into the container, run poller.py
  2. poller diffs current vs. previous snapshot (processes, connections),
     emits new canonical events, updates its state file
  3. if zero new events → skip this cycle entirely (no manufactured verdicts)
  4. if events exist → hash the batch (SHA-256) → POST to verdict-engine /score
  5. broadcast event(s) + verdict over the existing WebSocket
  6. if verdict == Compromised and not already isolated:
       docker network disconnect mirraura-monitor-net <container>
       flip isolated=true, audit-log the action, broadcast {"type":"isolated"}
  (docker exec keeps working on an isolated container — it goes through
   the Docker daemon socket, not the container's own network path —
   so polling continues even while contained)

Dashboard: shows an "Isolated" banner + Reconnect button when isolated=true.
POST /api/monitor/reconnect → docker network connect ... → flip flag,
  audit-log the action, broadcast {"type":"reconnected"}.
```

## 5. Components

- **`monitored-endpoint/Dockerfile`** — minimal image with `ps`/`ss` (procps + iproute2), no `strace` needed.
- **`monitored-endpoint/poller.py`** — pure diff function (`diff_snapshots(prev, curr) -> list[event]`) plus a thin main that reads/writes a local state file (e.g. `/var/run/poller_state.json`) between invocations and prints new events as canonical JSON lines (same shape the shadow sensor already emits: `event_id, device_id, event_type, process_ref/network_ref/file_ref, timestamp, baseline_deviation_score`).
- **`docker-compose.yml`** — add:
  ```yaml
  monitored-endpoint:
    build: ./monitored-endpoint
    container_name: mirraura-monitored-endpoint
    networks: [monitor-net]

  networks:
    monitor-net:
      name: mirraura-monitor-net
  ```
  This container is never dynamically created/torn down by the backend — compose owns its lifecycle entirely, same as `backend`/`verdict-engine`/`frontend`. The backend only references it by its fixed name.
- **`backend/monitor.go`** — new type (or functions) using the existing `DockerManager`'s Docker client:
  - `PollOnce(ctx) ([]json.RawMessage, error)` — `docker exec mirraura-monitored-endpoint python3 /poller/poller.py`, same channel/scan pattern as `RunSensor`, but called once per tick rather than streamed.
  - `IsolateContainer(ctx) error` — `NetworkDisconnect(ctx, "mirraura-monitor-net", "mirraura-monitored-endpoint", false)`.
  - `ReconnectContainer(ctx) error` — `NetworkConnect(ctx, "mirraura-monitor-net", "mirraura-monitored-endpoint", nil)`.
  - An `isolated bool` guarded by a mutex (single-process in-memory state; `ponytail: in-memory flag, move to the audit log's own read-path if a second backend instance ever exists`).
- **`backend/monitor_handlers.go`**:
  - `GET /api/monitor/status` → `{"isolated": bool}`.
  - `POST /api/monitor/reconnect` → 400 if not currently isolated, else calls `ReconnectContainer`, flips flag, logs, broadcasts.
- **`main.go`** — starts one ticker goroutine (10s) alongside the HTTP server; on each tick runs the poll→score→(maybe isolate) sequence described in §4.
- **Frontend**: one `MonitorBanner` component (isolated status + Reconnect button, calls the new endpoint, listens for `isolated`/`reconnected` WebSocket messages) rendered in `App.tsx` alongside the existing panels. `api.ts` gets `reconnectMonitor(): Promise<void>`.
- **Verdict-engine**: unchanged. The batch's SHA-256 hash is passed as `sample_hash` — keeps the "every judgment is content-addressed" principle intact even though this isn't a file upload.

## 6. Canonical Event Reuse

`poller.py` emits the exact schema already defined in `verdict-engine/schemas.py` / `backend/types.go` / `frontend/src/types.ts`: `event_id, device_id, event_type, process_ref{pid,name,parent_pid}, network_ref{dst_ip,dst_port,protocol}, file_ref{path,action}, timestamp, baseline_deviation_score`. `device_id` for this flow is a fixed string (e.g. `"monitored-endpoint"`) distinguishing it from `"shadow-node"` in the dashboard feed.

## 7. Error Handling

- `docker exec` fails (container restarting, transient daemon error) → log, skip this cycle, retry next tick. Never crashes the ticker loop.
- Verdict-engine unreachable → same skip-and-retry, matching the existing `scoreWithVerdictEngine` error path.
- `IsolateContainer`/`ReconnectContainer` failures → log the error, broadcast an error status; do not retry automatically (a stuck isolate/reconnect needs a human look, not a retry loop guessing at Docker daemon state).
- The `isolated` flag guards against double-isolate or double-reconnect calls (reconnect endpoint returns 400 if not isolated; isolate is skipped if already isolated).

## 8. Testing

- **Go**: unit test for the poll→score→isolate decision function using a fake `DockerManager` (returns canned events) and an `httptest` fake verdict-engine — asserts: zero events → no scoring call; `Compromised` verdict → isolate called once, not called again on a second `Compromised` tick while already isolated. Integration test (real Docker, like `TestShadowNetworkAndContainerLifecycle`) for `IsolateContainer`/`ReconnectContainer` actually disconnecting/reconnecting a real container's network.
- **Python**: unit test for `diff_snapshots(prev, curr)` — pure function, fixture snapshots in, expected new-event list out (empty-both, new-process-only, new-connection-only, nothing-new cases).
- **Manual end-to-end**: bring up the stack, `docker exec` into `mirraura-monitored-endpoint` and spawn a process that trips the existing rule weights (e.g. touch a file under `/etc/`), watch the dashboard show the event → verdict → isolated banner, click Reconnect, confirm the container is back on its network and the audit log shows both actions.

## 9. Global Constraints (for the implementation plan)

- Container name: `mirraura-monitored-endpoint` (fixed, compose-managed).
- Network name: `mirraura-monitor-net` (fixed, compose-managed, separate from the default `mirraura` network `backend`/`verdict-engine`/`frontend` share).
- Poll interval: 10 seconds.
- `device_id` for this flow: `"monitored-endpoint"`.
- Verdict banding, rule weights, and `/score` contract: unchanged from the existing spec (`docs/superpowers/specs/2026-09-07-mirraura-design.md` §6).
- No automatic reconnect under any condition — only `POST /api/monitor/reconnect`, human-triggered.
