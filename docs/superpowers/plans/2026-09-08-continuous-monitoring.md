# Continuous Behavioral Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persistent monitored container that's polled every 10s, scored by the existing verdict engine, with real network-disconnect containment on a `Compromised` verdict and a human-triggered Reconnect recovery path — all visible in the existing dashboard feed.

**Architecture:** A new `monitored-endpoint` Docker Compose service (always up, never torn down) runs a poll-and-diff Python script. The Go backend's ticker calls it via `docker exec` every 10s, forwards new events to the *existing* verdict-engine `/score` endpoint unchanged, and on `Compromised` disconnects the container's network via the Docker API. A new tiny verdict-engine endpoint (`/audit/action`) logs isolate/reconnect actions into the same hash-chained audit log. The frontend shows a banner + Reconnect button driven by the existing WebSocket feed.

**Tech Stack:** Go (existing `DockerManager`, `Broadcaster`), Python (FastAPI `/score` reused as-is, one new tiny endpoint), TypeScript/React (existing components extended), `ps`/`ss` (procps/iproute2) for the poll capture.

**Spec:** `docs/superpowers/specs/2026-09-08-continuous-monitoring-design.md`

## Global Constraints

- Container name: `mirraura-monitored-endpoint` (fixed, Compose-managed, never dynamically created/torn down).
- Network name: `mirraura-monitor-net` (fixed, Compose-managed, separate from the default `mirraura` network).
- Poll interval: 10 seconds.
- `device_id` for this flow: `"monitored-endpoint"`.
- Canonical event schema, verdict banding, and the `/score` contract are unchanged from `docs/superpowers/specs/2026-09-07-mirraura-design.md` §5-6.
- `sample_hash` for this flow = SHA-256 of the JSON-serialized event batch (not a file hash — same field, same "what exactly was judged" meaning).
- No automatic reconnect under any condition — only `POST /api/monitor/reconnect`, human-triggered.
- A quiet poll cycle (zero new events) skips scoring entirely — never call `/score` with an empty batch from this flow.

---

## File Structure

```
monitored-endpoint/
  Dockerfile
  differ.py              (pure functions: parse_ps_output, parse_ss_output, diff_snapshots)
  poller.py               (entrypoint: capture, diff, save state, print events)
  tests/
    test_differ.py

docker-compose.yml        (modify: add monitored-endpoint service + monitor-net network)

verdict-engine/
  app.py                  (modify: add POST /audit/action)
  tests/
    test_app.py           (modify: add test for /audit/action)

backend/
  dockermanager.go        (modify: extract execAndStream, add RunPoller/IsolateContainer/ReconnectContainer)
  dockermanager_test.go   (modify: add isolate/reconnect integration test)
  monitor.go              (new: Monitor type, Tick, Reconnect, monitorDocker interface)
  monitor_test.go         (new: fake-driven unit tests for Tick/Reconnect)
  monitor_handlers.go     (new: GET /api/monitor/status, POST /api/monitor/reconnect)
  main.go                 (modify: wire Monitor, register routes, start ticker goroutine)

frontend/src/
  api.ts                  (modify: extend LiveMessage, add reconnectMonitor/fetchMonitorStatus)
  App.tsx                 (modify: wire MonitorBanner + isolated state)
  components/
    MonitorBanner.tsx      (new)
    AuditLogTable.tsx      (modify: render action rows alongside verdict rows)
```

---

### Task 1: Poller pure functions (parse + diff)

**Files:**
- Create: `monitored-endpoint/differ.py`
- Test: `monitored-endpoint/tests/test_differ.py`

**Interfaces:**
- Produces: `parse_ps_output(text: str) -> dict[str, str]` (pid string → process name), `parse_ss_output(text: str) -> dict[str, dict]` (`"ip:port"` → `{"dst_ip", "dst_port", "protocol"}`), `diff_snapshots(prev: dict, curr: dict) -> list[dict]` (raw canonical event dicts, `event_type` + `process_ref`/`network_ref`). Consumed by `poller.py` in Task 2.

- [ ] **Step 1: Write the failing tests**

```python
# monitored-engine placeholder path note: actual path is monitored-endpoint/tests/test_differ.py
from differ import diff_snapshots, parse_ps_output, parse_ss_output


def test_parse_ps_output_skips_header():
    text = "  PID COMMAND\n    1 init\n   42 touch\n"
    assert parse_ps_output(text) == {"1": "init", "42": "touch"}


def test_parse_ss_output_only_established():
    text = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "ESTAB  0      0      10.0.0.5:41234       93.184.216.34:80\n"
        "LISTEN 0      128    0.0.0.0:22            0.0.0.0:*\n"
    )
    assert parse_ss_output(text) == {
        "93.184.216.34:80": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"}
    }


def test_no_new_processes_or_connections():
    snap = {"processes": {"1": "init"}, "connections": {}}
    assert diff_snapshots(snap, snap) == []


def test_empty_snapshots_produce_no_events():
    empty = {"processes": {}, "connections": {}}
    assert diff_snapshots(empty, empty) == []


def test_new_process_detected():
    prev = {"processes": {"1": "init"}, "connections": {}}
    curr = {"processes": {"1": "init", "42": "touch"}, "connections": {}}
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "process_spawn",
            "process_ref": {"pid": 42, "name": "touch", "parent_pid": 0},
        }
    ]


def test_new_connection_detected():
    prev = {"processes": {}, "connections": {}}
    curr = {
        "processes": {},
        "connections": {
            "93.184.216.34:80": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"}
        },
    }
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "network_connect",
            "network_ref": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"},
        }
    ]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd monitored-endpoint && pytest tests/test_differ.py -v`
Expected: FAIL (`differ` module not found)

- [ ] **Step 3: Implement the pure functions**

```python
# monitored-endpoint/differ.py
from typing import Dict, List


def parse_ps_output(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    lines = text.strip().splitlines()
    for line in lines[1:] if lines else []:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            pid, name = parts
            result[pid] = name
    return result


def parse_ss_output(text: str) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    lines = text.strip().splitlines()
    for line in lines[1:] if lines else []:
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        peer = parts[4]
        ip, sep, port = peer.rpartition(":")
        if not sep:
            continue
        key = f"{ip}:{port}"
        result[key] = {"dst_ip": ip, "dst_port": int(port), "protocol": "tcp"}
    return result


def diff_snapshots(prev: dict, curr: dict) -> List[dict]:
    events: List[dict] = []
    prev_procs = prev.get("processes", {})
    curr_procs = curr.get("processes", {})
    for pid in sorted(set(curr_procs) - set(prev_procs)):
        events.append(
            {
                "event_type": "process_spawn",
                "process_ref": {"pid": int(pid), "name": curr_procs[pid], "parent_pid": 0},
            }
        )

    prev_conns = prev.get("connections", {})
    curr_conns = curr.get("connections", {})
    for key in sorted(set(curr_conns) - set(prev_conns)):
        events.append(
            {
                "event_type": "network_connect",
                "network_ref": curr_conns[key],
            }
        )
    return events
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitored-endpoint && pytest tests/test_differ.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add monitored-endpoint/differ.py monitored-endpoint/tests/test_differ.py
git commit -m "feat: add poll-and-diff pure functions for continuous monitoring"
```

---

### Task 2: Poller entrypoint + Dockerfile

**Files:**
- Create: `monitored-endpoint/poller.py`
- Create: `monitored-endpoint/Dockerfile`

**Interfaces:**
- Consumes: `diff_snapshots`, `parse_ps_output`, `parse_ss_output` from `differ.py` (Task 1).
- Produces: `poller.py` — prints one canonical Event JSON per line to stdout, same shape the shadow sensor already emits. Consumed by the Go backend's `RunPoller` (Task 4) via `docker exec`.

No new automated tests (thin CLI wrapper over already-tested pure functions, matching how `sensor/sensor.py` was verified) — verified manually below.

- [ ] **Step 1: Write the poller entrypoint**

```python
# monitored-endpoint/poller.py
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from differ import diff_snapshots, parse_ps_output, parse_ss_output

STATE_PATH = Path("/var/run/poller_state.json")
DEVICE_ID = "monitored-endpoint"


def capture_snapshot() -> dict:
    ps_out = subprocess.run(
        ["ps", "-eo", "pid,comm"], capture_output=True, text=True
    ).stdout
    ss_out = subprocess.run(["ss", "-tn"], capture_output=True, text=True).stdout
    return {
        "processes": parse_ps_output(ps_out),
        "connections": parse_ss_output(ss_out),
    }


def load_previous() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"processes": {}, "connections": {}}


def save_current(snapshot: dict) -> None:
    STATE_PATH.write_text(json.dumps(snapshot))


def main() -> None:
    prev = load_previous()
    curr = capture_snapshot()
    raw_events = diff_snapshots(prev, curr)
    save_current(curr)

    for raw in raw_events:
        event = {
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_deviation_score": 0.0,
            **raw,
        }
        print(json.dumps(event), flush=True)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write the Dockerfile**

```dockerfile
# monitored-endpoint/Dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends procps iproute2 && rm -rf /var/lib/apt/lists/*
COPY differ.py /poller/differ.py
COPY poller.py /poller/poller.py
CMD ["sleep", "infinity"]
```

- [ ] **Step 3: Build the image and manually verify two poll cycles detect a change**

Run (from repo root):
```bash
docker build -f monitored-endpoint/Dockerfile -t mirraura-monitored-endpoint:latest .
docker run -d --name monitor-test mirraura-monitored-endpoint:latest
docker exec monitor-test python3 /poller/poller.py
```
Expected: no output (first run has no previous state to diff against, or only pre-existing processes/connections show once as a baseline — either is fine, this is the seed run).

```bash
docker exec -d monitor-test touch /tmp/marker
docker exec monitor-test sh -c "sleep 1 && bash -c 'echo test'"
docker exec monitor-test python3 /poller/poller.py
```
Expected: at least one JSON line printed with `"event_type": "process_spawn"`.

```bash
docker rm -f monitor-test
```

- [ ] **Step 4: Commit**

```bash
git add monitored-endpoint/poller.py monitored-endpoint/Dockerfile
git commit -m "feat: add poller entrypoint and monitored-endpoint Docker image"
```

---

### Task 3: Docker Compose wiring for the persistent monitored container

**Files:**
- Modify: `docker-compose.yml`

**Interfaces:** None new — this task only wires the image built in Task 2 into the stack.

- [ ] **Step 1: Add the service and network**

```yaml
# docker-compose.yml
name: mirraura

services:
  backend:
    build: ./backend
    ports:
      - "${BACKEND_PORT:-8080}:8080"
    environment:
      - BACKEND_PORT=8080
      - VERDICT_ENGINE_URL=http://verdict-engine:8000
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - verdict-engine

  verdict-engine:
    build: ./verdict-engine
    ports:
      - "${VERDICT_ENGINE_PORT:-8000}:8000"
    environment:
      - AUDIT_LOG_PATH=/data/audit_log.jsonl
    volumes:
      - audit-log-data:/data

  frontend:
    build: ./frontend
    ports:
      - "${FRONTEND_PORT:-5173}:5173"
    environment:
      - VITE_BACKEND_URL=http://localhost:${BACKEND_PORT:-8080}
    depends_on:
      - backend

  monitored-endpoint:
    build: ./monitored-endpoint
    container_name: mirraura-monitored-endpoint
    networks:
      - monitor-net

volumes:
  audit-log-data:

networks:
  monitor-net:
    name: mirraura-monitor-net
```

- [ ] **Step 2: Verify the compose file resolves and the container comes up**

Run:
```bash
docker compose config --quiet && echo "config OK"
docker compose up --build -d monitored-endpoint
docker ps --filter "name=mirraura-monitored-endpoint"
docker exec mirraura-monitored-endpoint python3 /poller/poller.py
docker compose down
```
Expected: `config OK`; the container shows `Up`; the exec runs without error (output may be empty on a quiet system).

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: add monitored-endpoint service and dedicated network to compose"
```

---

### Task 4: Go DockerManager — RunPoller, IsolateContainer, ReconnectContainer

**Files:**
- Modify: `backend/dockermanager.go`
- Modify: `backend/dockermanager_test.go`

**Interfaces:**
- Consumes: existing `*DockerManager`, `types`/`network`/`client` imports already in the file.
- Produces: `RunPoller(ctx context.Context, containerID string) (<-chan string, error)`, `IsolateContainer(ctx context.Context, networkName, containerName string) error`, `ReconnectContainer(ctx context.Context, networkName, containerName string) error` — all consumed by `backend/monitor.go` in Task 6 via the `monitorDocker` interface.

- [ ] **Step 1: Write the failing integration test**

```go
// backend/dockermanager_test.go — add this test function to the existing file
func TestIsolateAndReconnectContainer(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-isolate-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-isolate-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	if err := dm.IsolateContainer(ctx, "mirraura-isolate-test-net", "mirraura-isolate-test-container"); err != nil {
		t.Fatalf("IsolateContainer: %v", err)
	}
	if err := dm.ReconnectContainer(ctx, "mirraura-isolate-test-net", "mirraura-isolate-test-container"); err != nil {
		t.Fatalf("ReconnectContainer: %v", err)
	}
}
```

(This test file already imports `context`, `testing`, `time` per the existing `TestShadowNetworkAndContainerLifecycle` — no new imports needed.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && go test ./... -run TestIsolateAndReconnectContainer -v`
Expected: FAIL (`IsolateContainer`/`ReconnectContainer` undefined)

- [ ] **Step 3: Refactor RunSensor and add the three new methods**

```go
// backend/dockermanager.go — replace the existing RunSensor function with this,
// which extracts the shared exec+stream logic into execAndStream and adds RunPoller,
// IsolateContainer, ReconnectContainer. Everything else in the file (imports,
// DockerManager, NewDockerManager, CreateShadowNetwork, StartShadowContainer,
// CopyFileIntoContainer, Teardown) stays exactly as-is.

func (m *DockerManager) execAndStream(ctx context.Context, containerID string, cmd []string) (<-chan string, error) {
	execID, err := m.cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
	})
	if err != nil {
		return nil, err
	}
	attach, err := m.cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{Tty: true})
	if err != nil {
		return nil, err
	}

	lines := make(chan string)
	go func() {
		defer close(lines)
		defer attach.Close()
		scanner := bufio.NewScanner(attach.Reader)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines <- line
			}
		}
	}()
	return lines, nil
}

func (m *DockerManager) RunSensor(ctx context.Context, containerID, samplePathInContainer string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"python3", "/sensor/sensor.py", samplePathInContainer})
}

func (m *DockerManager) RunPoller(ctx context.Context, containerID string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"python3", "/poller/poller.py"})
}

func (m *DockerManager) IsolateContainer(ctx context.Context, networkName, containerName string) error {
	return m.cli.NetworkDisconnect(ctx, networkName, containerName, false)
}

func (m *DockerManager) ReconnectContainer(ctx context.Context, networkName, containerName string) error {
	return m.cli.NetworkConnect(ctx, networkName, containerName, nil)
}
```

Note for the implementer: if `NetworkDisconnect`/`NetworkConnect`'s exact signature differs on the installed Docker SDK version, run `go doc github.com/docker/docker/client Client` from `backend/` to check — keep the four method signatures above (`RunPoller`, `IsolateContainer`, `ReconnectContainer`, and the now-refactored `RunSensor`) unchanged since Task 6 depends on them exactly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go build ./... && go test ./... -v`
Expected: PASS (all existing tests plus the new one; requires Docker daemon running)

- [ ] **Step 5: Commit**

```bash
git add backend/dockermanager.go backend/dockermanager_test.go
git commit -m "feat: add RunPoller/IsolateContainer/ReconnectContainer to DockerManager"
```

---

### Task 5: Verdict-engine audit action endpoint

**Files:**
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes: existing `audit_log` instance and `_strip_entry_hash` helper already in `app.py`.
- Produces: `POST /audit/action` (body `{"action": str, "device_id": str}` → the stored record, hash-chained into the same audit log). Consumed by the Go backend's `monitor.go` in Task 6.

- [ ] **Step 1: Write the failing test**

```python
# verdict-engine/tests/test_app.py — add this test to the existing file
def test_log_action_appends_to_audit_log():
    resp = client.post("/audit/action", json={"action": "isolated", "device_id": "monitored-endpoint"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "isolated"
    assert body["device_id"] == "monitored-endpoint"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "isolated" and r.get("device_id") == "monitored-endpoint"
        for r in listed
    )
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd verdict-engine && pytest tests/test_app.py -v`
Expected: FAIL (404, `/audit/action` doesn't exist)

- [ ] **Step 3: Implement the endpoint**

```python
# verdict-engine/app.py — add this class and route; everything else in the file
# (imports, audit_log instance, ScoreRequest, _strip_entry_hash, /score, /verdicts,
# /verdicts/{id}) stays exactly as-is. Insert after the ScoreRequest class.

class ActionRequest(BaseModel):
    action: str
    device_id: str


@app.post("/audit/action")
def log_action(req: ActionRequest):
    record = {
        "record_id": str(uuid.uuid4()),
        "device_id": req.device_id,
        "action": req.action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return _strip_entry_hash(audit_log.append(record))
```

Note: this record has no `verdict`/`sample_hash`/`confidence` fields by design — it's a distinct action record, not a verdict. `AuditLog.append`/`verify_chain` (Task 4 of the original build) operate on plain dicts with no schema coupling, so this works without touching `audit_log.py` or the `Verdict` Pydantic model's `Literal` type.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd verdict-engine && pytest tests/test_app.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "feat: add audit-log action endpoint for isolate/reconnect events"
```

---

### Task 6: Go Monitor decision logic (Tick + Reconnect)

**Files:**
- Create: `backend/monitor.go`
- Create: `backend/monitor_test.go`

**Interfaces:**
- Consumes: `Broadcaster` (from `backend/types.go`), `Verdict` (from `backend/types.go`), `scoreWithVerdictEngine` (from `backend/samples.go`), `fakeBroadcaster` (already defined in `backend/samples_test.go` — **do not redefine it**, this test file is compiled into the same `main` package and will get a duplicate-symbol error if you do).
- Produces: `monitorDocker` interface, `Monitor` struct with `NewMonitor(dm monitorDocker, verdictEngineURL string, hub Broadcaster) *Monitor`, `(*Monitor).Tick(ctx) error`, `(*Monitor).Reconnect(ctx) error`, `(*Monitor).IsIsolated() bool`, `errNotIsolated` sentinel error. Consumed by `backend/monitor_handlers.go` and `main.go` in Task 7.

- [ ] **Step 1: Write the failing tests**

```go
// backend/monitor_test.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeMonitorDocker struct {
	pollLines      []string
	pollErr        error
	isolateCalls   int
	reconnectCalls int
	isolateErr     error
	reconnectErr   error
}

func (f *fakeMonitorDocker) RunPoller(ctx context.Context, containerID string) (<-chan string, error) {
	if f.pollErr != nil {
		return nil, f.pollErr
	}
	ch := make(chan string, len(f.pollLines))
	for _, l := range f.pollLines {
		ch <- l
	}
	close(ch)
	return ch, nil
}

func (f *fakeMonitorDocker) IsolateContainer(ctx context.Context, networkName, containerName string) error {
	f.isolateCalls++
	return f.isolateErr
}

func (f *fakeMonitorDocker) ReconnectContainer(ctx context.Context, networkName, containerName string) error {
	f.reconnectCalls++
	return f.reconnectErr
}

func fakeVerdictEngine(t *testing.T, verdictLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: verdictLabel, Confidence: 1.0})
	}))
}

func TestTickSkipsScoringWhenNoEvents(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: nil}
	engine := fakeVerdictEngine(t, "Normal")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if fd.isolateCalls != 0 {
		t.Fatalf("expected no isolate calls, got %d", fd.isolateCalls)
	}
}

func TestTickIsolatesOnCompromisedVerdict(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if fd.isolateCalls != 1 {
		t.Fatalf("expected 1 isolate call, got %d", fd.isolateCalls)
	}
	if !mon.IsIsolated() {
		t.Fatal("expected monitor to be marked isolated")
	}
}

func TestTickDoesNotReIsolateWhenAlreadyIsolated(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if fd.isolateCalls != 1 {
		t.Fatalf("expected isolate called exactly once across two Compromised ticks, got %d", fd.isolateCalls)
	}
}

func TestReconnectFailsWhenNotIsolated(t *testing.T) {
	fd := &fakeMonitorDocker{}
	mon := NewMonitor(fd, "http://unused", &fakeBroadcaster{})
	if err := mon.Reconnect(context.Background()); err != errNotIsolated {
		t.Fatalf("expected errNotIsolated, got %v", err)
	}
}

func TestReconnectClearsIsolatedFlag(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := mon.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if mon.IsIsolated() {
		t.Fatal("expected monitor to no longer be isolated")
	}
	if fd.reconnectCalls != 1 {
		t.Fatalf("expected 1 reconnect call, got %d", fd.reconnectCalls)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && go test ./... -run "TestTick|TestReconnect" -v`
Expected: FAIL (`Monitor`, `NewMonitor`, `errNotIsolated` undefined)

- [ ] **Step 3: Implement Monitor**

```go
// backend/monitor.go
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

const (
	monitorContainerName = "mirraura-monitored-endpoint"
	monitorNetworkName   = "mirraura-monitor-net"
	monitorDeviceID      = "monitored-endpoint"
)

var errNotIsolated = errors.New("monitor is not currently isolated")

type monitorDocker interface {
	RunPoller(ctx context.Context, containerID string) (<-chan string, error)
	IsolateContainer(ctx context.Context, networkName, containerName string) error
	ReconnectContainer(ctx context.Context, networkName, containerName string) error
}

type Monitor struct {
	dm               monitorDocker
	verdictEngineURL string
	hub              Broadcaster

	mu       sync.Mutex
	isolated bool
}

func NewMonitor(dm monitorDocker, verdictEngineURL string, hub Broadcaster) *Monitor {
	return &Monitor{dm: dm, verdictEngineURL: verdictEngineURL, hub: hub}
}

func (mon *Monitor) IsIsolated() bool {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	return mon.isolated
}

func (mon *Monitor) Tick(ctx context.Context) error {
	lines, err := mon.dm.RunPoller(ctx, monitorContainerName)
	if err != nil {
		return fmt.Errorf("poll failed: %w", err)
	}

	events := []json.RawMessage{}
	for line := range lines {
		if !json.Valid([]byte(line)) {
			log.Printf("monitor: non-JSON line ignored: %s", line)
			continue
		}
		events = append(events, json.RawMessage(line))
	}

	if len(events) == 0 {
		return nil
	}

	for _, e := range events {
		mon.hub.Broadcast(map[string]any{"type": "event", "data": e})
	}

	batch, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events failed: %w", err)
	}
	sum := sha256.Sum256(batch)
	batchHash := hex.EncodeToString(sum[:])

	verdict, err := scoreWithVerdictEngine(mon.verdictEngineURL, batchHash, events)
	if err != nil {
		return fmt.Errorf("scoring failed: %w", err)
	}
	mon.hub.Broadcast(map[string]any{"type": "verdict", "data": verdict})

	if verdict.Verdict != "Compromised" {
		return nil
	}

	mon.mu.Lock()
	alreadyIsolated := mon.isolated
	mon.mu.Unlock()
	if alreadyIsolated {
		return nil
	}

	if err := mon.dm.IsolateContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		return fmt.Errorf("isolate failed: %w", err)
	}
	mon.mu.Lock()
	mon.isolated = true
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "isolated"})
	if err := logAction(mon.verdictEngineURL, "isolated", monitorDeviceID); err != nil {
		log.Printf("monitor: failed to audit-log isolate action: %v", err)
	}
	return nil
}

func (mon *Monitor) Reconnect(ctx context.Context) error {
	mon.mu.Lock()
	if !mon.isolated {
		mon.mu.Unlock()
		return errNotIsolated
	}
	mon.mu.Unlock()

	if err := mon.dm.ReconnectContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		return err
	}
	mon.mu.Lock()
	mon.isolated = false
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "reconnected"})
	if err := logAction(mon.verdictEngineURL, "reconnected", monitorDeviceID); err != nil {
		log.Printf("monitor: failed to audit-log reconnect action: %v", err)
	}
	return nil
}

func logAction(baseURL, action, deviceID string) error {
	body, err := json.Marshal(map[string]string{"action": action, "device_id": deviceID})
	if err != nil {
		return err
	}
	resp, err := http.Post(baseURL+"/audit/action", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verdict-engine returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./... -run "TestTick|TestReconnect" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/monitor.go backend/monitor_test.go
git commit -m "feat: add Monitor tick/isolate/reconnect decision logic"
```

---

### Task 7: HTTP handlers + main.go wiring

**Files:**
- Create: `backend/monitor_handlers.go`
- Modify: `backend/main.go`

**Interfaces:**
- Consumes: `Monitor`, `NewMonitor`, `errNotIsolated` (Task 6); `DockerManager`, `NewDockerManager` (existing); `Hub`, `NewHub` (existing).
- Produces: registers `GET /api/monitor/status` and `POST /api/monitor/reconnect` routes, and a background ticker that calls `Tick` every 10s.

- [ ] **Step 1: Write the handlers**

```go
// backend/monitor_handlers.go
package main

import (
	"encoding/json"
	"net/http"
)

func monitorStatusHandler(mon *Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"isolated": mon.IsIsolated()})
	}
}

func monitorReconnectHandler(mon *Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := mon.Reconnect(r.Context()); err != nil {
			if err == errNotIsolated {
				http.Error(w, "not currently isolated", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"isolated": false})
	}
}
```

- [ ] **Step 2: Wire main.go**

```go
// backend/main.go — full replacement
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	verdictEngineURL := os.Getenv("VERDICT_ENGINE_URL")
	if verdictEngineURL == "" {
		verdictEngineURL = "http://localhost:8000"
	}
	dm, err := NewDockerManager()
	if err != nil {
		log.Fatal(err)
	}
	hub := NewHub()
	mon := NewMonitor(dm, verdictEngineURL, hub)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/samples", samplesHandler(dm, verdictEngineURL, hub))
	mux.HandleFunc("/api/verdicts", verdictsListHandler(verdictEngineURL))
	mux.HandleFunc("/api/verdicts/", verdictDetailHandler(verdictEngineURL))
	mux.HandleFunc("/api/live", hub.HandleWS)
	mux.HandleFunc("/api/monitor/status", monitorStatusHandler(mon))
	mux.HandleFunc("/api/monitor/reconnect", monitorReconnectHandler(mon))

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := mon.Tick(ctx); err != nil {
				log.Printf("monitor tick failed: %v", err)
			}
			cancel()
		}
	}()

	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 3: Run the full suite and build to verify everything compiles and passes**

Run: `cd backend && go build ./... && go vet ./... && go test ./... -v`
Expected: PASS (all tests including the new monitor tests; the ticker goroutine doesn't run during `go test` since `main()` isn't invoked by tests)

- [ ] **Step 4: Commit**

```bash
git add backend/monitor_handlers.go backend/main.go
git commit -m "feat: wire monitor status/reconnect routes and ticker into main.go"
```

---

### Task 8: Frontend — MonitorBanner, API client, audit table

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/AuditLogTable.tsx`
- Create: `frontend/src/components/MonitorBanner.tsx`

**Interfaces:**
- Consumes: `MirraEvent`, `Verdict` (from `types.ts`), existing `BASE`/`connectLive` pattern in `api.ts`.
- Produces: `reconnectMonitor(): Promise<void>`, `fetchMonitorStatus(): Promise<{isolated: boolean}>` in `api.ts`; `MonitorBanner` component.

No new automated tests for this task (presentational + one API client extension matching the existing untested-by-design pattern for `uploadSample`'s sibling functions) — verified via build + manual check in Task 9.

- [ ] **Step 1: Extend api.ts**

```typescript
// frontend/src/api.ts — full replacement
import type { MirraEvent, Verdict } from "./types";

const BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8080";

export async function uploadSample(file: File): Promise<Verdict> {
  const form = new FormData();
  form.append("sample", file);
  const res = await fetch(`${BASE}/api/samples`, { method: "POST", body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchVerdicts(): Promise<Verdict[]> {
  const res = await fetch(`${BASE}/api/verdicts`);
  return res.json();
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  const res = await fetch(`${BASE}/api/monitor/status`);
  return res.json();
}

export async function reconnectMonitor(): Promise<void> {
  const res = await fetch(`${BASE}/api/monitor/reconnect`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}

export type LiveMessage =
  | { type: "event"; data: MirraEvent }
  | { type: "verdict"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };

export function connectLive(onMessage: (msg: LiveMessage) => void): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws") + "/api/live";
  const ws = new WebSocket(wsUrl);
  ws.onmessage = (ev) => onMessage(JSON.parse(ev.data));
  return ws;
}
```

- [ ] **Step 2: Build MonitorBanner**

```tsx
// frontend/src/components/MonitorBanner.tsx
import { useState } from "react";
import { reconnectMonitor } from "../api";

export function MonitorBanner({
  isolated,
  onReconnected,
}: {
  isolated: boolean;
  onReconnected: () => void;
}) {
  const [busy, setBusy] = useState(false);

  if (!isolated) return null;

  async function handleReconnect() {
    setBusy(true);
    try {
      await reconnectMonitor();
      onReconnected();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ background: "#5c1a1a", color: "white", padding: "0.75rem 1rem" }}>
      Monitored endpoint isolated — network disconnected after a Compromised verdict.
      <button onClick={handleReconnect} disabled={busy} style={{ marginLeft: "1rem" }}>
        {busy ? "Reconnecting..." : "Reconnect"}
      </button>
    </div>
  );
}
```

- [ ] **Step 3: Wire App.tsx**

```tsx
// frontend/src/App.tsx — full replacement
import { useEffect, useState } from "react";
import { connectLive, fetchMonitorStatus } from "./api";
import { AuditLogTable } from "./components/AuditLogTable";
import { EventFeed } from "./components/EventFeed";
import { MonitorBanner } from "./components/MonitorBanner";
import { UploadPanel } from "./components/UploadPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import type { MirraEvent, Verdict } from "./types";

function App() {
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
    const ws = connectLive((msg) => {
      if (msg.type === "event") setEvents((prev) => [...prev, msg.data]);
      if (msg.type === "verdict") setVerdict(msg.data);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
    return () => ws.close();
  }, []);

  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
  }

  function handleNewRun() {
    setEvents([]);
  }

  return (
    <div>
      <h1>Mirraura</h1>
      <MonitorBanner isolated={isolated} onReconnected={() => setIsolated(false)} />
      <div onClickCapture={handleNewRun}>
        <UploadPanel onVerdict={handleUpload} />
      </div>
      <EventFeed events={events} />
      <VerdictPanel verdict={verdict} />
      <AuditLogTable refreshKey={refreshKey} />
    </div>
  );
}

export default App;
```

- [ ] **Step 4: Make AuditLogTable render action rows**

```tsx
// frontend/src/components/AuditLogTable.tsx — full replacement
import { useEffect, useState } from "react";
import { fetchVerdicts } from "../api";
import type { Verdict } from "../types";

type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
};

export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<AuditRow[]>([]);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => setVerdicts(v as AuditRow[]))
      .catch(() => setVerdicts([]));
  }, [refreshKey]);

  return (
    <div>
      <h2>Audit Log</h2>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Sample Hash / Device</th>
            <th>Verdict / Action</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {verdicts.map((v) => {
            const key = v.verdict_id ?? v.record_id ?? `${v.action}-${v.device_id}`;
            return (
              <tr key={key}>
                <td>{v.timestamp}</td>
                <td>{v.action ? `device: ${v.device_id}` : `${v.sample_hash.slice(0, 12)}...`}</td>
                <td>{v.action ?? v.verdict}</td>
                <td>{v.action ? "—" : v.confidence.toFixed(2)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 5: Build to verify everything compiles**

Run: `cd frontend && npx tsc -b && npx vite build && npx vitest run`
Expected: no type errors, build succeeds, existing `api.test.ts` suite still passes.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api.ts frontend/src/App.tsx frontend/src/components/AuditLogTable.tsx frontend/src/components/MonitorBanner.tsx
git commit -m "feat: add monitor banner, reconnect action, and audit table action rows"
```

---

### Task 9: Full end-to-end wiring + manual verification

**Files:** None new — this task proves Tasks 1-8 work together against the live stack.

- [ ] **Step 1: Bring up the full stack**

```bash
docker compose up --build -d
```
Expected: all five services (`backend`, `verdict-engine`, `frontend`, `monitored-endpoint`) reach `Up`.

- [ ] **Step 2: Trigger a suspicious event inside the monitored container**

```bash
docker exec mirraura-monitored-endpoint touch /etc/mirraura-monitor-marker
```
Wait up to 10-15 seconds for the next poll tick.

- [ ] **Step 3: Confirm detection and containment**

```bash
curl -s http://localhost:8080/api/verdicts | tail -c 500
```
Expected: a new verdict entry appears (likely `Suspicious` or `Compromised` depending on which rule fired — `touch /etc/...` alone only trips the sensitive-path-write rule at 0.25, which bands to `Suspicious`, not `Compromised`; if the goal is specifically to test the isolate path, chain a second command inside the container too, e.g. also `docker exec mirraura-monitored-endpoint sh -c "cat /etc/hostname > /dev/null"` in the same 10s window to add the child-process-spawn rule and cross the 0.6 `Compromised` threshold).

```bash
curl -s http://localhost:8080/api/monitor/status
```
Expected: `{"isolated":true}` once a `Compromised` verdict has landed.

```bash
docker network inspect mirraura-monitor-net | grep -A3 mirraura-monitored-endpoint
```
Expected: the container is no longer listed as connected (or the command finds nothing for it), confirming real disconnection.

- [ ] **Step 4: Confirm recovery**

```bash
curl -s -X POST http://localhost:8080/api/monitor/reconnect
curl -s http://localhost:8080/api/monitor/status
```
Expected: second call returns `{"isolated":false}`.

```bash
docker network inspect mirraura-monitor-net | grep -A3 mirraura-monitored-endpoint
```
Expected: the container is connected again.

- [ ] **Step 5: Confirm the audit log recorded both actions**

```bash
curl -s http://localhost:8080/api/verdicts | grep -o '"action":"[a-z]*"'
```
Expected: both `"action":"isolated"` and `"action":"reconnected"` appear.

- [ ] **Step 6: Confirm the dashboard reflects it**

Open `http://localhost:5173`, confirm the isolated banner appeared and disappeared (or, if the timing window was missed, refresh the page — `fetchMonitorStatus` on mount will show the current true state either way) and the audit log table shows the action rows.

- [ ] **Step 7: Tear down cleanly**

```bash
docker compose down
docker ps -a --filter "name=mirraura"
docker network ls --filter "name=mirraura"
```
Expected: no leftover Mirraura containers or networks (the named volume persisting is expected, same as the original build).

- [ ] **Step 8: Commit** (only if Step 6 required any fixes; otherwise this task has nothing new to commit)

---

## Self-Review Notes

- **Spec coverage:** §2 (persistent container) → Tasks 2-3. §2 (poll-and-diff) → Task 1-2. §2 (reuse existing scorer) → Task 6 (calls `scoreWithVerdictEngine` unchanged). §2 (real containment) → Task 4, 6. §2 (human-triggered recovery, no auto-reconnect) → Task 6 (`Reconnect` only called from the handler, never from `Tick`), Task 7 (route), Task 8 (button). §2 (audit log record for isolate/reconnect) → Task 5, 6. §2 (same dashboard feed) → Task 8. §9 Global Constraints (names, poll interval, device_id, sample_hash-as-batch-hash, no auto-reconnect, skip-scoring-on-empty) → reflected in Task 1 (device_id via poller.py), Task 6 (batch hash, skip-when-empty, isolated-flag guard), Task 7 (10s ticker).
- **Placeholder scan:** none found — every step has runnable code or an exact command.
- **Type consistency checked:** `monitorDocker` interface (Task 6) matches the exact method signatures added to `*DockerManager` in Task 4 (`RunPoller`, `IsolateContainer`, `ReconnectContainer`) — Go's structural typing means `*DockerManager` satisfies the interface automatically as long as these three signatures match, which they do. `Monitor`/`NewMonitor`/`errNotIsolated` from Task 6 are used unchanged in Task 7's handlers and `main.go`. `fakeBroadcaster` is reused from `samples_test.go` (Task 9 of the original build), not redefined, avoiding a duplicate-symbol compile error. `AuditRow` in Task 8 correctly models both the existing `Verdict` shape and the new action-record shape from Task 5.
