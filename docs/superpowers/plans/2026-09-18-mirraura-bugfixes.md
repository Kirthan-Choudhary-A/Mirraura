# Mirraura Bug Fixes (Part 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the nine real bugs (5 backend, 4 frontend — bug 4 on the
frontend list is explicitly deferred, see below) called out in the spec,
each landing as its own tested, working commit, before login (Part 2) or
the redesign (Part 3) begin.

**Architecture:** No new services or dependencies. Each task touches the
existing Go backend, Python verdict engine, or React frontend in place.

**Tech Stack:** Go (stdlib `net/http`, `docker/docker` SDK, `gorilla/websocket`),
Python (FastAPI/pydantic), React + TypeScript + Vitest.

**Spec:** `docs/superpowers/specs/2026-09-18-mirraura-auth-redesign-design.md`
(Part 1 — Bug fixes)

## Global Constraints

- No "prototype"/"Day N" framing in code, comments, docs, or commit messages.
- Minimum code that works; reuse existing patterns (e.g. the
  `known_bad_label` short-circuit style in `verdict-engine/app.py`) instead
  of inventing new ones.
- No new dependencies. The frontend has no component-rendering test setup
  (no `@testing-library/react`, no `jsdom` in `vite.config.ts`) — do not add
  one for this plan; where a fix needs a test, either write it as a plain
  Vitest logic test against an exported pure function, or note it as
  manually verified via `docker compose up` (the same way the two existing
  Docker-dependent tests in `dockermanager_test.go` already require a live
  daemon).
- Every new language/library/tool gets an entry in `docs/concepts.md` in
  the same change that introduces it — not applicable to this plan since it
  adds none, but Task 1 and Task 5 each update `docs/concepts.md` to keep
  existing entries honest.
- **Part 1 item "frontend bug 4" (`VITE_BACKEND_URL` baked in at build
  time) is explicitly NOT fixed by this plan.** The spec's own fix is
  "serve frontend and API from the same origin" — that's the nginx reverse
  proxy built in Part 2. Attempting it here would mean either leaving two
  half-finished serving models in place or building nginx early out of
  order. No task below touches it.
- **Removing the wildcard CORS header (Task 3) temporarily breaks running
  `frontend` and `backend` as separate origins in local dev** (today's
  `docker compose up` setup: frontend on `:5173` fetching `:8080` via
  `VITE_BACKEND_URL`) until Part 2's nginx same-origin proxy lands. This is
  what the spec explicitly asks for in this order (bugs, then serving), so
  it's accepted as a known, temporary gap between this plan's completion
  and Part 2's first commit — not a regression to work around here.

---

### Task 1: Sandbox-harden the detonation container

**Files:**
- Modify: `backend/dockermanager.go` (`StartShadowContainer`)
- Test: `backend/dockermanager_test.go`
- Modify: `docs/concepts.md` (Docker-socket risk note)

**Interfaces:**
- Consumes: nothing new.
- Produces: `StartShadowContainer` keeps its existing signature
  `(ctx context.Context, image, networkID, name string) (string, error)` —
  callers (`backend/samples.go`) are unaffected.

- [ ] **Step 1: Write the failing test**

Add to `backend/dockermanager_test.go`:

```go
func TestShadowContainerIsHardened(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-hardening-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-hardening-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	inspect, err := dm.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		t.Fatalf("ContainerInspect: %v", err)
	}
	hc := inspect.HostConfig
	if hc.Memory != 256*1024*1024 {
		t.Errorf("expected 256MB memory limit, got %d", hc.Memory)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 128 {
		t.Errorf("expected PidsLimit 128, got %v", hc.PidsLimit)
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("expected CapDrop [ALL], got %v", hc.CapDrop)
	}
	if len(hc.CapAdd) != 1 || hc.CapAdd[0] != "SYS_PTRACE" {
		t.Errorf("expected CapAdd [SYS_PTRACE] (strace needs it), got %v", hc.CapAdd)
	}
	found := false
	for _, opt := range hc.SecurityOpt {
		if opt == "no-new-privileges" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no-new-privileges in SecurityOpt, got %v", hc.SecurityOpt)
	}
	if !hc.ReadonlyRootfs {
		t.Error("expected ReadonlyRootfs true")
	}
	if _, ok := hc.Tmpfs["/tmp"]; !ok {
		t.Errorf("expected a /tmp tmpfs mount, got %v", hc.Tmpfs)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./... -run TestShadowContainerIsHardened -v`
Expected: FAIL (current `StartShadowContainer` passes `nil` as the
`HostConfig`, so `hc.Memory` etc. are all zero values) — requires a Docker
daemon; if none is available in this environment, read the diff of
`StartShadowContainer` in Step 3 against this test by hand instead of
running it, and rely on `setup.sh`/`docker compose up` for real
verification later (same caveat as the two pre-existing tests in this
file).

- [ ] **Step 3: Implement the hardening**

In `backend/dockermanager.go`, change `StartShadowContainer`:

```go
func (m *DockerManager) StartShadowContainer(ctx context.Context, image, networkID, name string) (string, error) {
	one := int64(128)
	resp, err := m.cli.ContainerCreate(
		ctx,
		&container.Config{Image: image, Cmd: []string{"sleep", "infinity"}},
		&container.HostConfig{
			Resources: container.Resources{
				Memory:     256 * 1024 * 1024,
				PidsLimit:  &one,
			},
			CapDrop:        []string{"ALL"},
			CapAdd:         []string{"SYS_PTRACE"}, // strace needs this to trace the sample
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": ""},
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				networkID: {},
			},
		},
		nil,
		name,
	)
	if err != nil {
		return "", err
	}
	if err := m.cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}
```

Note: `/samples` (where `CopyFileIntoContainer` writes the uploaded file)
and `/sensor` (where the sensor binary lives, per the shadow image
Dockerfile) are baked into the image layer, not written at runtime, so
`ReadonlyRootfs` doesn't break either — only `/tmp` needs to be writable,
which the `Tmpfs` entry above provides.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./... -run TestShadowContainerIsHardened -v`
Expected: PASS (Docker daemon required — see Step 2's note).

- [ ] **Step 5: Document the Docker-socket mount risk**

In `docs/concepts.md`, add a new bullet under "Core security concepts"
(after the "Immutable / hash-chained audit log" paragraph, before
"Rule-based scorer"):

```markdown
**Docker-socket mount — a known, accepted risk** — The backend container
is granted the host's Docker socket (`/var/run/docker.sock`) so it can
create/start/exec/teardown the shadow container for each detonation. This
is powerful by necessity, but it also means anyone who compromises the
backend process effectively controls the host's Docker daemon — code
running in a compromised backend could create new containers, mount host
paths into them, or otherwise reach the host. This is a well-known Docker
anti-pattern for exactly that reason, and Mirraura accepts it as the
simplest way to orchestrate detonation containers from a single Go binary.
The mitigation that actually reduces the blast radius is hardening the
*detonation* container itself (dropped capabilities, read-only rootfs,
memory/PID limits — see the sandbox-hardening note below), not trying to
avoid the socket mount, and running the stack only on infrastructure you
already trust.
```

Also append one sentence to the end of the existing `docker/docker (Go)`
entry (around line 99): `" The detonation container it creates is hardened
(dropped capabilities except SYS_PTRACE for strace, read-only rootfs,
memory/PID limits, no-new-privileges) since it's the one place Mirraura
intentionally runs untrusted code."`

- [ ] **Step 6: Commit**

```bash
git add backend/dockermanager.go backend/dockermanager_test.go docs/concepts.md
git commit -m "fix: sandbox-harden the detonation container"
```

---

### Task 2: Hard sensor execution timeout surfaces as Inconclusive, not a hang

**Files:**
- Modify: `backend/dockermanager.go` (`execAndStream`)
- Modify: `backend/samples.go` (`samplesHandler`, `scoreWithVerdictEngine`)
- Modify: `backend/monitor.go` (its `scoreWithVerdictEngine` call site)
- Modify: `backend/samples_test.go`
- Test: `backend/dockermanager_test.go`
- Modify: `verdict-engine/app.py` (`ScoreRequest`, `score`)
- Test: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes: `scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename,
  source string, events []json.RawMessage) (*Verdict, error)` (current
  signature, from the detonation-report change already on `main`).
- Produces: `scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename,
  source string, timedOut bool, events []json.RawMessage) (*Verdict,
  error)` — the new signature every call site must use from this task on.

- [ ] **Step 1: Write the failing Go test for the request payload**

Add to `backend/samples_test.go`:

```go
func TestScoreWithVerdictEngineSendsTimedOutFlag(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Inconclusive"})
	}))
	defer fakeEngine.Close()

	_, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["timed_out"] != true {
		t.Fatalf("expected timed_out=true in request body, got %v", gotBody["timed_out"])
	}
}
```

Update the existing `TestScoreWithVerdictEngine` call site in the same
file to match the new signature (fourth positional arg becomes `"sample"`,
fifth is the new `timedOut bool`):

```go
	v, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", false, nil)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./... -run TestScoreWithVerdictEngine -v`
Expected: FAIL to compile — `scoreWithVerdictEngine` doesn't accept a 6th
positional bool argument yet.

- [ ] **Step 3: Implement the signature change and timeout detection**

In `backend/samples.go`, change `scoreWithVerdictEngine`:

```go
func scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source string, timedOut bool, events []json.RawMessage) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{
		"sample_hash":     sampleHash,
		"sample_filename": sampleFilename,
		"timed_out":       timedOut,
		"events":          events,
		"source":          source,
	})
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(baseURL+"/score", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verdict-engine returned %d: %s", resp.StatusCode, string(b))
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
```

Add a `sensorTimeout` constant and wrap the sensor call in `samplesHandler`
with its own bounded context, then detect whether it was the cause of the
channel closing. Add `"errors"` to the import block. In `samplesHandler`,
replace:

```go
		lines, err := dm.RunSensor(ctx, containerID, "/samples/"+safeFilename)
		if err != nil {
			http.Error(w, fmt.Sprintf("sensor run failed: %v", err), http.StatusInternalServerError)
			return
		}

		events := []json.RawMessage{}
		for line := range lines {
			if !json.Valid([]byte(line)) {
				log.Printf("sensor: non-JSON line ignored: %s", line)
				continue
			}
			raw := json.RawMessage(line)
			hub.Broadcast(map[string]any{"type": "event", "data": raw})
			events = append(events, raw)
		}

		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, safeFilename, "sample", events)
```

with:

```go
		sensorCtx, sensorCancel := context.WithTimeout(ctx, sensorTimeout)
		defer sensorCancel()

		lines, err := dm.RunSensor(sensorCtx, containerID, "/samples/"+safeFilename)
		if err != nil {
			http.Error(w, fmt.Sprintf("sensor run failed: %v", err), http.StatusInternalServerError)
			return
		}

		events := []json.RawMessage{}
		for line := range lines {
			if !json.Valid([]byte(line)) {
				log.Printf("sensor: non-JSON line ignored: %s", line)
				continue
			}
			raw := json.RawMessage(line)
			hub.Broadcast(map[string]any{"type": "event", "source": "sample", "data": raw})
			events = append(events, raw)
		}
		timedOut := errors.Is(sensorCtx.Err(), context.DeadlineExceeded)

		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, safeFilename, "sample", timedOut, events)
```

Add the constant near `shadowImage`:

```go
const shadowImage = "mirraura-shadow:latest"

// sensorTimeout bounds a single detonation run; if the sensor hasn't
// finished by then, execAndStream force-closes its exec stream (see
// dockermanager.go) and the run is scored as Inconclusive instead of
// hanging the HTTP request.
const sensorTimeout = 30 * time.Second
```

Also update the second broadcast call a few lines down to carry `source`:

```go
		hub.Broadcast(map[string]any{"type": "verdict", "source": "sample", "data": verdict})
```

In `backend/dockermanager.go`, make `execAndStream` actually stop when its
context is done — today the attach connection's lifetime isn't tied to
`ctx` once established, so a hung command would stream past any deadline:

```go
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

	// ctx's deadline isn't otherwise enforced once the attach connection is
	// established, so a hung or slow-running command would keep streaming
	// past it. Closing the connection here forces the scan loop above to
	// exit and the channel to close.
	go func() {
		<-ctx.Done()
		attach.Close()
	}()

	return lines, nil
}
```

In `backend/monitor.go`, update the one `scoreWithVerdictEngine` call site
(continuous monitoring never times out a sensor run, so it always passes
`false`):

```go
	verdict, err := scoreWithVerdictEngine(mon.verdictEngineURL, batchHash, "", "monitor", false, events)
```

And its event broadcast, a few lines up, to carry `source`:

```go
	for _, e := range events {
		mon.hub.Broadcast(map[string]any{"type": "event", "source": "monitor", "data": e})
	}
```

and its verdict broadcast:

```go
	mon.hub.Broadcast(map[string]any{"type": "verdict", "source": "monitor", "data": verdict})
```

In `verdict-engine/app.py`, add `timed_out` to `ScoreRequest` and a
short-circuit branch in `score`, mirroring the existing `known_bad_label`
branch:

```python
class ScoreRequest(BaseModel):
    sample_hash: str
    sample_filename: str = ""
    timed_out: bool = False
    events: List[Event] = []
    # "sample" = uploaded file (sample_hash is a real file identity, eligible for
    # auto-propose); "monitor" = continuous-monitoring event batch (the hash is of
    # a JSON event array, would never match a future upload).
    source: str = "sample"
```

```python
@app.post("/score", response_model=Verdict)
def score(req: ScoreRequest):
    verdict_id = str(uuid.uuid4())
    known_bad_label = check_hash(req.sample_hash)
    if known_bad_label:
        verdict, confidence, chain = (
            "Compromised",
            1.0,
            [f"sample hash matches known-bad entry '{known_bad_label}'"],
        )
    elif req.timed_out:
        verdict, confidence, chain = (
            "Inconclusive",
            0.0,
            ["sample detonation aborted: sensor exceeded its execution timeout"],
        )
    else:
        confidence, chain = score_events(req.events)
        verdict = verdict_from_score(confidence, chain, had_telemetry=len(req.events) > 0)
        if verdict == "Compromised" and req.source == "sample":
            try:
                propose_hash(
                    req.sample_hash,
                    f"auto-proposed from verdict {verdict_id}",
                    source="auto",
                )
            except HashExistsError:
                pass
            except Exception:
                logger.warning(
                    "failed to auto-propose hash for verdict %s", verdict_id, exc_info=True
                )
```

(The rest of `score` — building `record`, appending to `audit_log` and
`event_archive`, returning the `Verdict` — is unchanged; a timed-out run
still gets a real audit-log entry, same as any other verdict.)

- [ ] **Step 4: Run the Go test to verify it passes**

Run: `cd backend && go test ./... -run TestScoreWithVerdictEngine -v`
Expected: PASS.

- [ ] **Step 5: Write and run the failing pytest test**

Add to `verdict-engine/tests/test_app.py`:

```python
def test_score_timed_out_is_inconclusive_with_reason():
    resp = client.post(
        "/score",
        json={"sample_hash": "8" * 64, "events": [], "timed_out": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "Inconclusive"
    assert body["confidence"] == 0.0
    assert "execution timeout" in body["causal_chain"][0]
```

Run: `cd verdict-engine && python -m pytest tests/test_app.py -k timed_out -v`
Expected: FAILs before Step 3's `app.py` change is in place (it isn't —
Step 3 already applied it above), so this should already PASS. If run
before Step 3 for strict TDD ordering, it fails with a `KeyError` or
`AssertionError` since `timed_out` isn't a recognized field yet.

- [ ] **Step 6: Add the Docker-dependent stream-cancellation test**

Add to `backend/dockermanager_test.go`:

```go
func TestExecAndStreamStopsWhenContextCanceled(t *testing.T) {
	dm, err := NewDockerManager()
	if err != nil {
		t.Fatalf("NewDockerManager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-timeout-test-net")
	if err != nil {
		t.Fatalf("CreateShadowNetwork: %v", err)
	}
	containerID, err := dm.StartShadowContainer(ctx, "alpine:3.19", networkID, "mirraura-timeout-test-container")
	if err != nil {
		t.Fatalf("StartShadowContainer: %v", err)
	}
	defer dm.Teardown(context.Background(), containerID, networkID)

	execCtx, execCancel := context.WithTimeout(ctx, 2*time.Second)
	defer execCancel()

	lines, err := dm.execAndStream(execCtx, containerID, []string{"sleep", "60"})
	if err != nil {
		t.Fatalf("execAndStream: %v", err)
	}

	start := time.Now()
	for range lines {
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("expected stream to stop shortly after the 2s context deadline, took %v", elapsed)
	}
}
```

Run: `cd backend && go test ./... -run TestExecAndStreamStopsWhenContextCanceled -v`
Expected: PASS (Docker daemon required — same caveat as Task 1).

- [ ] **Step 7: Run full backend and verdict-engine suites**

Run: `cd backend && go build ./... && go test ./...`
Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS (aside from the two pre-existing Docker-daemon-dependent
tests if no daemon is available in this environment — unrelated to this
task).

- [ ] **Step 8: Commit**

```bash
git add backend/dockermanager.go backend/samples.go backend/samples_test.go backend/monitor.go verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "fix: sensor execution timeout surfaces as Inconclusive instead of hanging"
```

---

### Task 3: Remove wildcard CORS

**Files:**
- Modify: `backend/main.go`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing new; `withCORS` is deleted entirely.

- [ ] **Step 1: Remove `withCORS` and its use**

In `backend/main.go`, change:

```go
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

to:

```go
	log.Printf("backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
```

- [ ] **Step 2: Run the backend build and tests**

Run: `cd backend && go build ./... && go test ./...`
Expected: PASS (no test referenced `withCORS`).

- [ ] **Step 3: Commit**

```bash
git add backend/main.go
git commit -m "fix: remove wildcard CORS (same-origin serving lands in Part 2)"
```

---

### Task 4: WebSocket same-origin check

**Files:**
- Modify: `backend/hub.go`
- Test: `backend/hub_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new; `upgrader.CheckOrigin` behavior changes only.

- [ ] **Step 1: Write the failing test**

Add to `backend/hub_test.go`:

```go
func TestHubRejectsCrossOriginUpgrade(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(newTestMux(hub))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	headers := http.Header{"Origin": []string{"http://evil.example"}}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("expected dial to fail for a cross-origin request")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		status := "no response"
		if resp != nil {
			status = resp.Status
		}
		t.Fatalf("expected 403 Forbidden, got %s", status)
	}
}

func TestHubAllowsSameOriginUpgrade(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(newTestMux(hub))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	headers := http.Header{"Origin": []string{server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("expected same-origin dial to succeed, got: %v", err)
	}
	conn.Close()
}
```

Add `"net/http"` to the test file's imports if not already present (it
already is, via `httptest`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./... -run TestHubRejects -v`
Expected: FAIL — current `CheckOrigin` always returns `true`.

- [ ] **Step 3: Implement the check**

In `backend/hub.go`, add `"net/url"` to the imports and change:

```go
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}
```

to:

```go
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Non-browser clients (curl, server-to-server health checks) send no
			// Origin header at all; browsers always send one, so this only
			// affects non-browser callers, which this check isn't meant to stop.
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	},
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./... -run TestHub -v`
Expected: PASS for both new tests and the existing
`TestHubBroadcastsToConnectedClient` (which dials with no `Origin` header
at all, so it's unaffected).

- [ ] **Step 5: Commit**

```bash
git add backend/hub.go backend/hub_test.go
git commit -m "fix: reject cross-origin WebSocket upgrades"
```

---

### Task 5: `trained_scorer.py` can now emit `Normal`

**Files:**
- Modify: `verdict-engine/trained_scorer.py`
- Modify: `verdict-engine/tests/test_trained_scorer.py`
- Modify: `docs/concepts.md`

**Interfaces:**
- Consumes: `rule_scorer.SENSITIVE_PREFIXES`, `rule_scorer.STANDARD_PORTS`,
  `rule_scorer.RAPID_FILE_CHANGE_THRESHOLD` (unchanged, still imported).
- Produces: `trained_scorer.verdict_from_score(confidence: float, chain:
  List[str], had_telemetry: bool) -> str` — a new function local to this
  module (previously a re-export of `rule_scorer.verdict_from_score`).

- [ ] **Step 1: Write the failing test**

In `verdict-engine/tests/test_trained_scorer.py`, replace:

```python
def test_verdict_from_score_is_rule_scorer_function():
    assert trained_scorer.verdict_from_score is rule_scorer.verdict_from_score
```

with:

```python
def test_verdict_from_score_no_telemetry_is_inconclusive():
    assert trained_scorer.verdict_from_score(0.9, [], had_telemetry=False) == "Inconclusive"


def test_verdict_from_score_near_zero_confidence_is_normal():
    # trained_scorer's sigmoid-based confidence can never hit exactly 0.0
    # (unlike rule_scorer's additive score), so this must use a threshold
    # rather than an exact-equality check.
    assert trained_scorer.verdict_from_score(0.004, [], had_telemetry=True) == "Normal"


def test_verdict_from_score_mid_confidence_is_suspicious():
    assert trained_scorer.verdict_from_score(0.3, ["some reason"], had_telemetry=True) == "Suspicious"


def test_verdict_from_score_high_confidence_is_compromised():
    assert trained_scorer.verdict_from_score(0.8, ["some reason"], had_telemetry=True) == "Compromised"


def test_real_weights_clean_run_scores_normal():
    # A genuinely clean detonation (no rule contributions at all) should
    # come back Normal end to end, using the actual shipped weights.
    confidence, chain = trained_scorer.score_events([])
    assert chain == []
    # had_telemetry only matters with real events; this asserts the
    # confidence itself is low enough to clear the Normal threshold once
    # paired with at least one observed (but benign) event elsewhere.
    assert confidence < 0.1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd verdict-engine && python -m pytest tests/test_trained_scorer.py -v`
Expected: FAIL — `trained_scorer.verdict_from_score` is still
`rule_scorer.verdict_from_score`, whose `confidence == 0.0` check never
matches `0.004`, so it returns `"Suspicious"` instead of `"Normal"`.

- [ ] **Step 3: Implement the fix**

In `verdict-engine/trained_scorer.py`, change:

```python
import rule_scorer
from rule_scorer import verdict_from_score  # re-exported unchanged
from schemas import Event
```

to:

```python
import rule_scorer
from schemas import Event
from typing import List
```

(`List` is already imported at the top via `from typing import List, Tuple`
— just drop the now-unused `verdict_from_score` re-export line, keep the
existing `from typing import List, Tuple` line as-is, and don't add a
duplicate import.)

Add, right after `score_events`:

```python
def verdict_from_score(confidence: float, chain: List[str], had_telemetry: bool) -> str:
    if not had_telemetry:
        return "Inconclusive"
    # Unlike rule_scorer's additive score, this sigmoid-based confidence can
    # only approach 0.0 asymptotically and never hits it exactly, so a
    # confidence == 0.0 check (rule_scorer's check) would never fire and a
    # genuinely clean run would always come back "Suspicious". A small
    # threshold band gives a real Normal outcome instead.
    if confidence < 0.1:
        return "Normal"
    if confidence < 0.6:
        return "Suspicious"
    return "Compromised"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd verdict-engine && python -m pytest tests/test_trained_scorer.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full verdict-engine suite**

Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS (this also exercises `revalidate.py`'s dynamic-loading
contract against `trained_scorer.py`, which still exposes both
`score_events` and `verdict_from_score` as required).

- [ ] **Step 6: Update the caveat in `docs/concepts.md`**

Replace the last sentence of the "Rule-based scorer (v1) vs. trained ML
classifier (later)" paragraph (around line 41):

```
One real caveat for any future promotion decision: `trained_scorer.py` re-exports `rule_scorer.py`'s `verdict_from_score` unchanged, but its sigmoid-based confidence only approaches 0.0 asymptotically and never hits it exactly, so as shipped it can never clear the `confidence == 0.0` check that function uses for `"Normal"` — a genuinely clean device would come back `"Suspicious"` instead.
```

with:

```
`trained_scorer.py` defines its own `verdict_from_score` (a `< 0.1` confidence threshold for `"Normal"`) rather than reusing `rule_scorer.py`'s exact `confidence == 0.0` check, because its sigmoid-based confidence only approaches 0.0 asymptotically and never hits it exactly — with the shared check, a genuinely clean run would always come back `"Suspicious"` instead of `"Normal"`. Fixed 2026-09-18.
```

- [ ] **Step 7: Commit**

```bash
git add verdict-engine/trained_scorer.py verdict-engine/tests/test_trained_scorer.py docs/concepts.md
git commit -m "fix: give trained_scorer its own Normal threshold (sigmoid never hits 0.0)"
```

---

### Task 6: Event feed no longer clears on unrelated clicks

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/UploadPanel.tsx`

**Interfaces:**
- Consumes: nothing new.
- Produces: `UploadPanel` gains a required `onUploadStart: () => void`
  prop, called synchronously at the top of `handleUpload` before the file
  is read.

- [ ] **Step 1: Update `UploadPanel`**

In `frontend/src/components/UploadPanel.tsx`, change:

```tsx
export function UploadPanel({ onVerdict }: { onVerdict: (v: Verdict) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpload() {
    const file = inputRef.current?.files?.[0];
    if (!file) return;
    setBusy(true);
```

to:

```tsx
export function UploadPanel({
  onVerdict,
  onUploadStart,
}: {
  onVerdict: (v: Verdict) => void;
  onUploadStart: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpload() {
    const file = inputRef.current?.files?.[0];
    if (!file) return;
    onUploadStart();
    setBusy(true);
```

- [ ] **Step 2: Update `App.tsx`**

In `frontend/src/App.tsx`, remove the `onClickCapture` wrapper and
`handleNewRun`, and pass the new prop. Change:

```tsx
  function handleNewRun() {
    setEvents([]);
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-header__title">Mirraura</h1>
        <p className="app-header__subtitle">
          Shadow honeypot — live behavioral verdict engine
        </p>
      </header>

      <section className="detonation-zone">
        <div className="detonation-zone__left" onClickCapture={handleNewRun}>
          <UploadPanel onVerdict={handleUpload} />
          <VerdictPanel verdict={verdict} />
        </div>
```

to:

```tsx
  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-header__title">Mirraura</h1>
        <p className="app-header__subtitle">
          Shadow honeypot — live behavioral verdict engine
        </p>
      </header>

      <section className="detonation-zone">
        <div className="detonation-zone__left">
          <UploadPanel onVerdict={handleUpload} onUploadStart={() => setEvents([])} />
          <VerdictPanel verdict={verdict} />
        </div>
```

- [ ] **Step 3: Type-check and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm run build`
Expected: PASS — no other file references `handleNewRun` or
`onClickCapture` on this element.

- [ ] **Step 4: Manually verify**

No component-rendering test harness exists in this repo (see Global
Constraints), so verify by running `docker compose up --build`, uploading
a sample, letting events stream in, then clicking the file `<input>` (or
anywhere else inside the left column) without picking a new file — the
event feed and verdict must stay exactly as they were.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/App.tsx frontend/src/components/UploadPanel.tsx
git commit -m "fix: only clear the event feed when a new upload actually starts"
```

---

### Task 7: Separate sample-run and monitor-loop WebSocket traffic

**Files:**
- Modify: `backend/samples.go`, `backend/monitor.go` (already carry `source` from Task 2 — this task is only needed if Task 2 hasn't run yet in this session; if it has, skip straight to the frontend half)
- Modify: `frontend/src/api.ts` (`LiveMessage` type, plus two new pure helpers)
- Test: `frontend/src/api.test.ts`
- Modify: `frontend/src/App.tsx`

**Interfaces:**
- Consumes: `LiveMessage` (current shape, no `source` field on `event`/`verdict`).
- Produces:
  - `LiveMessage` variants `event` and `verdict` each gain a required
    `source: "sample" | "monitor"` field.
  - `applyLiveEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[]`
    — pure function, appends only `source: "sample"` events and caps the
    result at the most recent 500.
  - `shouldUpdateSampleVerdict(msg: LiveMessage): msg is Extract<LiveMessage, { type: "verdict" }>`
    — pure function, true only for `type: "verdict", source: "sample"`.

- [ ] **Step 1: Confirm backend `source` tagging (from Task 2)**

If Task 2 has already been completed, `backend/samples.go` and
`backend/monitor.go` already tag every `event`/`verdict` broadcast with
`source: "sample"` or `source: "monitor"` respectively — nothing to do
here. If this task is being done standalone (Task 2 skipped), apply the
four broadcast-call edits described in Task 2 Step 3 first (the two
`hub.Broadcast` calls in `samplesHandler`, the two in `Monitor.Tick`).

- [ ] **Step 2: Write the failing frontend tests**

Add to `frontend/src/api.test.ts` (new imports alongside the existing
ones):

```ts
import { applyLiveEvent, shouldUpdateSampleVerdict } from "./api";
import type { MirraEvent, Verdict } from "./types";

function makeEvent(id: string): MirraEvent {
  return {
    event_id: id,
    device_id: "d1",
    event_type: "process_spawn",
    timestamp: "2026-09-18T00:00:00Z",
    baseline_deviation_score: 0,
  };
}

describe("applyLiveEvent", () => {
  it("appends a sample-source event", () => {
    const result = applyLiveEvent([], { type: "event", source: "sample", data: makeEvent("e1") });
    expect(result).toHaveLength(1);
  });

  it("ignores a monitor-source event", () => {
    const result = applyLiveEvent([], { type: "event", source: "monitor", data: makeEvent("e1") });
    expect(result).toHaveLength(0);
  });

  it("ignores non-event messages", () => {
    const result = applyLiveEvent([makeEvent("e1")], { type: "isolated" });
    expect(result).toHaveLength(1);
  });

  it("caps the result at 500 events", () => {
    const existing = Array.from({ length: 500 }, (_, i) => makeEvent(`e${i}`));
    const result = applyLiveEvent(existing, { type: "event", source: "sample", data: makeEvent("new") });
    expect(result).toHaveLength(500);
    expect(result[result.length - 1].event_id).toBe("new");
    expect(result[0].event_id).toBe("e1");
  });
});

describe("shouldUpdateSampleVerdict", () => {
  const verdict: Verdict = {
    verdict_id: "v1",
    sample_hash: "a".repeat(64),
    sample_filename: "f.sh",
    verdict: "Normal",
    confidence: 0,
    causal_chain: [],
    timestamp: "2026-09-18T00:00:00Z",
    prev_log_hash: "0".repeat(64),
  };

  it("is true for a sample-source verdict", () => {
    expect(shouldUpdateSampleVerdict({ type: "verdict", source: "sample", data: verdict })).toBe(true);
  });

  it("is false for a monitor-source verdict", () => {
    expect(shouldUpdateSampleVerdict({ type: "verdict", source: "monitor", data: verdict })).toBe(false);
  });

  it("is false for a non-verdict message", () => {
    expect(shouldUpdateSampleVerdict({ type: "reconnected" })).toBe(false);
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL to compile — `applyLiveEvent`/`shouldUpdateSampleVerdict`
don't exist yet, and `LiveMessage`'s `event`/`verdict` variants don't have
`source`.

- [ ] **Step 4: Implement in `frontend/src/api.ts`**

Change:

```ts
export type LiveMessage =
  | { type: "event"; data: MirraEvent }
  | { type: "verdict"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };
```

to:

```ts
export type LiveMessage =
  | { type: "event"; source: "sample" | "monitor"; data: MirraEvent }
  | { type: "verdict"; source: "sample" | "monitor"; data: Verdict }
  | { type: "isolated" }
  | { type: "reconnected" };

const MAX_EVENTS = 500;

// Only the shadow-run feed is rendered today (App.tsx); monitor-loop events
// are received but not yet shown anywhere (Part 3 adds that tab), so they're
// filtered out here rather than mixed into the same list.
export function applyLiveEvent(events: MirraEvent[], msg: LiveMessage): MirraEvent[] {
  if (msg.type !== "event" || msg.source !== "sample") return events;
  return [...events, msg.data].slice(-MAX_EVENTS);
}

export function shouldUpdateSampleVerdict(
  msg: LiveMessage
): msg is Extract<LiveMessage, { type: "verdict" }> {
  return msg.type === "verdict" && msg.source === "sample";
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS.

- [ ] **Step 6: Wire the helpers into `App.tsx`**

Change:

```tsx
    const ws = connectLive((msg) => {
      if (msg.type === "event") setEvents((prev) => [...prev, msg.data]);
      if (msg.type === "verdict") {
        setVerdict(msg.data);
        setRefreshKey((k) => k + 1);
      }
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
```

to:

```tsx
    const ws = connectLive((msg) => {
      setEvents((prev) => applyLiveEvent(prev, msg));
      if (shouldUpdateSampleVerdict(msg)) {
        setVerdict(msg.data);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
```

(A monitor-source verdict still bumps `refreshKey` so the audit log
refreshes — it just no longer overwrites the upload verdict panel or the
shadow-run event feed.) Update the import line at the top of `App.tsx`:

```tsx
import { applyLiveEvent, connectLive, fetchMonitorStatus, shouldUpdateSampleVerdict } from "./api";
```

- [ ] **Step 7: Type-check, build, and run the full frontend suite**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/samples.go backend/monitor.go frontend/src/api.ts frontend/src/api.test.ts frontend/src/App.tsx
git commit -m "fix: separate sample-run and monitor-loop WebSocket traffic; cap feed at 500"
```

---

### Task 8: WebSocket reconnect with backoff, guarded parsing, exposed connection state

**Files:**
- Modify: `frontend/src/api.ts` (`connectLive`)
- Test: `frontend/src/api.test.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/index.css` (one small class for the status text)

**Interfaces:**
- Consumes: `connectLive(onMessage: (msg: LiveMessage) => void): WebSocket`
  (current signature).
- Produces:
  - `type ConnectionState = "connecting" | "live" | "offline"`
  - `nextBackoffMs(current: number): number` — pure function, doubles up to
    a 30000ms cap.
  - `connectLive(onMessage: (msg: LiveMessage) => void, onStatus: (state:
    ConnectionState) => void): { close: () => void }` — new signature and
    return type; callers must call `.close()` instead of treating the
    result as a raw `WebSocket`.

- [ ] **Step 1: Write the failing test for the pure backoff function**

Add to `frontend/src/api.test.ts`:

```ts
import { nextBackoffMs } from "./api";

describe("nextBackoffMs", () => {
  it("doubles the current delay", () => {
    expect(nextBackoffMs(1000)).toBe(2000);
  });

  it("caps at 30 seconds", () => {
    expect(nextBackoffMs(20000)).toBe(30000);
    expect(nextBackoffMs(30000)).toBe(30000);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test`
Expected: FAIL — `nextBackoffMs` doesn't exist yet.

- [ ] **Step 3: Implement in `frontend/src/api.ts`**

Change:

```ts
export function connectLive(onMessage: (msg: LiveMessage) => void): WebSocket {
  const wsUrl = BASE.replace(/^http/, "ws") + "/api/live";
  const ws = new WebSocket(wsUrl);
  ws.onmessage = (ev) => onMessage(JSON.parse(ev.data));
  return ws;
}
```

to:

```ts
export type ConnectionState = "connecting" | "live" | "offline";

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

export function nextBackoffMs(current: number): number {
  return Math.min(current * 2, MAX_BACKOFF_MS);
}

export function connectLive(
  onMessage: (msg: LiveMessage) => void,
  onStatus: (state: ConnectionState) => void
): { close: () => void } {
  let ws: WebSocket | null = null;
  let closed = false;
  let backoff = INITIAL_BACKOFF_MS;

  function connect() {
    if (closed) return;
    onStatus("connecting");
    const wsUrl = BASE.replace(/^http/, "ws") + "/api/live";
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      backoff = INITIAL_BACKOFF_MS;
      onStatus("live");
    };
    ws.onmessage = (ev) => {
      try {
        onMessage(JSON.parse(ev.data));
      } catch {
        // malformed frame — drop it rather than crash the socket handler
      }
    };
    ws.onclose = () => {
      if (closed) return;
      onStatus("offline");
      const delay = backoff;
      backoff = nextBackoffMs(backoff);
      setTimeout(connect, delay);
    };
    ws.onerror = () => {
      ws?.close();
    };
  }

  connect();

  return {
    close() {
      closed = true;
      ws?.close();
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test`
Expected: PASS.

- [ ] **Step 5: Wire the new API into `App.tsx`**

Change:

```tsx
import { connectLive, fetchMonitorStatus } from "./api";
```

to (combining with Task 7's import if that task already landed):

```tsx
import { applyLiveEvent, connectLive, fetchMonitorStatus, shouldUpdateSampleVerdict } from "./api";
import type { ConnectionState } from "./api";
```

Add state and use it in the effect. Change:

```tsx
  const [isolated, setIsolated] = useState(false);

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
    const ws = connectLive((msg) => {
      setEvents((prev) => applyLiveEvent(prev, msg));
      if (shouldUpdateSampleVerdict(msg)) {
        setVerdict(msg.data);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
    return () => ws.close();
  }, []);
```

to:

```tsx
  const [isolated, setIsolated] = useState(false);
  const [connState, setConnState] = useState<ConnectionState>("connecting");

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
    const conn = connectLive((msg) => {
      setEvents((prev) => applyLiveEvent(prev, msg));
      if (shouldUpdateSampleVerdict(msg)) {
        setVerdict(msg.data);
      }
      if (msg.type === "verdict") setRefreshKey((k) => k + 1);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    }, setConnState);
    return () => conn.close();
  }, []);
```

Render the state somewhere visible in the header (Part 3 will style this
properly — this just needs to be a real, visible indicator, not silent
state):

```tsx
      <header className="app-header">
        <h1 className="app-header__title">Mirraura</h1>
        <p className="app-header__subtitle">
          Shadow honeypot — live behavioral verdict engine
        </p>
        <p className="app-header__conn-state" data-state={connState}>
          {connState === "live" ? "● Live" : connState === "connecting" ? "○ Connecting…" : "○ Offline — retrying"}
        </p>
      </header>
```

Add a minimal style in `frontend/src/index.css` (near the other
`.app-header__*` rules):

```css
.app-header__conn-state {
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--ink-muted);
}

.app-header__conn-state[data-state="live"] {
  color: var(--sev-normal);
}

.app-header__conn-state[data-state="offline"] {
  color: var(--sev-compromised);
}
```

- [ ] **Step 6: Type-check, build, and run the full frontend suite**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`
Expected: PASS.

- [ ] **Step 7: Manually verify reconnect**

With `docker compose up --build` running, confirm the header shows "●
Live"; stop the `backend` container (`docker compose stop backend`) and
confirm it flips to "Offline — retrying" within a couple seconds; restart
it (`docker compose start backend`) and confirm it returns to "● Live"
without a page reload.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts frontend/src/App.tsx frontend/src/index.css
git commit -m "fix: reconnect the live WebSocket with backoff and expose connection state"
```

---

### Task 9: Every fetch checks `res.ok`; unused template asset removed

**Files:**
- Modify: `frontend/src/api.ts` (`fetchVerdicts`, `fetchMonitorStatus`)
- Test: `frontend/src/api.test.ts`
- Modify: `frontend/src/components/AuditLogTable.tsx`
- Modify: `frontend/src/App.tsx`
- Delete: `frontend/public/icons.svg`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new; `fetchVerdicts`/`fetchMonitorStatus` now reject
  instead of silently resolving on a non-OK response.

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/api.test.ts`:

```ts
it("fetchVerdicts throws when the response is not ok", async () => {
  (fetch as any).mockResolvedValue({ ok: false, text: async () => "boom" });
  await expect(fetchVerdicts()).rejects.toThrow("boom");
});

it("fetchMonitorStatus throws when the response is not ok", async () => {
  (fetch as any).mockResolvedValue({ ok: false, text: async () => "boom" });
  await expect(fetchMonitorStatus()).rejects.toThrow("boom");
});
```

(Add `fetchMonitorStatus` to the existing top-of-file import list.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — both functions currently resolve regardless of `res.ok`.

- [ ] **Step 3: Implement in `frontend/src/api.ts`**

Change:

```ts
export async function fetchVerdicts(): Promise<Verdict[]> {
  const res = await fetch(`${BASE}/api/verdicts`);
  return res.json();
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  const res = await fetch(`${BASE}/api/monitor/status`);
  return res.json();
}
```

to:

```ts
export async function fetchVerdicts(): Promise<Verdict[]> {
  const res = await fetch(`${BASE}/api/verdicts`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  const res = await fetch(`${BASE}/api/monitor/status`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npm test`
Expected: PASS.

- [ ] **Step 5: Give `AuditLogTable` a real error state**

In `frontend/src/components/AuditLogTable.tsx`, change:

```tsx
export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<AuditRow[]>([]);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => setVerdicts(v as AuditRow[]))
      .catch(() => setVerdicts([]));
  }, [refreshKey]);

  return (
    <div className="panel">
      <h2>Audit Log</h2>
      <div className="table-scroll">
```

to:

```tsx
export function AuditLogTable({ refreshKey }: { refreshKey: number }) {
  const [verdicts, setVerdicts] = useState<AuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchVerdicts()
      .then((v) => {
        setVerdicts(v as AuditRow[]);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load audit log"));
  }, [refreshKey]);

  return (
    <div className="panel">
      <h2>Audit Log</h2>
      {error && <p className="error-text">{error}</p>}
      <div className="table-scroll">
```

- [ ] **Step 6: Give the monitor-status fetch in `App.tsx` a real error state**

Change:

```tsx
  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => setIsolated(s.isolated))
      .catch(() => {});
```

to:

```tsx
  const [monitorError, setMonitorError] = useState<string | null>(null);

  useEffect(() => {
    fetchMonitorStatus()
      .then((s) => {
        setIsolated(s.isolated);
        setMonitorError(null);
      })
      .catch((e) => setMonitorError(e instanceof Error ? e.message : "failed to load monitor status"));
```

Render it right after the header:

```tsx
      </header>

      {monitorError && <p className="error-text">{monitorError}</p>}

      <section className="detonation-zone">
```

- [ ] **Step 7: Delete the unused template asset**

`frontend/public/icons.svg` is never referenced by `index.html` or
anything under `frontend/src` (confirmed by grep before writing this
plan). `frontend/index.html`'s `<title>` is already `Mirraura` and
`frontend/src/index.css` has no leftover Vite-template selectors (`#social`,
`.counter`, a centered `#root`, or a 56px `h1`) — both were already
cleaned up in the earlier dashboard-redesign commit (`a360f22`), so no
action is needed for those two.

```bash
rm frontend/public/icons.svg
```

- [ ] **Step 8: Type-check, build, and run the full frontend suite**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts frontend/src/components/AuditLogTable.tsx frontend/src/App.tsx
git add -u frontend/public/icons.svg
git commit -m "fix: surface real errors from every fetch; drop unused template asset"
```

---

## Definition of done for this plan

- `cd backend && go build ./... && go vet ./... && go test ./...` passes
  (aside from the two pre-existing Docker-daemon-dependent tests if this
  environment has no Docker daemon — unrelated to this plan).
- `cd verdict-engine && python -m pytest tests/ -q` passes.
- `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build` passes.
- Manually verified via `docker compose up --build` (Task 6 and Task 8
  each call this out specifically): clicking around the upload panel
  doesn't clear the feed, the header shows live/connecting/offline
  correctly and recovers after a backend restart, and a monitor-loop tick
  no longer overwrites the upload verdict panel.
- Nine commits land in this plan's order, each building and passing tests
  on its own.
