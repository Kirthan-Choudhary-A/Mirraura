# Rust Sensor Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python in-container sensor (`sensor/sensor.py`, `tracer.py`, `parser.py`) with a Rust binary that is a full behavioral swap-in — same `strace`-based capture, same canonical event JSON out — so the verdict engine and dashboard need zero changes.

**Architecture:** A small Rust binary crate (`sensor/`) with three modules mirroring the Python files 1:1 (`tracer.rs`, `parser.rs`, `main.rs`), built via a multi-stage Docker build in `shadow-image/Dockerfile` (matching `backend/Dockerfile`'s existing Go pattern: `rust:1-alpine` builder → `alpine:3.19` runtime). `backend/dockermanager.go`'s `RunSensor` execs the compiled binary instead of `python3 sensor.py`.

**Tech Stack:** Rust (stable, 2021 edition), crates: `regex`, `serde_json`, `uuid`, `chrono`. No host Rust toolchain is available in this environment — all `cargo` commands in this plan run inside a `rust:1-alpine` Docker container against a bind-mounted `sensor/` directory.

**Spec:** `docs/superpowers/specs/2026-09-11-rust-sensor-design.md`

## Global Constraints

- Tracing mechanism stays `strace`, invoked exactly as today: `strace -f -e trace=execve,openat,connect -o <tmp> bash <sample_path>` — no ptrace crate, no eBPF.
- Event JSON shape is unchanged: `event_id`, `device_id: "shadow-node"`, `event_type`, exactly one of `process_ref`/`network_ref`/`file_ref`, `timestamp`, `baseline_deviation_score: 0.0`.
- `openat` only becomes a `file_write` event when its flags include `O_WRONLY`, `O_RDWR`, or `O_CREAT` — read-only opens are not events.
- ~0.3s sleep between printed event lines is preserved (dashboard live-feed pacing), and stdout is explicitly flushed after every line (matches Python's `print(..., flush=True)` — required because stdout is piped through `docker exec`, not a terminal, so it's block-buffered by default without an explicit flush).
- `backend/dockermanager.go`'s `RunSensor` execs `/sensor/sensor` (no `python3` prefix) with the sample path as its only argument — `execAndStream`'s stdout-streaming logic is untouched.
- `shadow-image/Dockerfile` is a multi-stage build: `rust:1-alpine` builder → `alpine:3.19` runtime with `strace`+`bash` only, no Python (alpine→alpine keeps both stages on musl libc).
- Full replacement: the Python `sensor/` files and their tests are deleted, not retained as a fallback.
- No change to `verdict-engine/schemas.py`, `rule_scorer.py`, or anything in `monitored-endpoint/`.

---

### Task 1: Crate skeleton + `tracer.rs`

**Files:**
- Create: `sensor/Cargo.toml`
- Create: `sensor/src/tracer.rs`
- Create: `sensor/src/main.rs` (minimal stub for this task — just enough for the crate to compile; Task 3 fills it in)

**Interfaces:**
- Consumes: nothing from other tasks (base layer).
- Produces (for Task 3): `tracer::run_strace(sample_path: &str) -> std::io::Result<String>`, `tracer::strip_root_execve(trace_text: &str) -> String` (both `pub`).

- [ ] **Step 1: Create the crate manifest**

Create `sensor/Cargo.toml`:

```toml
[package]
name = "sensor"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "sensor"
path = "src/main.rs"

[dependencies]
regex = "1"
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["clock"] }
```

- [ ] **Step 2: Create a minimal main.rs so the crate compiles**

Create `sensor/src/main.rs`:

```rust
mod tracer;

fn main() {
    println!("sensor stub — filled in by Task 3");
}
```

- [ ] **Step 3: Write the failing tests**

Create `sensor/src/tracer.rs`:

```rust
use std::fs;
use std::io;
use std::process::Command;

use regex::Regex;

pub fn strip_root_execve(trace_text: &str) -> String {
    let root_execve_re = Regex::new(r"^\d+\s+execve\(").unwrap();
    let mut removed = false;
    let mut result = String::with_capacity(trace_text.len());
    for line in trace_text.split_inclusive('\n') {
        if !removed && root_execve_re.is_match(line.trim()) {
            removed = true;
            continue;
        }
        result.push_str(line);
    }
    result
}

// ponytail: no timeout on the strace subprocess, matching the existing
// Python sensor (its timeout=15 argument was never actually caught —
// an uncaught subprocess.TimeoutExpired crashes it too, so dropping the
// timeout keeps identical observable behavior for a hung sample).
// Upgrade path: a watcher thread + Command::kill if a hung sample ever
// becomes a real problem in practice.
pub fn run_strace(sample_path: &str) -> io::Result<String> {
    let trace_path =
        std::env::temp_dir().join(format!("mirraura-sensor-{}.trace", std::process::id()));

    let spawn_result = Command::new("strace")
        .args(["-f", "-e", "trace=execve,openat,connect", "-o"])
        .arg(&trace_path)
        .args(["bash", sample_path])
        .output();

    let trace_text = fs::read_to_string(&trace_path).unwrap_or_default();
    let _ = fs::remove_file(&trace_path);

    spawn_result?;
    Ok(strip_root_execve(&trace_text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTI_LINE_TRACE: &str = r#"12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
"#;

    const ONLY_ROOT_TRACE: &str = r#"12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0
"#;

    const NO_EXECVE_TRACE: &str = r#"12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
"#;

    #[test]
    fn test_strips_only_the_leading_root_execve_line() {
        let result = strip_root_execve(MULTI_LINE_TRACE);
        let original_lines: Vec<&str> = MULTI_LINE_TRACE.split_inclusive('\n').collect();
        let expected: String = original_lines[1..].concat();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_only_root_execve_line_results_in_empty_string() {
        assert_eq!(strip_root_execve(ONLY_ROOT_TRACE), "");
    }

    #[test]
    fn test_empty_string_returns_empty_string() {
        assert_eq!(strip_root_execve(""), "");
    }

    #[test]
    fn test_no_execve_line_leaves_everything_untouched() {
        assert_eq!(strip_root_execve(NO_EXECVE_TRACE), NO_EXECVE_TRACE);
    }
}
```

(The tests are written in the same file as Step 3 on purpose — Rust's idiomatic unit-test style is an inline `#[cfg(test)] mod tests` block, not a separate file, and `cargo test` compiles and runs both the implementation and its tests together. There is no separate "write failing test, then implementation" file split here the way Python's plans did it; instead, run the tests once before believing they pass — Step 4 below runs them for the first time.)

- [ ] **Step 4: Run tests to verify they pass**

From the repo root (`C:\Users\akirt\Mirraura` or your worktree root):

```bash
docker run --rm \
  -v "$(pwd)/sensor:/sensor" \
  -v mirraura-cargo-registry:/usr/local/cargo/registry \
  -w /sensor \
  rust:1-alpine \
  sh -c "apk add --no-cache build-base >/dev/null 2>&1 && cargo test"
```

Expected: `running 4 tests ... test result: ok. 4 passed; 0 failed`. (First run downloads crates and installs `build-base` inside the container — slower; the named `mirraura-cargo-registry` volume caches crate downloads across runs, so subsequent `cargo test`/`cargo build` invocations in later tasks are faster.)

This also generates `sensor/Cargo.lock` on the host (via the bind mount) — a binary crate commits its lockfile, unlike a library.

- [ ] **Step 5: Commit**

```bash
git add sensor/Cargo.toml sensor/Cargo.lock sensor/src/tracer.rs sensor/src/main.rs
git commit -m "feat: add Rust sensor crate skeleton with tracer module"
```

---

### Task 2: `parser.rs`

**Files:**
- Create: `sensor/src/parser.rs`
- Modify: `sensor/src/main.rs` (add `mod parser;`)

**Interfaces:**
- Consumes: nothing from Task 1 directly (independent module).
- Produces (for Task 3): `parser::parse_trace_log(log_text: &str) -> Vec<serde_json::Value>` (`pub`). Each `Value` is a JSON object with exactly one of these shapes:
  - `{"event_type": "process_spawn", "process_ref": {"pid": <u32>, "name": <string>, "parent_pid": 0}}`
  - `{"event_type": "file_write", "file_ref": {"path": <string>, "action": "write"}}`
  - `{"event_type": "network_connect", "network_ref": {"dst_ip": <string>, "dst_port": <u16>, "protocol": "tcp"}}`

- [ ] **Step 1: Write the module with inline tests**

Create `sensor/src/parser.rs`:

```rust
use regex::Regex;
use serde_json::{json, Value};

const WRITE_FLAGS: [&str; 3] = ["O_WRONLY", "O_RDWR", "O_CREAT"];

pub fn parse_trace_log(log_text: &str) -> Vec<Value> {
    let execve_re = Regex::new(r#"^(\d+)\s+execve\("([^"]+)""#).unwrap();
    let openat_re = Regex::new(r#"^(\d+)\s+openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)"#).unwrap();
    let connect_re = Regex::new(
        r#"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)"#,
    )
    .unwrap();

    let mut events = Vec::new();

    for raw_line in log_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = execve_re.captures(line) {
            let pid: u32 = caps[1].parse().unwrap_or(0);
            let path = &caps[2];
            let name = path.rsplit('/').next().unwrap_or(path);
            events.push(json!({
                "event_type": "process_spawn",
                "process_ref": {"pid": pid, "name": name, "parent_pid": 0}
            }));
            continue;
        }

        if let Some(caps) = openat_re.captures(line) {
            let path = &caps[2];
            let flags = &caps[3];
            if WRITE_FLAGS.iter().any(|f| flags.contains(f)) {
                events.push(json!({
                    "event_type": "file_write",
                    "file_ref": {"path": path, "action": "write"}
                }));
            }
            continue;
        }

        if let Some(caps) = connect_re.captures(line) {
            let port: u16 = caps[2].parse().unwrap_or(0);
            let ip = &caps[3];
            events.push(json!({
                "event_type": "network_connect",
                "network_ref": {"dst_ip": ip, "dst_port": port, "protocol": "tcp"}
            }));
            continue;
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_SAMPLE: &str = r#"
12345 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
12346 openat(AT_FDCWD, "/tmp/readme.txt", O_RDONLY) = 4
"#;

    #[test]
    fn test_parses_process_spawn() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let spawns: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "process_spawn")
            .collect();
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0]["process_ref"]["name"], "touch");
        assert_eq!(spawns[0]["process_ref"]["pid"], 12345);
    }

    #[test]
    fn test_parses_file_write_but_not_read_only() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let writes: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "file_write")
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0]["file_ref"]["path"], "/etc/mirraura-test-marker");
    }

    #[test]
    fn test_parses_network_connect() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let conns: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "network_connect")
            .collect();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0]["network_ref"]["dst_port"], 31337);
        assert_eq!(conns[0]["network_ref"]["dst_ip"], "127.0.0.1");
    }

    #[test]
    fn test_empty_log_gives_no_events() {
        let events: Vec<Value> = parse_trace_log("");
        assert!(events.is_empty());
    }
}
```

- [ ] **Step 2: Wire the module into main.rs**

In `sensor/src/main.rs`, change:

```rust
mod tracer;
```

to:

```rust
mod parser;
mod tracer;
```

- [ ] **Step 3: Run tests to verify they pass**

```bash
docker run --rm \
  -v "$(pwd)/sensor:/sensor" \
  -v mirraura-cargo-registry:/usr/local/cargo/registry \
  -w /sensor \
  rust:1-alpine \
  sh -c "apk add --no-cache build-base >/dev/null 2>&1 && cargo test"
```

Expected: `test result: ok. 8 passed; 0 failed` (4 from Task 1's `tracer` module + 4 new from `parser`).

- [ ] **Step 4: Commit**

```bash
git add sensor/src/parser.rs sensor/src/main.rs sensor/Cargo.lock
git commit -m "feat: add Rust sensor's strace-output parser"
```

---

### Task 3: `main.rs` entrypoint

**Files:**
- Modify: `sensor/src/main.rs`

**Interfaces:**
- Consumes (from Task 1): `tracer::run_strace(sample_path: &str) -> std::io::Result<String>`. (from Task 2): `parser::parse_trace_log(log_text: &str) -> Vec<serde_json::Value>`.
- Produces: the compiled `sensor` binary's full CLI behavior — `sensor <sample_path>` prints one JSON line per event to stdout, flushed immediately, ~300ms apart. Nothing else depends on this task at the Rust level; Task 6 wires the compiled binary into the Docker image and backend.

- [ ] **Step 1: Write main.rs with an inline-tested helper**

Replace the entire contents of `sensor/src/main.rs`:

```rust
mod parser;
mod tracer;

use std::env;
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

const DEVICE_ID: &str = "shadow-node";

fn wrap_event(raw: Value) -> Value {
    let mut event = json!({
        "event_id": Uuid::new_v4().to_string(),
        "device_id": DEVICE_ID,
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false),
        "baseline_deviation_score": 0.0,
    });
    if let (Value::Object(event_map), Value::Object(raw_map)) = (&mut event, raw) {
        event_map.extend(raw_map);
    }
    event
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: sensor <path-to-sample>");
        process::exit(1);
    }
    let sample_path = &args[1];

    let log_text = match tracer::run_strace(sample_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("strace failed: {e}");
            process::exit(1);
        }
    };

    let raw_events = parser::parse_trace_log(&log_text);
    let stdout = io::stdout();

    for raw in raw_events {
        let event = wrap_event(raw);
        println!("{event}");
        stdout.lock().flush().ok();
        thread::sleep(Duration::from_millis(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_event_merges_envelope_and_raw_fields() {
        let raw = json!({
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0}
        });
        let event = wrap_event(raw);
        assert_eq!(event["device_id"], DEVICE_ID);
        assert_eq!(event["baseline_deviation_score"], 0.0);
        assert_eq!(event["event_type"], "process_spawn");
        assert_eq!(event["process_ref"]["name"], "sh");
        assert!(event["event_id"].is_string());
        assert!(event["timestamp"].is_string());
    }

    #[test]
    fn test_wrap_event_generates_unique_ids() {
        let raw1 = json!({
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0}
        });
        let raw2 = raw1.clone();
        let e1 = wrap_event(raw1);
        let e2 = wrap_event(raw2);
        assert_ne!(e1["event_id"], e2["event_id"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
docker run --rm \
  -v "$(pwd)/sensor:/sensor" \
  -v mirraura-cargo-registry:/usr/local/cargo/registry \
  -w /sensor \
  rust:1-alpine \
  sh -c "apk add --no-cache build-base >/dev/null 2>&1 && cargo test"
```

Expected: `test result: ok. 10 passed; 0 failed` (8 from Tasks 1-2 + 2 new `wrap_event` tests).

- [ ] **Step 3: Cross-language parity sanity check (manual, one-time — not committed)**

Run the parser's fixture trace through both implementations and compare the event shapes by eye. This confirms Rust and Python agree before the Python files are deleted in Task 4:

```bash
python3 -c "
from sensor.parser import parse_trace_log
import json
trace = open('/dev/stdin').read()
for e in parse_trace_log(trace):
    print(json.dumps(e))
" <<'EOF'
12345 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
EOF
```

(If Python isn't runnable on the host either, skip this and trust the two test suites' shared fixture — `TRACE_SAMPLE` in `sensor/src/parser.rs` is byte-identical to `sensor/tests/test_parser.py`'s fixture, and both assert the same three event shapes from it, which is the real parity evidence.) No commit for this step — it's a development-time check only.

- [ ] **Step 4: Commit**

```bash
git add sensor/src/main.rs
git commit -m "feat: wire Rust sensor's CLI entrypoint (tracer -> parser -> event stream)"
```

---

### Task 4: Delete the Python sensor

**Files:**
- Delete: `sensor/sensor.py`
- Delete: `sensor/tracer.py`
- Delete: `sensor/parser.py`
- Delete: `sensor/tests/test_parser.py`
- Delete: `sensor/tests/test_tracer.py`

**Interfaces:**
- Consumes: nothing (Task 3's Rust crate is already a complete, tested replacement).
- Produces: nothing — this task only removes files.

- [ ] **Step 1: Delete the Python files and their tests**

```bash
git rm sensor/sensor.py sensor/tracer.py sensor/parser.py sensor/tests/test_parser.py sensor/tests/test_tracer.py
```

If `sensor/tests/` is now empty (no other files in it), also remove the now-empty directory:

```bash
rmdir sensor/tests 2>/dev/null || true
```

- [ ] **Step 2: Confirm the Rust suite still passes (nothing in it depended on the deleted Python files)**

```bash
docker run --rm \
  -v "$(pwd)/sensor:/sensor" \
  -v mirraura-cargo-registry:/usr/local/cargo/registry \
  -w /sensor \
  rust:1-alpine \
  sh -c "apk add --no-cache build-base >/dev/null 2>&1 && cargo test"
```

Expected: `test result: ok. 10 passed; 0 failed` — unchanged from Task 3, confirming the Rust crate never referenced the Python files.

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: remove the Python sensor, replaced by the Rust crate"
```

---

### Task 5: `shadow-image/Dockerfile` multi-stage build

**Files:**
- Modify: `shadow-image/Dockerfile`

**Interfaces:**
- Consumes (from Tasks 1-4): the complete `sensor/` Rust crate (`Cargo.toml`, `Cargo.lock`, `src/`).
- Produces (for Task 6): a `mirraura-shadow:latest` image with the compiled binary at `/sensor/sensor`, plus `strace` and `bash`, no Python.

- [ ] **Step 1: Rewrite the Dockerfile**

Replace the entire contents of `shadow-image/Dockerfile`:

```dockerfile
FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /sensor
COPY sensor/Cargo.toml sensor/Cargo.lock ./
COPY sensor/src ./src
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache strace bash
COPY --from=build /sensor/target/release/sensor /sensor/sensor
WORKDIR /samples
CMD ["sleep", "infinity"]
```

- [ ] **Step 2: Build the image and verify the binary runs inside it**

From the repo root:

```bash
docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
```

Expected: build succeeds (first run compiles the crate from scratch inside the container — this is a separate build cache from the `mirraura-cargo-registry` volume used in Tasks 1-3, since Docker's own layer cache handles it here).

```bash
docker run --rm mirraura-shadow:latest /sensor/sensor
```

Expected: exits non-zero and prints `usage: sensor <path-to-sample>` to stderr — proves the binary was compiled correctly and runs inside the final Alpine runtime stage (i.e., no glibc/musl linking mismatch, no missing shared libraries).

```bash
docker run --rm mirraura-shadow:latest which strace bash
```

Expected: both print a path — confirms the runtime stage has the tools the compiled binary shells out to.

- [ ] **Step 3: Commit**

```bash
git add shadow-image/Dockerfile
git commit -m "feat: build the shadow image's sensor as a Rust multi-stage build"
```

---

### Task 6: Backend wiring, docs, manual end-to-end verification

**Files:**
- Modify: `backend/dockermanager.go:111-113`
- Modify: `docs/concepts.md`

**Interfaces:**
- Consumes (from Task 5): the `mirraura-shadow:latest` image with `/sensor/sensor`.
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Update the backend's RunSensor invocation**

In `backend/dockermanager.go`, change:

```go
func (m *DockerManager) RunSensor(ctx context.Context, containerID, samplePathInContainer string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"python3", "/sensor/sensor.py", samplePathInContainer})
}
```

to:

```go
func (m *DockerManager) RunSensor(ctx context.Context, containerID, samplePathInContainer string) (<-chan string, error) {
	return m.execAndStream(ctx, containerID, []string{"/sensor/sensor", samplePathInContainer})
}
```

- [ ] **Step 2: Confirm the Go suite still builds and passes**

```bash
cd backend && go build ./... && go test ./... -v
```

Expected: build succeeds, all tests pass (no existing Go test asserts the literal `RunSensor` command array, so this is a build/regression check, not a behavior-changing one).

- [ ] **Step 3: Update the tech notes**

In `docs/concepts.md`, replace:

```markdown
**Python (verdict engine + in-container sensor, `verdict-engine/`, `sensor/`)** — Fast to write correct data-processing/scoring logic in, the natural language for anything ML-adjacent (so a phase-2 trained classifier slots in with no rewrite), and the language the mentor expects to see used.
```

with:

```markdown
**Python (verdict engine, `verdict-engine/`)** — Fast to write correct data-processing/scoring logic in, the natural language for anything ML-adjacent (so a phase-2 trained classifier slots in with no rewrite), and the language the mentor expects to see used.

**Rust (in-container sensor, `sensor/`)** — The sensor parses `strace`'s raw text output from an untrusted sample's behavior — exactly the kind of string/byte handling where a memory-safety bug would matter most, and Rust's ownership model rules out a whole class of parsing bugs at compile time. It also compiles to a single static-ish binary with no runtime to install in the shadow image, so the container that runs untrusted samples carries less software (no Python interpreter, no pip packages) than it did before.
```

In `docs/concepts.md`, replace:

```markdown
**strace (sensor, inside the shadow container)** — A standard Linux tool that logs every syscall a process makes. The sensor runs the sample under `strace -f -e trace=execve,openat,connect` so it sees process spawns, file writes, and network connections without writing a custom kernel-level instrumentation layer — a well-understood, battle-tested way to observe behavior cheaply.
```

with:

```markdown
**strace (sensor, inside the shadow container)** — A standard Linux tool that logs every syscall a process makes. The sensor runs the sample under `strace -f -e trace=execve,openat,connect` so it sees process spawns, file writes, and network connections without writing a custom kernel-level instrumentation layer — a well-understood, battle-tested way to observe behavior cheaply.
*In Mirraura:* the sensor that shells out to `strace` is a compiled Rust binary (previously Python) — same invocation, same three syscalls traced, same events out; only the language parsing `strace`'s output changed.
```

- [ ] **Step 4: Manual end-to-end verification**

Bring the stack up and confirm the Rust sensor produces the same verdicts the Python sensor did in earlier sessions' verifications:

1. `docker compose up --build -d` (the `verdict-engine`/`backend`/`frontend`/`monitored-endpoint` services — the shadow image itself was already rebuilt in Task 5's Step 2, but rebuild it again here if any Task 5/6 change postdates that build: `docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .`)
2. Upload `samples/spawn_and_write.sh` via `POST /api/samples` and confirm the verdict is `Suspicious` at confidence `0.55` with causal chain entries for a spawned `touch` process and a write to `/etc/mirraura-test-marker` — matching what the Python sensor produced for this exact sample in the item-2 verification session.
3. Upload `samples/connect_odd_port.sh` and confirm `Suspicious` at confidence `0.2` with a causal chain entry for the odd-port connection.
4. Upload the EICAR sample (see `samples/EICAR.md` for regeneration instructions) and confirm the known-bad-hash short-circuit still fires (`Compromised` at confidence `1.0` via the hash match, not the behavioral rules — this path doesn't even depend on the sensor's parsing, but confirms the shadow container + sensor pipeline runs cleanly end-to-end for a file that also has other behavior).
5. Confirm the dashboard's live event feed still shows events arriving with visible pacing (not all at once) — the flushed, paced `println!` calls doing their job over the real `docker exec` pipe, not just in a unit test.
6. `docker compose down` when done.

If any verdict differs from the Python sensor's known behavior, investigate the Rust parser/tracer for a discrepancy before considering this task done — parity with the existing rule thresholds and the item-3 fixture corpus is the actual bar for "swap-in replacement," not just passing `cargo test`.

- [ ] **Step 5: Commit**

```bash
git add backend/dockermanager.go docs/concepts.md
git commit -m "feat: wire the Rust sensor into the backend and update tech notes"
```
