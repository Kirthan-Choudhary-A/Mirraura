# Mirraura — Rust Sensor Agent (Sub-project 2, item 4)

Status: approved for implementation planning
Date: 2026-09-11
Scope: fourth item of the Sub-project 2 finishing phase. Builds on the completed continuous-monitoring layer, human-approval gate, and re-validation loop (all merged to `main`).

## 1. Problem & Context

The sensor that runs inside the shadow container (`sensor/`) is Python today — a deliberate Sub-project 1 shortcut, called out explicitly in the original design spec's non-goals (§3: "Rust sensor agent — sensor is a Python script for now") and revisited in Sub-project 2's scope (§14, item 4: "Rust rewrite of the sensor agent (swap-in replacement for the Python sensor, same event schema out)"). This item builds that replacement.

The sensor's job is narrow and already well-isolated: run `strace` against an uploaded sample inside the shadow container, parse the resulting syscall trace into Mirraura's canonical `Event` shape, and print one JSON line per event to stdout. `sensor/tracer.py` wraps the `strace` invocation and strips its own root `execve` line; `sensor/parser.py` regex-parses three syscall types (`execve`, `openat`, `connect`) into `process_spawn`/`file_write`/`network_connect` events; `sensor/sensor.py` is the thin CLI entrypoint that adds `event_id`/`device_id`/`timestamp`/`baseline_deviation_score` and prints. The Go backend invokes it via `docker exec` (`backend/dockermanager.go`'s `RunSensor`) and streams its stdout lines.

## 2. Goals

- A Rust binary that is a full, behavioral swap-in for the Python sensor: same `strace`-based capture mechanism, same three event types, same canonical `Event` JSON shape (`event_id`, `device_id`, `event_type`, `process_ref`/`network_ref`/`file_ref`, `timestamp`, `baseline_deviation_score`), one JSON line per event on stdout, same ~0.3s pacing between lines for the dashboard's live event feed.
- The existing verdict-engine (`rule_scorer.py`) and dashboard require zero changes — from their point of view, nothing observable is different.
- `shadow-image/Dockerfile` builds the Rust binary via a multi-stage Docker build (matching `backend/Dockerfile`'s existing Go pattern) instead of installing Python; the final image drops the Python runtime entirely.
- `backend/dockermanager.go`'s `RunSensor` is updated to exec the compiled binary instead of `python3 sensor.py`.

## 3. Non-goals

- No change to the underlying tracing mechanism — `strace` stays. This is a language/runtime swap (Python → Rust), not a tracing-technology swap (no ptrace crate, no eBPF). A lower-level rewrite is a much larger, riskier project than "swap-in replacement" calls for, and nothing in the spec asks for it.
- No change to `monitored-endpoint/poller.py`/`differ.py` (the continuous-monitoring poller). It's a different component solving a different problem (snapshot-diffing an always-on container, not tracing a single sample run) and isn't mentioned by item 4.
- No dual-maintenance period. The Python sensor files (`sensor/sensor.py`, `sensor/tracer.py`, `sensor/parser.py`, their tests) are deleted, not kept alongside as a fallback — "swap-in replacement" means replacement.
- No change to the canonical `Event` schema itself (`verdict-engine/schemas.py`) — the Rust sensor must produce events that already validate against it unchanged.

## 4. Architecture

```
shadow-image (Docker multi-stage build)
  Stage 1 (build): rust:1-alpine, `cargo build --release` the sensor binary
  Stage 2 (runtime): alpine:3.19 + strace + bash (no Python)
    COPY --from=build the compiled binary to /sensor/sensor

sensor/ (Rust binary crate, replaces the 3 Python files 1:1)
  Cargo.toml       — deps: regex, serde + serde_json, uuid (v4), chrono
  src/tracer.rs    — spawn `strace -f -e trace=execve,openat,connect -o <tmp>
                      bash <sample_path>`, read the temp file, strip the
                      leading root execve line (same logic as tracer.py,
                      same comment explaining why)
  src/parser.rs    — same 3 regexes as parser.py: execve → process_spawn,
                      openat (O_WRONLY|O_RDWR|O_CREAT only) → file_write,
                      connect → network_connect
  src/main.rs      — argv[1] = sample path; tracer → parser; wrap each raw
                      event with event_id (uuid v4), device_id
                      ("shadow-node"), timestamp (RFC3339 with microseconds
                      and +00:00 offset, matching Python's
                      datetime.now(timezone.utc).isoformat() style),
                      baseline_deviation_score (0.0); print one JSON line
                      per event, ~0.3s sleep between prints
  tests/           — cargo test, ports test_parser.py's and test_tracer.py's
                      cases 1:1 (see §8)

backend/dockermanager.go
  RunSensor(...) exec command changes from
    []string{"python3", "/sensor/sensor.py", samplePathInContainer}
  to
    []string{"/sensor/sensor", samplePathInContainer}
  execAndStream's streaming/scanning logic is unchanged — it just reads
  stdout lines regardless of what produced them.
```

## 5. Why `strace`-shelling instead of native tracing

Rewriting the tracing mechanism itself (ptrace directly, or eBPF) was considered and rejected for this item: it would be a substantially larger project (kernel-version constraints for eBPF, direct syscall-interception complexity for raw ptrace) carrying real risk of behavioral drift from what the verdict engine's rule thresholds and the re-validation loop's fixture corpus (item 3) already assume. `strace` itself is unchanged and already documented in `docs/concepts.md` as "a well-understood, battle-tested way to observe behavior cheaply" — that reasoning doesn't change just because the process invoking and parsing it is now Rust instead of Python. The actual, real goal of this item — removing Python from the shadow image's runtime and gaining a compiled-language sensor with memory safety guarantees when parsing untrusted trace output — is fully achieved by the language swap alone.

## 6. Components

- **`sensor/Cargo.toml`** (new) — binary crate manifest; `regex`, `serde`, `serde_json`, `uuid`, `chrono`.
- **`sensor/src/tracer.rs`** (new, replaces `sensor/tracer.py`) — `run_strace(sample_path: &str) -> io::Result<String>`, `strip_root_execve(trace_text: &str) -> String`.
- **`sensor/src/parser.rs`** (new, replaces `sensor/parser.py`) — `parse_trace_log(log_text: &str) -> Vec<RawEvent>` (an internal struct/enum mirroring the three raw-event shapes before the `main.rs` wrapper adds the envelope fields).
- **`sensor/src/main.rs`** (new, replaces `sensor/sensor.py`) — CLI entrypoint, event envelope + printing.
- **`sensor/tests/`** (new, replaces `sensor/tests/test_parser.py` + `sensor/tests/test_tracer.py`) — `tracer_test.rs`, `parser_test.rs` (or `#[cfg(test)]` inline modules — implementer's call, following whichever is more idiomatic and matches how the tests read most like their Python originals).
- **Deleted:** `sensor/sensor.py`, `sensor/tracer.py`, `sensor/parser.py`, `sensor/tests/test_parser.py`, `sensor/tests/test_tracer.py`.
- **`shadow-image/Dockerfile`** (rewritten) — multi-stage build per §4.
- **`backend/dockermanager.go`** (one-line change) — `RunSensor`'s exec command.
- **`docs/concepts.md`** — the "Languages" section's Python bullet (currently covering both `verdict-engine/` and `sensor/`) splits: Python's rationale stays for `verdict-engine/` only; a new Rust bullet explains the choice for `sensor/` (memory safety parsing untrusted trace output, single static binary, no runtime needed in the shadow image). The `strace` tools bullet gets a one-clause update noting the sensor is now the Rust binary.

## 7. Error Handling

- Unchanged from the Python sensor's existing (implicit) behavior: if `strace` fails to run or the sample errors out, the trace file may be empty or partial — `parse_trace_log` already handles this by simply producing fewer/no events (matches `test_empty_log_gives_no_events`); the Rust parser preserves this — no new error-surfacing behavior is being added that the Python version didn't have, since this item's job is parity, not improvement.
- If `argv[1]` (the sample path) is missing, print a usage message to stderr and exit non-zero, matching `sensor.py`'s existing `usage: sensor.py <path-to-sample>` behavior (message text updated to the new binary name).
- Malformed/unparseable individual `strace` lines are silently skipped by `parse_trace_log`, matching the Python parser's existing behavior (no `match` → the line is simply not turned into an event).

## 8. Testing

- **`sensor/tests/tracer_test.rs`**: `strip_root_execve` — strips only the leading root execve line (multi-line case), only-root-line → empty string, empty string → empty string, no-execve-line → unchanged. Direct ports of `test_tracer.py`'s four cases, same fixture strings.
- **`sensor/tests/parser_test.rs`**: `parse_trace_log` — parses a process spawn, parses a file write but not a read-only open, parses a network connect, empty log gives no events. Direct ports of `test_parser.py`'s four cases, same fixture strace-output string.
- **Cross-language parity check** (one-time, during implementation, not committed as permanent test infrastructure): run the same raw `strace` output fixture through both the old Python parser and the new Rust parser before the Python files are deleted, confirm matching event shapes. This is a development-time sanity check, not ongoing CI.
- **Manual end-to-end verification** (Claude drives Docker directly, as in items 2 and 3 — the user doesn't use Docker): rebuild `shadow-image`, re-upload the same samples used in earlier verifications (`samples/spawn_and_write.sh`, `samples/connect_odd_port.sh`, the EICAR known-bad hash), confirm the verdict engine produces the same verdicts/confidence it did under the Python sensor — the real proof that "same event schema out" holds end-to-end, not just at the unit-test level.

## 9. Global Constraints (for the implementation plan)

- Tracing mechanism stays `strace`, invoked the same way (`strace -f -e trace=execve,openat,connect -o <tmp> bash <sample_path>`) — no ptrace crate, no eBPF.
- Event JSON shape is unchanged: `event_id`, `device_id: "shadow-node"`, `event_type`, `process_ref`/`network_ref`/`file_ref` (exactly one of these three per event, matching `schemas.Event`), `timestamp`, `baseline_deviation_score: 0.0`.
- `openat` only becomes a `file_write` event when its flags include `O_WRONLY`, `O_RDWR`, or `O_CREAT` — read-only opens are not events, matching current behavior.
- ~0.3s sleep between printed event lines is preserved (dashboard live-feed pacing, not detection logic).
- `backend/dockermanager.go`'s `RunSensor` execs `/sensor/sensor` (no `python3` prefix) with the sample path as its only argument — `execAndStream`'s stdout-streaming logic is untouched.
- `shadow-image/Dockerfile` is a multi-stage build (`rust:1-alpine` builder → `alpine:3.19` runtime with `strace`+`bash` only, no Python) — same shape as `backend/Dockerfile`'s existing Go multi-stage pattern (alpine→alpine keeps both stages on musl libc, avoiding a glibc/musl ABI mismatch that a debian runtime stage would risk for a binary built on `rust:1-alpine`).
- Full replacement: the Python `sensor/` files and their tests are deleted, not retained as a fallback.
- No change to `verdict-engine/schemas.py`, `rule_scorer.py`, or anything in `monitored-endpoint/`.
