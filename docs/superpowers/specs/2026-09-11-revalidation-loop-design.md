# Mirraura — Re-validation Loop (Sub-project 2, item 3)

Status: approved for implementation planning
Date: 2026-09-11
Scope: third item of the Sub-project 2 finishing phase. Builds on the completed continuous-monitoring layer and human-approval gate (both merged to `main`).

## 1. Problem & Context

Today there is no way to safely try a change to the behavioral rule scorer (`verdict-engine/rule_scorer.py`'s `RULE_WEIGHTS`, thresholds, or logic) and know what it would have done to past traffic before it goes live. The human-approval gate spec (item 2, §1) explicitly deferred this: "approving a weight change well requires re-running it against history first, which is item 3."

A second, harder problem surfaced during design: **no archive of raw event captures exists yet.** `POST /score` (`verdict-engine/app.py`) receives the raw `events` that produced a verdict but only ever persists the verdict summary (`verdict_id`, `sample_hash`, `verdict`, `confidence`, `causal_chain`) to the audit log — the events themselves are discarded after scoring. "Replay archived event captures" (spec §14, item 3) is not possible against anything that exists today. This item therefore includes standing up that archive, not just the replay tool.

## 2. Goals

- A small, hand-authored, ground-truth-labeled fixture corpus that isolates each scoring rule (and the no-telemetry / known-hash edge cases), so a candidate rule change gets a real accuracy percentage, not a guess.
- Going forward, every real `/score` call (sample upload or continuous-monitoring tick) archives its raw events alongside the verdict that was produced at the time — honestly labeled as "what the engine believed then," not a claimed ground truth.
- A standalone CLI tool, `verdict-engine/revalidate.py`, that loads a candidate scorer implementation, replays both corpora against it, and reports:
  - **Fixtures:** before/after accuracy against the known-correct label (the "red-to-green flip" story).
  - **Archive:** verdict drift — which real captures would score differently under the candidate, and in which direction.
- The tool runs with no live stack required for the fixture half (no Docker, no running backend/frontend) — only the archive half needs the verdict-engine's data volume.

## 3. Non-goals

- No dashboard/UI integration — this is an offline analysis tool run from a terminal, not a live-path feature. (Revisit only if a future item needs it visible in the browser.)
- No mandatory ground-truth labeling added to the live upload or continuous-monitoring flow — real captures are archived with their verdict-at-capture-time only, never a fabricated "true" label.
- No automatic promotion of a candidate scorer to production — a human reads the report and, if satisfied, manually edits `rule_scorer.py` themselves. This tool informs that decision; it doesn't make it.
- No change to `rule_scorer.py`'s actual rules or weights as part of this item — this item ships the *tool* to evaluate future changes, not a change itself.
- No retrofit of `AuditLog`'s hash-chaining onto the new event archive (see §4) — the archive is diagnostic data, not a tamper-evidence-critical record.

## 4. Architecture

```
verdict-engine (FastAPI, single process, no new service)

POST /score (existing handler, gains one step):
  1-4. unchanged (hash short-circuit, or rule scoring; audit_log.append(record))
  5. NEW: event_archive.append({
       verdict_id, sample_hash, source, events,
       verdict_at_capture: verdict, confidence_at_capture: confidence,
       timestamp: record["timestamp"],
     })
     Best-effort: on failure, log a warning, still return the verdict normally.
     (Mirrors the existing auto-propose-hash side effect's failure handling.)

New file: verdict-engine/event_archive.py
  EventArchive — append-only JSONL, one line per /score call.
  No hash-chaining (unlike AuditLog): this is bulk diagnostic data, not
  part of the tamper-evident trail. Default path /data/event_archive.jsonl
  (same Docker volume as the audit log), overridable via EVENT_ARCHIVE_PATH.

New: verdict-engine/revalidation_fixtures/*.json
  Hand-authored Event lists + an expected_verdict label, one file per case,
  covering: no telemetry (Inconclusive), zero-confidence benign activity
  (Normal), each individual rule in isolation (Suspicious), the combined
  case that crosses the 0.6 Compromised threshold, and the rapid-file-changes
  threshold boundary. Not derived from live sandbox runs — literal JSON
  matching schemas.Event, chosen so each fixture exercises exactly one
  documented rule-scorer branch. This is what makes the fixture half
  Docker-free.

New: verdict-engine/revalidation_report.py
  Pure functions, no I/O beyond what's passed in — the testable core:
    score_with(scorer_module, events) -> (verdict, confidence, chain)
    run_fixtures(fixtures, current_scorer, candidate_scorer) -> [...]
    run_archive(archive_entries, candidate_scorer) -> [...]
    build_report(fixture_results, archive_results) -> dict
    format_table(report) -> str

New: verdict-engine/revalidate.py (CLI entrypoint)
  argparse: --candidate <path.py> (required), --archive-path (default
  EVENT_ARCHIVE_PATH env or /data/event_archive.jsonl), --fixtures-dir
  (default ./revalidation_fixtures), --report-dir (default
  ./revalidation_reports).
  1. Dynamically load the candidate module (importlib.util), fail fast
     with a clear error if it's missing score_events or verdict_from_score.
  2. Load fixtures (always available, no Docker needed).
  3. Try loading the archive; if the file doesn't exist or is unreachable
     (e.g. not run inside the verdict-engine container), skip the archive
     section with a note in the report rather than failing the whole run —
     the fixture half must still work standalone.
  4. Run both, print format_table(report) to stdout, write the same
     report as JSON to <report-dir>/<timestamp>.json.

New dirs: verdict-engine/revalidation_candidates/, verdict-engine/revalidation_reports/
  Scratch space for user-authored candidate scorers and generated reports.
  Both gitignored (a .gitkeep each) — these are run artifacts, not source.

Typical usage:
  docker compose exec verdict-engine \
    python revalidate.py --candidate revalidation_candidates/lower_threshold.py
```

## 5. Why events weren't already archived, and why a separate file now

Sub-project 1's audit log was designed as a tamper-evident record of *decisions* (verdicts, isolate/reconnect actions, hash approvals) — deliberately lean, since every field is hashed into the chain and every record is displayed in the dashboard's audit log table. Raw event payloads were never part of that design and were discarded once scored.

The new event archive is intentionally a separate, unchained file rather than a new field on the audit log record: it exists purely to feed offline replay, has no tamper-evidence requirement, and keeping it separate means the audit log's shape, size, and hash-chain semantics are completely unaffected by this item — consistent with item 2's precedent of not touching `AuditLog` internals for a new, unrelated concern.

## 6. Components

- **`verdict-engine/event_archive.py`** (new) — `EventArchive` class: `append(record)` writes one JSONL line, `all()` reads them back, tolerant of malformed lines (skip + warn, matching `AuditLog`'s read tolerance elsewhere in the codebase).
- **`verdict-engine/app.py`** — `score()` gains the archive-write step (§4); module-level `event_archive = EventArchive(Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")))`.
- **`verdict-engine/revalidation_fixtures/*.json`** (new, 7 files) — one per rule-scorer branch: `normal.json`, `no_telemetry.json`, `single_rule_spawn.json`, `single_rule_sensitive_write.json`, `single_rule_odd_port.json`, `rapid_file_changes.json`, `compromised_combined.json`. Each: `{"events": [...], "expected_verdict": "..."}`.
- **`verdict-engine/revalidation_report.py`** (new) — scoring/diffing/formatting logic, unit-testable without files or Docker.
- **`verdict-engine/revalidate.py`** (new) — CLI entrypoint (argparse + candidate loading + wiring the above together).
- **`verdict-engine/revalidation_candidates/.gitkeep`**, **`verdict-engine/revalidation_reports/.gitkeep`** (new) — scratch dirs, gitignored otherwise.
- **`.gitignore`** — add `verdict-engine/revalidation_candidates/*.py` and `verdict-engine/revalidation_reports/*.json` (keeping the `.gitkeep`s).
- **`docker-compose.yml`** — `verdict-engine` service gains `EVENT_ARCHIVE_PATH=/data/event_archive.jsonl` alongside the existing `AUDIT_LOG_PATH`, same `audit-log-data` volume (already mounted at `/data`). Also gains two bind mounts, `./verdict-engine/revalidation_candidates:/app/revalidation_candidates` and `./verdict-engine/revalidation_reports:/app/revalidation_reports` — without these, a candidate file added on the host wouldn't be visible inside the built image without a rebuild, and generated reports would vanish when the container is removed (the image has no other host-visible mount; `WORKDIR /app` in the Dockerfile is where `COPY . .` lands, so bind-mounting these two subdirectories over it is what makes `docker compose exec verdict-engine python revalidate.py` usable for real iteration).
- **`docs/concepts.md`** — note the new event archive and the re-validation tool under the verdict-engine section, per this project's CLAUDE.md convention of documenting new tools as part of the same change.

## 7. Error Handling

- Event-archive write failure inside `/score` → logged as a warning, `/score` response is unaffected (mirrors the existing auto-propose-hash best-effort pattern in the same handler).
- A malformed line in `event_archive.jsonl` → skipped with a warning when `revalidate.py` loads the archive, not a hard failure (one corrupt line shouldn't block reviewing everything else).
- `--candidate` path that doesn't exist, isn't valid Python, or is missing `score_events`/`verdict_from_score` → `revalidate.py` exits with a clear, specific error before scoring anything (fail fast — a half-run report comparing against a broken candidate would be misleading).
- Archive file missing/unreadable (e.g. running outside the container with no volume access) → the fixture section still runs and reports; the archive section is explicitly marked "skipped: <reason>" in both the table and the JSON report, never silently empty.
- A fixture file that fails its own sanity check (see §8) → `revalidate.py` reports it as a fixture-corpus error, not a candidate failure, so a stale fixture doesn't get misread as "the candidate got worse."

## 8. Testing

- **`verdict-engine/tests/test_event_archive.py`** — append/read-back, tolerance of a malformed line, matching the existing `test_audit_log.py` style.
- **`verdict-engine/tests/test_app.py`** — extended: a `/score` call also writes an archive entry with the right shape; archive-write failure doesn't break the `/score` response.
- **`verdict-engine/tests/test_revalidation_report.py`** — the core logic, entirely in-memory (no files, no Docker): `run_fixtures`/`run_archive`/`build_report`/`format_table` against small synthetic inputs, including a candidate that changes a verdict (proves drift/accuracy-delta detection actually works) and one that doesn't (proves it correctly reports no change).
- **Fixture sanity test** (`verdict-engine/tests/test_revalidation_fixtures.py`) — asserts every checked-in fixture's `expected_verdict` matches what the *current* `rule_scorer.py` actually produces today, so a fixture can't silently drift out of sync with the rules it's supposed to test.
- **Manual end-to-end** (mirrors the item 2 verification style): bring the stack up, upload a sample, confirm an entry appears in `event_archive.jsonl`; write a trivial candidate scorer that flips one rule's weight; run `revalidate.py` inside the container; confirm the fixture table shows a real before/after accuracy change and the archive section shows the uploaded sample's drift (or lack of it).

## 9. Global Constraints (for the implementation plan)

- New event archive: `verdict-engine/event_archive.py`, JSONL, no hash-chaining, default path `/data/event_archive.jsonl` via `EVENT_ARCHIVE_PATH`, same Docker volume as the audit log.
- Archiving is best-effort and must never change `/score`'s response or fail the request.
- Fixture corpus is hand-authored literal `Event` JSON (not derived from live sandbox runs) — the fixture half of `revalidate.py` must run without Docker.
- "Before" for fixtures is always the real, currently-imported `rule_scorer.py`; "before" for archive entries is the stored `verdict_at_capture` (never re-computed) — "after" is always the `--candidate` module.
- Candidate scorer contract: a Python file exposing `score_events(events) -> (float, List[str])` and `verdict_from_score(confidence, chain, had_telemetry) -> str`, loaded via `importlib.util`.
- No UI/dashboard change, no new backend/frontend routes — this item is entirely inside `verdict-engine/`.
- No automatic write-back to `rule_scorer.py` — the report informs a human decision only.
- `verdict-engine/revalidation_candidates/` and `verdict-engine/revalidation_reports/` are gitignored scratch space (each keeps a `.gitkeep`).
