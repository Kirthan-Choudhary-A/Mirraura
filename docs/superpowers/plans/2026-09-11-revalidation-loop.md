# Re-validation Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone CLI tool replays a hand-labeled fixture corpus and an archive of real event captures against a candidate rule scorer, reporting before/after accuracy and verdict drift — so a change to `rule_scorer.py` can be evaluated before it goes live.

**Architecture:** `/score` gains a best-effort side effect that archives raw events to a new, unchained JSONL file (`event_archive.py`) alongside the verdict it produced at the time. A hand-authored fixture corpus (literal `Event` JSON with a known-correct label, no Docker required) lives under `verdict-engine/revalidation_fixtures/`. `revalidation_report.py` holds the pure scoring/diff/report logic; `revalidate.py` is the CLI entrypoint that dynamically loads a candidate scorer module, runs both corpora through it, prints a table, and writes a JSON report.

**Tech Stack:** Python (verdict-engine, stdlib `importlib`/`argparse` only — no new dependencies).

**Spec:** `docs/superpowers/specs/2026-09-11-revalidation-loop-design.md`

## Global Constraints

- New event archive: `verdict-engine/event_archive.py`, JSONL, no hash-chaining, default path `/data/event_archive.jsonl` via `EVENT_ARCHIVE_PATH`, same Docker volume as the audit log.
- Archiving is best-effort and must never change `/score`'s response or fail the request.
- Fixture corpus is hand-authored literal `Event` JSON (not derived from live sandbox runs) — the fixture half of `revalidate.py` must run without Docker.
- "Before" for fixtures is always the real, currently-imported `rule_scorer.py`; "before" for archive entries is the stored `verdict_at_capture` (never re-computed) — "after" is always the `--candidate` module.
- Candidate scorer contract: a Python file exposing `score_events(events) -> (float, List[str])` and `verdict_from_score(confidence, chain, had_telemetry) -> str`, loaded via `importlib.util`.
- No UI/dashboard change, no new backend/frontend routes — this item is entirely inside `verdict-engine/`.
- No automatic write-back to `rule_scorer.py` — the report informs a human decision only.
- `verdict-engine/revalidation_candidates/` and `verdict-engine/revalidation_reports/` are gitignored scratch space (each keeps a `.gitkeep`).

---

### Task 1: Event archive layer, wired into `/score`

**Files:**
- Create: `verdict-engine/event_archive.py`
- Create: `verdict-engine/tests/test_event_archive.py`
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`
- Modify: `verdict-engine/tests/conftest.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing from other tasks (base layer).
- Produces (for Task 4): `EventArchive(path: Path)` with `.append(record: dict) -> None` and `.all() -> List[dict]`. Every real `/score` call writes one archive record shaped `{"verdict_id": str, "sample_hash": str, "source": str, "events": List[dict], "verdict_at_capture": str, "confidence_at_capture": float, "timestamp": str}`.

- [ ] **Step 1: Write the failing test for the archive class**

Create `verdict-engine/tests/test_event_archive.py`:

```python
from event_archive import EventArchive


def test_append_and_read_back(tmp_path):
    archive = EventArchive(tmp_path / "event_archive.jsonl")
    archive.append({"verdict_id": "v1", "events": []})
    assert archive.all() == [{"verdict_id": "v1", "events": []}]


def test_multiple_appends_preserve_order(tmp_path):
    archive = EventArchive(tmp_path / "event_archive.jsonl")
    archive.append({"verdict_id": "v1"})
    archive.append({"verdict_id": "v2"})
    assert [r["verdict_id"] for r in archive.all()] == ["v1", "v2"]


def test_malformed_line_is_skipped(tmp_path):
    path = tmp_path / "event_archive.jsonl"
    archive = EventArchive(path)
    archive.append({"verdict_id": "v1"})
    with open(path, "a") as f:
        f.write("not valid json\n")
    archive.append({"verdict_id": "v2"})

    records = archive.all()
    assert [r["verdict_id"] for r in records] == ["v1", "v2"]


def test_creates_file_if_missing(tmp_path):
    path = tmp_path / "nested" / "event_archive.jsonl"
    EventArchive(path)
    assert path.exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd verdict-engine && python -m pytest tests/test_event_archive.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'event_archive'`.

- [ ] **Step 3: Implement the archive class**

Create `verdict-engine/event_archive.py`:

```python
import json
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class EventArchive:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, record: dict) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def all(self) -> List[dict]:
        records: List[dict] = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("skipping malformed event-archive line")
        return records
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd verdict-engine && python -m pytest tests/test_event_archive.py -v`
Expected: all PASS.

- [ ] **Step 5: Point tests at a throwaway archive file**

In `verdict-engine/tests/conftest.py`, change:

```python
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)
```

to:

```python
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)
```

And change:

```python
def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
    _TEST_KNOWN_BAD.unlink(missing_ok=True)
```

to:

```python
def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
    _TEST_KNOWN_BAD.unlink(missing_ok=True)
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
```

Add this line to `.gitignore`, next to the existing `verdict-engine/tests/test_audit_log.jsonl` line:

```
verdict-engine/tests/test_event_archive.jsonl
```

- [ ] **Step 6: Write the failing tests for the `/score` wiring**

Add to the end of `verdict-engine/tests/test_app.py`, and add `import app as app_module` as a new line right after the existing `from app import app` import at the top of the file:

```python
def test_score_writes_event_archive_entry():
    events = [
        {
            "event_id": "e1",
            "device_id": "shadow-node",
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0},
            "timestamp": "2026-09-11T00:00:00Z",
            "baseline_deviation_score": 0.0,
        }
    ]
    resp = client.post(
        "/score", json={"sample_hash": "6" * 64, "events": events, "source": "sample"}
    )
    verdict_id = resp.json()["verdict_id"]

    matches = [r for r in app_module.event_archive.all() if r["verdict_id"] == verdict_id]
    assert len(matches) == 1
    assert matches[0]["sample_hash"] == "6" * 64
    assert matches[0]["source"] == "sample"
    assert matches[0]["verdict_at_capture"] == "Suspicious"
    assert matches[0]["events"][0]["event_id"] == "e1"


def test_archive_write_failure_does_not_break_score(monkeypatch):
    def boom(record):
        raise OSError("disk full")

    monkeypatch.setattr(app_module.event_archive, "append", boom)
    resp = client.post("/score", json={"sample_hash": "7" * 64, "events": []})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "Inconclusive"
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_app.py -v`
Expected: FAIL — `AttributeError: module 'app' has no attribute 'event_archive'`.

- [ ] **Step 8: Wire the archive into `/score`**

In `verdict-engine/app.py`, change:

```python
from audit_log import AuditLog
```

to:

```python
from audit_log import AuditLog
from event_archive import EventArchive
```

Change:

```python
audit_log = AuditLog(Path(os.getenv("AUDIT_LOG_PATH", "/data/audit_log.jsonl")))
```

to:

```python
audit_log = AuditLog(Path(os.getenv("AUDIT_LOG_PATH", "/data/audit_log.jsonl")))
event_archive = EventArchive(Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")))
```

Change the end of the `score` function from:

```python
    stored = audit_log.append(record)
    return Verdict(**_strip_entry_hash(stored))
```

to:

```python
    stored = audit_log.append(record)

    try:
        event_archive.append(
            {
                "verdict_id": verdict_id,
                "sample_hash": req.sample_hash,
                "source": req.source,
                "events": [e.model_dump() for e in req.events],
                "verdict_at_capture": verdict,
                "confidence_at_capture": confidence,
                "timestamp": record["timestamp"],
            }
        )
    except Exception:
        logger.warning(
            "failed to archive events for verdict %s", verdict_id, exc_info=True
        )

    return Verdict(**_strip_entry_hash(stored))
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/ -v`
Expected: all PASS, including the full pre-existing suite.

- [ ] **Step 10: Commit**

```bash
git add verdict-engine/event_archive.py verdict-engine/tests/test_event_archive.py verdict-engine/app.py verdict-engine/tests/test_app.py verdict-engine/tests/conftest.py .gitignore
git commit -m "feat: archive raw events alongside every /score verdict"
```

---

### Task 2: Fixture corpus

**Files:**
- Create: `verdict-engine/revalidation_fixtures/normal.json`
- Create: `verdict-engine/revalidation_fixtures/no_telemetry.json`
- Create: `verdict-engine/revalidation_fixtures/single_rule_spawn.json`
- Create: `verdict-engine/revalidation_fixtures/single_rule_sensitive_write.json`
- Create: `verdict-engine/revalidation_fixtures/single_rule_odd_port.json`
- Create: `verdict-engine/revalidation_fixtures/rapid_file_changes.json`
- Create: `verdict-engine/revalidation_fixtures/compromised_combined.json`
- Create: `verdict-engine/tests/test_revalidation_fixtures.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (for Task 4): 7 fixture files under `verdict-engine/revalidation_fixtures/`, each shaped `{"expected_verdict": str, "events": [Event dict, ...]}`.

- [ ] **Step 1: Write the failing sanity test**

Create `verdict-engine/tests/test_revalidation_fixtures.py`:

```python
import json
from pathlib import Path

import rule_scorer
from schemas import Event

FIXTURES_DIR = Path(__file__).parent.parent / "revalidation_fixtures"


def test_seven_fixtures_present():
    assert len(sorted(FIXTURES_DIR.glob("*.json"))) == 7


def test_every_fixture_matches_current_rule_scorer():
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        events = [Event(**e) for e in data["events"]]
        confidence, chain = rule_scorer.score_events(events)
        verdict = rule_scorer.verdict_from_score(confidence, chain, had_telemetry=len(events) > 0)
        assert verdict == data["expected_verdict"], (
            f"{path.name}: expected {data['expected_verdict']}, "
            f"current rule_scorer produced {verdict} (confidence={confidence})"
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd verdict-engine && python -m pytest tests/test_revalidation_fixtures.py -v`
Expected: FAIL — `FileNotFoundError`/empty glob, no fixtures exist yet.

- [ ] **Step 3: Create the fixture files**

Create `verdict-engine/revalidation_fixtures/normal.json`:

```json
{
  "expected_verdict": "Normal",
  "events": [
    {
      "event_id": "e1",
      "device_id": "shadow-node",
      "event_type": "file_write",
      "file_ref": {"path": "/tmp/output.log", "action": "write"},
      "timestamp": "2026-09-11T00:00:00Z",
      "baseline_deviation_score": 0.0
    }
  ]
}
```

Create `verdict-engine/revalidation_fixtures/no_telemetry.json`:

```json
{
  "expected_verdict": "Inconclusive",
  "events": []
}
```

Create `verdict-engine/revalidation_fixtures/single_rule_spawn.json`:

```json
{
  "expected_verdict": "Suspicious",
  "events": [
    {
      "event_id": "e1",
      "device_id": "shadow-node",
      "event_type": "process_spawn",
      "process_ref": {"pid": 100, "name": "sh", "parent_pid": 1},
      "timestamp": "2026-09-11T00:00:00Z",
      "baseline_deviation_score": 0.0
    }
  ]
}
```

Create `verdict-engine/revalidation_fixtures/single_rule_sensitive_write.json`:

```json
{
  "expected_verdict": "Suspicious",
  "events": [
    {
      "event_id": "e1",
      "device_id": "shadow-node",
      "event_type": "file_write",
      "file_ref": {"path": "/etc/passwd", "action": "write"},
      "timestamp": "2026-09-11T00:00:00Z",
      "baseline_deviation_score": 0.0
    }
  ]
}
```

Create `verdict-engine/revalidation_fixtures/single_rule_odd_port.json`:

```json
{
  "expected_verdict": "Suspicious",
  "events": [
    {
      "event_id": "e1",
      "device_id": "shadow-node",
      "event_type": "network_connect",
      "network_ref": {"dst_ip": "127.0.0.1", "dst_port": 31337, "protocol": "tcp"},
      "timestamp": "2026-09-11T00:00:00Z",
      "baseline_deviation_score": 0.0
    }
  ]
}
```

Create `verdict-engine/revalidation_fixtures/rapid_file_changes.json`:

```json
{
  "expected_verdict": "Suspicious",
  "events": [
    {"event_id": "e1", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/tmp/f1", "action": "write"}, "timestamp": "2026-09-11T00:00:00Z", "baseline_deviation_score": 0.0},
    {"event_id": "e2", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/tmp/f2", "action": "write"}, "timestamp": "2026-09-11T00:00:01Z", "baseline_deviation_score": 0.0},
    {"event_id": "e3", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/tmp/f3", "action": "write"}, "timestamp": "2026-09-11T00:00:02Z", "baseline_deviation_score": 0.0},
    {"event_id": "e4", "device_id": "shadow-node", "event_type": "file_delete", "file_ref": {"path": "/tmp/f1", "action": "delete"}, "timestamp": "2026-09-11T00:00:03Z", "baseline_deviation_score": 0.0},
    {"event_id": "e5", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/tmp/f4", "action": "write"}, "timestamp": "2026-09-11T00:00:04Z", "baseline_deviation_score": 0.0},
    {"event_id": "e6", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/tmp/f5", "action": "write"}, "timestamp": "2026-09-11T00:00:05Z", "baseline_deviation_score": 0.0}
  ]
}
```

Create `verdict-engine/revalidation_fixtures/compromised_combined.json`:

```json
{
  "expected_verdict": "Compromised",
  "events": [
    {"event_id": "e1", "device_id": "shadow-node", "event_type": "process_spawn", "process_ref": {"pid": 200, "name": "touch", "parent_pid": 1}, "timestamp": "2026-09-11T00:00:00Z", "baseline_deviation_score": 0.0},
    {"event_id": "e2", "device_id": "shadow-node", "event_type": "file_write", "file_ref": {"path": "/etc/mirraura-fixture-marker", "action": "write"}, "timestamp": "2026-09-11T00:00:01Z", "baseline_deviation_score": 0.0},
    {"event_id": "e3", "device_id": "shadow-node", "event_type": "network_connect", "network_ref": {"dst_ip": "127.0.0.1", "dst_port": 9999, "protocol": "tcp"}, "timestamp": "2026-09-11T00:00:02Z", "baseline_deviation_score": 0.0}
  ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd verdict-engine && python -m pytest tests/test_revalidation_fixtures.py -v`
Expected: all PASS. (`rapid_file_changes.json` verifies at confidence 0.25 from 6 file-change events past the `RAPID_FILE_CHANGE_THRESHOLD` of 5; `compromised_combined.json` verifies at confidence 0.75 = 0.3 + 0.25 + 0.2, past the 0.6 `Compromised` threshold.)

- [ ] **Step 5: Commit**

```bash
git add verdict-engine/revalidation_fixtures/ verdict-engine/tests/test_revalidation_fixtures.py
git commit -m "feat: add hand-labeled fixture corpus for re-validation"
```

---

### Task 3: Report logic (`revalidation_report.py`)

**Files:**
- Create: `verdict-engine/revalidation_report.py`
- Create: `verdict-engine/tests/test_revalidation_report.py`

**Interfaces:**
- Consumes: nothing from other tasks (pure logic, tested entirely in-memory).
- Produces (for Task 4): `load_candidate(path: Path) -> module` (raises `ImportError` if the file can't be loaded, `AttributeError` if it's missing `score_events`/`verdict_from_score`), `score_with(module, events: List[Event]) -> (verdict: str, confidence: float, chain: List[str])`, `run_fixtures(fixtures: List[dict], current_module, candidate_module) -> List[dict]`, `run_archive(archive_entries: List[dict], candidate_module) -> List[dict]`, `build_report(fixture_results, archive_results, archive_skipped_reason=None) -> dict`, `format_table(report: dict) -> str`.

- [ ] **Step 1: Write the failing tests**

Create `verdict-engine/tests/test_revalidation_report.py`:

```python
from schemas import Event

from revalidation_report import build_report, format_table, load_candidate, run_archive, run_fixtures


class _StubScorer:
    """Stands in for a real candidate module without needing a file on disk."""

    def __init__(self, confidence, chain):
        self.confidence = confidence
        self.chain = chain

    def score_events(self, events):
        return self.confidence, self.chain

    def verdict_from_score(self, confidence, chain, had_telemetry):
        if not had_telemetry:
            return "Inconclusive"
        if confidence == 0.0:
            return "Normal"
        if confidence < 0.6:
            return "Suspicious"
        return "Compromised"


def _event_dict():
    return Event(
        event_id="e1",
        device_id="shadow-node",
        event_type="process_spawn",
        timestamp="2026-09-11T00:00:00Z",
        process_ref={"pid": 1, "name": "sh", "parent_pid": 0},
    ).model_dump()


def test_run_fixtures_reports_before_after_correctness():
    fixtures = [{"name": "f1", "expected_verdict": "Suspicious", "events": [_event_dict()]}]
    current = _StubScorer(0.3, ["x"])
    candidate = _StubScorer(0.7, ["x", "y"])

    results = run_fixtures(fixtures, current, candidate)

    assert results[0]["before_verdict"] == "Suspicious"
    assert results[0]["before_correct"] is True
    assert results[0]["after_verdict"] == "Compromised"
    assert results[0]["after_correct"] is False


def test_run_archive_detects_flip():
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [_event_dict()],
            "verdict_at_capture": "Suspicious",
        }
    ]
    results = run_archive(entries, _StubScorer(0.9, ["x"]))

    assert results[0]["before_verdict"] == "Suspicious"
    assert results[0]["after_verdict"] == "Compromised"
    assert results[0]["flipped"] is True


def test_run_archive_no_flip():
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [],
            "verdict_at_capture": "Inconclusive",
        }
    ]
    results = run_archive(entries, _StubScorer(0.0, []))

    assert results[0]["flipped"] is False


def test_build_report_computes_accuracy():
    fixture_results = [
        {
            "name": "f1", "expected_verdict": "Normal", "before_verdict": "Normal",
            "before_confidence": 0.0, "before_correct": True,
            "after_verdict": "Normal", "after_confidence": 0.0, "after_correct": True,
        },
        {
            "name": "f2", "expected_verdict": "Compromised", "before_verdict": "Suspicious",
            "before_confidence": 0.4, "before_correct": False,
            "after_verdict": "Compromised", "after_confidence": 0.7, "after_correct": True,
        },
    ]
    report = build_report(fixture_results, [])

    assert report["fixtures"]["before_accuracy"] == 0.5
    assert report["fixtures"]["after_accuracy"] == 1.0


def test_build_report_archive_skipped_reason_is_preserved():
    report = build_report([], [], archive_skipped_reason="archive not found")
    assert report["archive"]["skipped_reason"] == "archive not found"


def test_format_table_includes_accuracy_and_flip_lines():
    fixture_results = [
        {
            "name": "f1", "expected_verdict": "Normal", "before_verdict": "Normal",
            "before_confidence": 0.0, "before_correct": True,
            "after_verdict": "Normal", "after_confidence": 0.0, "after_correct": True,
        },
    ]
    archive_results = [
        {
            "verdict_id": "v1", "sample_hash": "a" * 64, "source": "sample",
            "before_verdict": "Suspicious", "after_verdict": "Compromised",
            "after_confidence": 0.7, "flipped": True,
        },
    ]
    table = format_table(build_report(fixture_results, archive_results))

    assert "Fixture Corpus" in table
    assert "Archived Captures" in table
    assert "Suspicious -> Compromised" in table


def test_load_candidate_missing_functions_raises(tmp_path):
    bad = tmp_path / "bad_candidate.py"
    bad.write_text("x = 1\n")
    try:
        load_candidate(bad)
        assert False, "expected AttributeError"
    except AttributeError:
        pass


def test_load_candidate_loads_real_module(tmp_path):
    good = tmp_path / "good_candidate.py"
    good.write_text(
        "def score_events(events):\n"
        "    return 0.0, []\n"
        "def verdict_from_score(confidence, chain, had_telemetry):\n"
        "    return 'Normal'\n"
    )
    module = load_candidate(good)
    assert module.score_events([]) == (0.0, [])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_revalidation_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'revalidation_report'`.

- [ ] **Step 3: Implement the report logic**

Create `verdict-engine/revalidation_report.py`:

```python
import importlib.util
from pathlib import Path
from typing import List, Optional, Tuple

from schemas import Event


def load_candidate(path: Path):
    spec = importlib.util.spec_from_file_location("revalidation_candidate", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load candidate module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "score_events") or not hasattr(module, "verdict_from_score"):
        raise AttributeError(
            f"candidate module {path} must define score_events and verdict_from_score"
        )
    return module


def score_with(module, events: List[Event]) -> Tuple[str, float, List[str]]:
    confidence, chain = module.score_events(events)
    verdict = module.verdict_from_score(confidence, chain, had_telemetry=len(events) > 0)
    return verdict, confidence, chain


def run_fixtures(fixtures: List[dict], current_module, candidate_module) -> List[dict]:
    results = []
    for fx in fixtures:
        events = [Event(**e) for e in fx["events"]]
        before_verdict, before_conf, _ = score_with(current_module, events)
        after_verdict, after_conf, _ = score_with(candidate_module, events)
        results.append(
            {
                "name": fx["name"],
                "expected_verdict": fx["expected_verdict"],
                "before_verdict": before_verdict,
                "before_confidence": before_conf,
                "before_correct": before_verdict == fx["expected_verdict"],
                "after_verdict": after_verdict,
                "after_confidence": after_conf,
                "after_correct": after_verdict == fx["expected_verdict"],
            }
        )
    return results


def run_archive(archive_entries: List[dict], candidate_module) -> List[dict]:
    results = []
    for entry in archive_entries:
        events = [Event(**e) for e in entry["events"]]
        after_verdict, after_conf, _ = score_with(candidate_module, events)
        before_verdict = entry["verdict_at_capture"]
        results.append(
            {
                "verdict_id": entry["verdict_id"],
                "sample_hash": entry["sample_hash"],
                "source": entry["source"],
                "before_verdict": before_verdict,
                "after_verdict": after_verdict,
                "after_confidence": after_conf,
                "flipped": after_verdict != before_verdict,
            }
        )
    return results


def build_report(
    fixture_results: List[dict],
    archive_results: List[dict],
    archive_skipped_reason: Optional[str] = None,
) -> dict:
    fixture_total = len(fixture_results)
    before_correct = sum(1 for r in fixture_results if r["before_correct"])
    after_correct = sum(1 for r in fixture_results if r["after_correct"])
    flips = [r for r in archive_results if r["flipped"]]
    return {
        "fixtures": {
            "total": fixture_total,
            "before_accuracy": before_correct / fixture_total if fixture_total else 0.0,
            "after_accuracy": after_correct / fixture_total if fixture_total else 0.0,
            "results": fixture_results,
        },
        "archive": {
            "skipped_reason": archive_skipped_reason,
            "total": len(archive_results),
            "flipped_count": len(flips),
            "results": archive_results,
        },
    }


def format_table(report: dict) -> str:
    lines = []
    fx = report["fixtures"]
    lines.append("=== Fixture Corpus (ground-truth accuracy) ===")
    lines.append(
        f"Before: {fx['before_accuracy']:.0%}   After: {fx['after_accuracy']:.0%}   "
        f"({fx['total']} fixtures)"
    )
    for r in fx["results"]:
        before_mark = "PASS" if r["before_correct"] else "FAIL"
        after_mark = "PASS" if r["after_correct"] else "FAIL"
        lines.append(
            f"  {r['name']:<28} expected={r['expected_verdict']:<12} "
            f"before={r['before_verdict']:<12}[{before_mark}] "
            f"after={r['after_verdict']:<12}[{after_mark}]"
        )
    lines.append("")
    ar = report["archive"]
    lines.append("=== Archived Captures (verdict drift) ===")
    if ar["skipped_reason"]:
        lines.append(f"  skipped: {ar['skipped_reason']}")
    else:
        lines.append(f"{ar['flipped_count']} / {ar['total']} verdicts changed")
        for r in ar["results"]:
            if r["flipped"]:
                lines.append(
                    f"  {r['verdict_id'][:8]}  {r['source']:<8} "
                    f"{r['before_verdict']} -> {r['after_verdict']}"
                )
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/test_revalidation_report.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add verdict-engine/revalidation_report.py verdict-engine/tests/test_revalidation_report.py
git commit -m "feat: add re-validation scoring/diff/report logic"
```

---

### Task 4: CLI entrypoint, Docker wiring, docs, manual verification

**Files:**
- Create: `verdict-engine/revalidate.py`
- Create: `verdict-engine/tests/test_revalidate.py`
- Create: `verdict-engine/revalidation_candidates/.gitkeep`
- Create: `verdict-engine/revalidation_reports/.gitkeep`
- Modify: `.gitignore`
- Modify: `docker-compose.yml`
- Modify: `docs/concepts.md`

**Interfaces:**
- Consumes (from Task 1): `EventArchive`. (from Task 3): `load_candidate`, `run_fixtures`, `run_archive`, `build_report`, `format_table`.
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Write the failing tests**

Create `verdict-engine/tests/test_revalidate.py`:

```python
import json

from revalidate import main


def _write_fixture(fixtures_dir, name, expected_verdict, events):
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    (fixtures_dir / f"{name}.json").write_text(
        json.dumps({"expected_verdict": expected_verdict, "events": events})
    )


def _write_candidate(path):
    path.write_text(
        "def score_events(events):\n"
        "    return 0.0, []\n"
        "def verdict_from_score(confidence, chain, had_telemetry):\n"
        "    return 'Normal' if had_telemetry else 'Inconclusive'\n"
    )


def test_main_runs_fixtures_only_when_archive_missing(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    _write_fixture(fixtures_dir, "normal", "Normal", [])

    candidate = tmp_path / "candidate.py"
    _write_candidate(candidate)

    report_dir = tmp_path / "reports"
    missing_archive = tmp_path / "no_such_archive.jsonl"

    exit_code = main(
        [
            "--candidate", str(candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(report_dir),
            "--archive-path", str(missing_archive),
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Fixture Corpus" in out
    assert "skipped:" in out

    written = list(report_dir.glob("*.json"))
    assert len(written) == 1
    report = json.loads(written[0].read_text())
    assert report["fixtures"]["total"] == 1


def test_main_returns_1_on_bad_candidate(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    _write_fixture(fixtures_dir, "normal", "Normal", [])
    bad_candidate = tmp_path / "bad.py"
    bad_candidate.write_text("x = 1\n")

    exit_code = main(
        [
            "--candidate", str(bad_candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(tmp_path / "reports"),
        ]
    )

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "error loading candidate" in err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_revalidate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'revalidate'`.

- [ ] **Step 3: Implement the CLI**

Create `verdict-engine/revalidate.py`:

```python
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

import rule_scorer as current_scorer
from event_archive import EventArchive
from revalidation_report import build_report, format_table, load_candidate, run_archive, run_fixtures


def load_fixtures(fixtures_dir: Path) -> List[dict]:
    fixtures = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = json.loads(path.read_text())
        data["name"] = path.stem
        fixtures.append(data)
    return fixtures


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay archived event captures against a candidate rule scorer."
    )
    parser.add_argument(
        "--candidate", required=True, type=Path, help="path to a candidate scorer .py file"
    )
    parser.add_argument(
        "--archive-path",
        type=Path,
        default=Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")),
    )
    parser.add_argument(
        "--fixtures-dir", type=Path, default=Path(__file__).parent / "revalidation_fixtures"
    )
    parser.add_argument(
        "--report-dir", type=Path, default=Path(__file__).parent / "revalidation_reports"
    )
    args = parser.parse_args(argv)

    try:
        candidate_module = load_candidate(args.candidate)
    except (ImportError, AttributeError) as e:
        print(f"error loading candidate: {e}", file=sys.stderr)
        return 1

    fixtures = load_fixtures(args.fixtures_dir)
    fixture_results = run_fixtures(fixtures, current_scorer, candidate_module)

    archive_skipped_reason = None
    archive_results: List[dict] = []
    if args.archive_path.exists():
        archive = EventArchive(args.archive_path)
        archive_results = run_archive(archive.all(), candidate_module)
    else:
        archive_skipped_reason = f"archive not found at {args.archive_path}"

    report = build_report(fixture_results, archive_results, archive_skipped_reason)
    print(format_table(report))

    args.report_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.report_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nFull report written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/ -v`
Expected: all PASS, including the full pre-existing suite from Tasks 1-3.

- [ ] **Step 5: Scratch dirs, gitignore, Docker wiring**

Create `verdict-engine/revalidation_candidates/.gitkeep` (empty file).
Create `verdict-engine/revalidation_reports/.gitkeep` (empty file).

Add to `.gitignore`:

```
verdict-engine/revalidation_candidates/*.py
!verdict-engine/revalidation_candidates/.gitkeep
verdict-engine/revalidation_reports/*.json
!verdict-engine/revalidation_reports/.gitkeep
```

In `docker-compose.yml`, change the `verdict-engine` service from:

```yaml
  verdict-engine:
    build: ./verdict-engine
    ports:
      - "${VERDICT_ENGINE_PORT:-8000}:8000"
    environment:
      - AUDIT_LOG_PATH=/data/audit_log.jsonl
      - KNOWN_BAD_HASHES_PATH=/data/known_bad_hashes.json
    volumes:
      - audit-log-data:/data
```

to:

```yaml
  verdict-engine:
    build: ./verdict-engine
    ports:
      - "${VERDICT_ENGINE_PORT:-8000}:8000"
    environment:
      - AUDIT_LOG_PATH=/data/audit_log.jsonl
      - KNOWN_BAD_HASHES_PATH=/data/known_bad_hashes.json
      - EVENT_ARCHIVE_PATH=/data/event_archive.jsonl
    volumes:
      - audit-log-data:/data
      - ./verdict-engine/revalidation_candidates:/app/revalidation_candidates
      - ./verdict-engine/revalidation_reports:/app/revalidation_reports
```

- [ ] **Step 6: Update the tech notes**

In `docs/concepts.md`, replace the existing bullet:

```markdown
**Re-validation loop** (phase 2) — After updating the scorer/model, you replay old recorded runs through it and check whether it now catches things it used to miss. That before/after comparison ("X% of previously-missed samples now detected") is a concrete, demoable improvement metric.
```

with:

```markdown
**Re-validation loop** — After updating the scorer/model, you replay old recorded runs through it and check whether it now catches things it used to miss. That before/after comparison ("X% of previously-missed samples now detected") is a concrete, demoable improvement metric.
*In Mirraura:* two corpora feed the replay. A small hand-authored fixture corpus (`verdict-engine/revalidation_fixtures/`) carries a real, known-correct label per case — one isolating each rule-scorer branch — so `revalidate.py` can report an honest before/after accuracy percentage. Real captures (every sample upload or continuous-monitoring tick, going forward) are archived separately in `verdict-engine/event_archive.py`, labeled only with the verdict the engine actually produced at capture time — never a fabricated ground truth — so those are reported as verdict *drift* under a candidate scorer, not accuracy. `revalidate.py --candidate <path.py>` dynamically loads any Python file exposing `score_events`/`verdict_from_score` and runs both corpora against it; nothing is promoted to production automatically — a human reads the report and decides whether to fold the change into `rule_scorer.py`.
```

- [ ] **Step 7: Manual end-to-end verification**

Bring the stack up and confirm the whole loop works against real, live-produced data:

1. `docker compose up --build`
2. Upload any sample through the dashboard (or `POST /api/samples` with a `sample` file field) and confirm `/score` still returns normally.
3. `docker compose exec verdict-engine cat /data/event_archive.jsonl` — confirm a new line appeared with the just-uploaded sample's `verdict_id` and its raw `events`.
4. Write a trivial candidate scorer that behaves differently from `rule_scorer.py` — e.g. `verdict-engine/revalidation_candidates/always_compromised.py`:
   ```python
   def score_events(events):
       return 1.0, ["always-compromised candidate for testing"]

   def verdict_from_score(confidence, chain, had_telemetry):
       return "Compromised" if had_telemetry else "Inconclusive"
   ```
5. `docker compose exec verdict-engine python revalidate.py --candidate revalidation_candidates/always_compromised.py`
6. Confirm the printed table shows the fixture corpus's `after_verdict` column reading `Compromised` for every telemetry-bearing fixture (accuracy should drop for the `Normal`/`Suspicious`-expected ones — this candidate is deliberately bad), and the archive section reports the just-uploaded sample flipped to `Compromised` if it wasn't already.
7. Confirm `revalidation_reports/` on the host (bind-mounted) now contains the matching timestamped JSON report.

- [ ] **Step 8: Commit**

```bash
git add verdict-engine/revalidate.py verdict-engine/tests/test_revalidate.py verdict-engine/revalidation_candidates/.gitkeep verdict-engine/revalidation_reports/.gitkeep .gitignore docker-compose.yml docs/concepts.md
git commit -m "feat: add revalidate.py CLI and wire it into the Docker stack"
```
