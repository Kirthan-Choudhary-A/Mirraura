# Human-Approval Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** New known-bad hash entries (auto-proposed from a Compromised behavioral verdict, or submitted manually) sit in a `pending` state and have zero effect on `/score` until a human approves them in the dashboard.

**Architecture:** Extend the verdict-engine's existing `known_bad_hashes.json` with a `status` field (no new database — flat file, guarded by an in-process `threading.Lock()`), add propose/approve/reject endpoints, have `/score` auto-propose on a behavioral `Compromised` verdict, proxy those endpoints through the Go backend the same way `/api/verdicts` is already proxied, and add a dashboard panel to review and decide.

**Tech Stack:** Python (FastAPI, verdict-engine), Go (backend proxy), TypeScript + React (frontend) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-09-human-approval-gate-design.md`

## Global Constraints

- Storage: `verdict-engine/known_bad_hashes.json`, extended in place — no new file, no new service, no database.
- Concurrency: a single module-level `threading.Lock()` in `hash_lookup.py` guards every read-modify-write to the hash file.
- `check_hash()` matches only `status == "approved"` entries — this is the entire enforcement mechanism for "pending has zero effect."
- Auto-propose trigger: `/score` returns `Compromised` via behavioral rules (not a hash match) AND `sample_hash` not already present under any status.
- No response-shape change to `Verdict` — auto-propose is a side effect, never part of `/score`'s response payload.
- No new WebSocket message type — the frontend refetches on the existing `verdict` message via the existing `refreshKey` mechanism.
- No authentication/approver-identity tracking.
- Behavioral rule weights (`RULE_WEIGHTS`, `RAPID_FILE_CHANGE_THRESHOLD`) are explicitly out of scope.
- Hash format validation on submission: exactly 64 lowercase hex characters.
- `POST /hashes` → `409` if hash already exists under any status; `400` if malformed.
- `POST /hashes/{hash}/approve|reject` → `404` unknown hash, `409` if not currently pending.

---

### Task 1: Hash store layer (`hash_lookup.py`)

**Files:**
- Modify: `verdict-engine/hash_lookup.py`
- Modify: `verdict-engine/known_bad_hashes.json`
- Modify: `verdict-engine/tests/conftest.py`
- Modify: `verdict-engine/tests/test_hash_lookup.py`

**Interfaces:**
- Consumes: nothing from other tasks (base layer).
- Produces (for Task 2): `check_hash(sample_hash, known_bad=None) -> Optional[str]` (unchanged signature, now approved-only), `list_hashes() -> List[dict]`, `propose_hash(sample_hash: str, label: str, source: str) -> dict`, `approve_hash(sample_hash: str) -> dict`, `reject_hash(sample_hash: str) -> dict`, `is_valid_hash(value: str) -> bool`, and exceptions `HashExistsError`, `HashNotFoundError`, `HashNotPendingError` (all subclass `Exception`, all take the hash string as their single arg). Each entry dict shape: `{"hash": str, "label": str, "status": "pending"|"approved"|"rejected", "source": "auto"|"manual", "proposed_at": str, "reviewed_at": str | None}`.

- [ ] **Step 1: Migrate the seed data file**

Replace the entire contents of `verdict-engine/known_bad_hashes.json`:

```json
[
  {
    "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "label": "EICAR-Test-File",
    "status": "approved",
    "source": "manual",
    "proposed_at": "2026-09-07T00:00:00+00:00",
    "reviewed_at": "2026-09-07T00:00:00+00:00"
  }
]
```

- [ ] **Step 2: Write the failing tests**

Replace the entire contents of `verdict-engine/tests/test_hash_lookup.py`:

```python
import hashlib
import json
import threading

import hash_lookup
from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    propose_hash,
    reject_hash,
)

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_known_bad_hash_returns_label():
    assert check_hash(EICAR_HASH) == "EICAR-Test-File"


def test_unknown_hash_returns_none():
    assert check_hash("0" * 64) is None


def test_eicar_hash_constant_matches_real_bytes():
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert hashlib.sha256(eicar_bytes).hexdigest() == EICAR_HASH


def _seed(tmp_path, monkeypatch, entries):
    path = tmp_path / "known_bad_hashes.json"
    path.write_text(json.dumps(entries))
    monkeypatch.setattr(hash_lookup, "KNOWN_BAD_PATH", path)
    return path


def test_is_valid_hash():
    assert is_valid_hash("a" * 64) is True
    assert is_valid_hash("A" * 64) is False
    assert is_valid_hash("a" * 63) is False
    assert is_valid_hash("z" * 64) is False


def test_pending_hash_is_invisible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    assert check_hash("a" * 64) is None


def test_propose_hash_creates_pending_entry(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    entry = propose_hash("a" * 64, "test-label", source="manual")
    assert entry["status"] == "pending"
    assert entry["source"] == "manual"
    assert entry["reviewed_at"] is None


def test_propose_hash_duplicate_raises(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "first", source="manual")
    try:
        propose_hash("a" * 64, "second", source="auto")
        assert False, "expected HashExistsError"
    except HashExistsError:
        pass


def test_approve_hash_makes_it_visible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    entry = approve_hash("a" * 64)
    assert entry["status"] == "approved"
    assert entry["reviewed_at"] is not None
    assert check_hash("a" * 64) == "test-label"


def test_reject_hash_never_visible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    entry = reject_hash("a" * 64)
    assert entry["status"] == "rejected"
    assert check_hash("a" * 64) is None


def test_approve_unknown_hash_raises_not_found(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    try:
        approve_hash("a" * 64)
        assert False, "expected HashNotFoundError"
    except HashNotFoundError:
        pass


def test_approve_already_decided_hash_raises_not_pending(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    approve_hash("a" * 64)
    try:
        approve_hash("a" * 64)
        assert False, "expected HashNotPendingError"
    except HashNotPendingError:
        pass


def test_list_hashes_returns_all_statuses(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "one", source="manual")
    propose_hash("b" * 64, "two", source="auto")
    approve_hash("a" * 64)
    entries = list_hashes()
    assert {e["hash"]: e["status"] for e in entries} == {"a" * 64: "approved", "b" * 64: "pending"}


def test_concurrent_propose_does_not_corrupt_file(tmp_path, monkeypatch):
    path = _seed(tmp_path, monkeypatch, [])
    hashes = [f"{i:064d}" for i in range(20)]

    def worker(h):
        propose_hash(h, "concurrent", source="manual")

    threads = [threading.Thread(target=worker, args=(h,)) for h in hashes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = json.loads(path.read_text())
    assert len(entries) == 20
    assert {e["hash"] for e in entries} == set(hashes)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_hash_lookup.py -v`
Expected: FAIL — `ImportError` or `AttributeError` for the not-yet-defined names (`propose_hash`, `approve_hash`, `reject_hash`, `is_valid_hash`, `list_hashes`, the exception classes, `hash_lookup.KNOWN_BAD_PATH` not existing under that exact name if it's still hardcoded).

- [ ] **Step 4: Implement the store layer**

Replace the entire contents of `verdict-engine/hash_lookup.py`:

```python
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

KNOWN_BAD_PATH = Path(
    os.getenv("KNOWN_BAD_HASHES_PATH", str(Path(__file__).parent / "known_bad_hashes.json"))
)

# ponytail: a single process-wide lock, not per-file — Mirraura runs the
# verdict-engine as one process with no multi-worker setup, so this is
# sufficient. Move to file locking (e.g. fcntl) only if that assumption
# changes.
_LOCK = threading.Lock()

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class HashExistsError(Exception):
    pass


class HashNotFoundError(Exception):
    pass


class HashNotPendingError(Exception):
    pass


def is_valid_hash(value: str) -> bool:
    return bool(_HASH_RE.fullmatch(value))


def _load_all() -> List[dict]:
    with open(KNOWN_BAD_PATH) as f:
        return json.load(f)


def _save_all(entries: List[dict]) -> None:
    with open(KNOWN_BAD_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def load_known_bad() -> Dict[str, str]:
    return {e["hash"]: e["label"] for e in _load_all() if e.get("status") == "approved"}


def check_hash(sample_hash: str, known_bad: Optional[Dict[str, str]] = None) -> Optional[str]:
    known_bad = known_bad if known_bad is not None else load_known_bad()
    return known_bad.get(sample_hash)


def list_hashes() -> List[dict]:
    with _LOCK:
        return _load_all()


def propose_hash(sample_hash: str, label: str, source: str) -> dict:
    with _LOCK:
        entries = _load_all()
        if any(e["hash"] == sample_hash for e in entries):
            raise HashExistsError(sample_hash)
        entry = {
            "hash": sample_hash,
            "label": label,
            "status": "pending",
            "source": source,
            "proposed_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_at": None,
        }
        entries.append(entry)
        _save_all(entries)
        return entry


def _decide(sample_hash: str, new_status: str) -> dict:
    with _LOCK:
        entries = _load_all()
        for e in entries:
            if e["hash"] == sample_hash:
                if e["status"] != "pending":
                    raise HashNotPendingError(sample_hash)
                e["status"] = new_status
                e["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                _save_all(entries)
                return e
        raise HashNotFoundError(sample_hash)


def approve_hash(sample_hash: str) -> dict:
    return _decide(sample_hash, "approved")


def reject_hash(sample_hash: str) -> dict:
    return _decide(sample_hash, "rejected")
```

- [ ] **Step 5: Point tests at a throwaway copy of the seed file**

Replace the entire contents of `verdict-engine/tests/conftest.py`:

```python
import os
import shutil
from pathlib import Path

# Point the verdict-engine's audit log and known-bad hash store at throwaway
# files for the whole test session, before app.py (or hash_lookup.py) is
# imported by any test module — otherwise they fall back to the hardcoded
# production paths and read/write real state.
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)

_TEST_KNOWN_BAD = Path(__file__).parent / "test_known_bad_hashes.json"
_SEED_KNOWN_BAD = Path(__file__).parent.parent / "known_bad_hashes.json"
shutil.copy(_SEED_KNOWN_BAD, _TEST_KNOWN_BAD)
os.environ["KNOWN_BAD_HASHES_PATH"] = str(_TEST_KNOWN_BAD)


def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
    _TEST_KNOWN_BAD.unlink(missing_ok=True)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/test_hash_lookup.py -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add verdict-engine/hash_lookup.py verdict-engine/known_bad_hashes.json verdict-engine/tests/conftest.py verdict-engine/tests/test_hash_lookup.py
git commit -m "feat: add pending/approved/rejected status to known-bad hash store"
```

---

### Task 2: Wire the verdict-engine (`app.py`)

**Files:**
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes (from Task 1): `check_hash`, `list_hashes`, `propose_hash`, `approve_hash`, `reject_hash`, `is_valid_hash`, `HashExistsError`, `HashNotFoundError`, `HashNotPendingError`.
- Produces (for Task 3): three routes — `GET /hashes` (200, JSON array of entry dicts), `POST /hashes` (body `{"hash": str, "label": str}`, 200 + entry dict on success, 400 on bad hash format, 409 on duplicate), `POST /hashes/{hash}/approve` and `POST /hashes/{hash}/reject` (200 + entry dict, 404 unknown hash, 409 not pending).

- [ ] **Step 1: Write the failing tests**

Add to the end of `verdict-engine/tests/test_app.py`:

```python
def _compromised_events():
    return [
        {
            "event_id": "e1",
            "device_id": "shadow-node",
            "event_type": "process_spawn",
            "process_ref": {"pid": 100, "name": "sh", "parent_pid": 1},
            "timestamp": "2026-09-09T00:00:00Z",
            "baseline_deviation_score": 0.0,
        },
        {
            "event_id": "e2",
            "device_id": "shadow-node",
            "event_type": "file_write",
            "file_ref": {"path": "/etc/passwd", "action": "write"},
            "timestamp": "2026-09-09T00:00:01Z",
            "baseline_deviation_score": 0.0,
        },
        {
            "event_id": "e3",
            "device_id": "shadow-node",
            "event_type": "network_connect",
            "network_ref": {"dst_ip": "127.0.0.1", "dst_port": 31337, "protocol": "tcp"},
            "timestamp": "2026-09-09T00:00:02Z",
            "baseline_deviation_score": 0.0,
        },
    ]


def test_behavioral_compromised_auto_proposes_pending_hash():
    sample_hash = "c" * 64
    resp = client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})
    assert resp.json()["verdict"] == "Compromised"

    hashes = client.get("/hashes").json()
    matches = [h for h in hashes if h["hash"] == sample_hash]
    assert len(matches) == 1
    assert matches[0]["status"] == "pending"
    assert matches[0]["source"] == "auto"


def test_repeated_compromised_verdict_does_not_duplicate_proposal():
    sample_hash = "d" * 64
    client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})
    client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})

    hashes = client.get("/hashes").json()
    matches = [h for h in hashes if h["hash"] == sample_hash]
    assert len(matches) == 1


def test_manual_hash_submission_then_approve_flow():
    sample_hash = "1" * 64
    resp = client.post("/hashes", json={"hash": sample_hash, "label": "manual-test"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    # not yet approved: does not affect /score
    score_resp = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp.json()["verdict"] == "Inconclusive"

    approve_resp = client.post(f"/hashes/{sample_hash}/approve")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    score_resp2 = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp2.json()["verdict"] == "Compromised"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "hash_approved" and r.get("hash") == sample_hash for r in listed
    )


def test_manual_hash_submission_reject_flow():
    sample_hash = "2" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "reject-test"})
    reject_resp = client.post(f"/hashes/{sample_hash}/reject")
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "rejected"

    score_resp = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp.json()["verdict"] == "Inconclusive"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "hash_rejected" and r.get("hash") == sample_hash for r in listed
    )


def test_submit_invalid_hash_format_rejected():
    resp = client.post("/hashes", json={"hash": "not-a-hash", "label": "bad"})
    assert resp.status_code == 400


def test_submit_duplicate_hash_conflicts():
    sample_hash = "3" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "first"})
    resp = client.post("/hashes", json={"hash": sample_hash, "label": "second"})
    assert resp.status_code == 409


def test_approve_unknown_hash_returns_404():
    resp = client.post(f"/hashes/{'4' * 64}/approve")
    assert resp.status_code == 404


def test_approve_already_decided_hash_returns_409():
    sample_hash = "5" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "x"})
    client.post(f"/hashes/{sample_hash}/approve")
    resp = client.post(f"/hashes/{sample_hash}/approve")
    assert resp.status_code == 409
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_app.py -v`
Expected: FAIL — `404 Not Found` for the not-yet-defined `/hashes*` routes, and the auto-propose tests fail because no pending entry is ever created.

- [ ] **Step 3: Implement the routes and auto-propose**

In `verdict-engine/app.py`, change the imports at the top from:

```python
from hash_lookup import check_hash
```

to:

```python
import logging

from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    propose_hash,
    reject_hash,
)
```

Add `from fastapi import FastAPI, HTTPException` is already imported — no change needed there. Add this line right after the existing `app = FastAPI()` / `audit_log = AuditLog(...)` lines:

```python
logger = logging.getLogger(__name__)
```

Add this new request model next to the existing `ScoreRequest`/`ActionRequest` classes:

```python
class HashSubmitRequest(BaseModel):
    hash: str
    label: str
```

Replace the entire `score` function with:

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
    else:
        confidence, chain = score_events(req.events)
        verdict = verdict_from_score(confidence, chain, had_telemetry=len(req.events) > 0)
        if verdict == "Compromised":
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

    record = {
        "verdict_id": verdict_id,
        "sample_hash": req.sample_hash,
        "verdict": verdict,
        "confidence": confidence,
        "causal_chain": chain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    stored = audit_log.append(record)
    return Verdict(**_strip_entry_hash(stored))
```

Add these four new routes at the end of the file, after the existing `log_action` route:

```python
@app.get("/hashes")
def list_hashes_route():
    return list_hashes()


@app.post("/hashes")
def submit_hash_route(req: HashSubmitRequest):
    if not is_valid_hash(req.hash):
        raise HTTPException(status_code=400, detail="hash must be 64 lowercase hex characters")
    try:
        return propose_hash(req.hash, req.label, source="manual")
    except HashExistsError:
        raise HTTPException(status_code=409, detail="hash already exists")


@app.post("/hashes/{hash}/approve")
def approve_hash_route(hash: str):
    try:
        entry = approve_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_approved",
            "hash": entry["hash"],
            "label": entry["label"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry


@app.post("/hashes/{hash}/reject")
def reject_hash_route(hash: str):
    try:
        entry = reject_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_rejected",
            "hash": entry["hash"],
            "label": entry["label"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/ -v`
Expected: all PASS, including the full pre-existing suite (`test_hash_lookup.py`, `test_app.py`, `test_audit_log.py`, `test_rule_scorer.py` if present).

- [ ] **Step 5: Commit**

```bash
git add verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "feat: add hash approval routes and auto-propose on Compromised verdicts"
```

---

### Task 3: Go backend proxy routes

**Files:**
- Create: `backend/hashes.go`
- Create: `backend/hashes_test.go`
- Modify: `backend/main.go`

**Interfaces:**
- Consumes: the verdict-engine HTTP contract from Task 2 (`GET /hashes`, `POST /hashes`, `POST /hashes/{hash}/approve`, `POST /hashes/{hash}/reject`) and the package-level `httpClient` already declared in `backend/samples.go`.
- Produces (for Task 4): Go backend routes `GET/POST /api/hashes`, `POST /api/hashes/{hash}/approve`, `POST /api/hashes/{hash}/reject` — thin proxies, pass through status code and JSON body verbatim.

- [ ] **Step 1: Write the failing tests**

Create `backend/hashes_test.go`:

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHashesHandlerProxiesGet(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"hash":"a","status":"pending"}]`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/hashes", nil)
	rec := httptest.NewRecorder()
	hashesHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"hash":"a"`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestHashesHandlerProxiesPost(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"detail":"hash already exists"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/hashes", strings.NewReader(`{"hash":"a","label":"b"}`))
	rec := httptest.NewRecorder()
	hashesHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestHashesHandlerRejectsOtherMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/hashes", nil)
	rec := httptest.NewRecorder()
	hashesHandler("http://unused")(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHashDecisionHandlerProxiesApprove(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes/abc123/approve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hash":"abc123","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/hashes/abc123/approve", nil)
	rec := httptest.NewRecorder()
	hashDecisionHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestHashDecisionHandlerRejectsBadPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/hashes/abc123/frobnicate", nil)
	rec := httptest.NewRecorder()
	hashDecisionHandler("http://unused")(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && go test ./... -run TestHashes -v`
Expected: FAIL — `hashesHandler`/`hashDecisionHandler` undefined.

- [ ] **Step 3: Implement the proxy handlers**

Create `backend/hashes.go`:

```go
package main

import (
	"io"
	"net/http"
	"strings"
)

func hashesHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var resp *http.Response
		var err error
		switch r.Method {
		case http.MethodGet:
			resp, err = http.Get(verdictEngineURL + "/hashes")
		case http.MethodPost:
			resp, err = httpClient.Post(verdictEngineURL+"/hashes", "application/json", r.Body)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func hashDecisionHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/hashes/")
		parts := strings.Split(path, "/")
		if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		hash, decision := parts[0], parts[1]
		resp, err := httpClient.Post(verdictEngineURL+"/hashes/"+hash+"/"+decision, "application/json", nil)
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}
```

In `backend/main.go`, add these two lines right after the existing `mux.HandleFunc("/api/monitor/reconnect", monitorReconnectHandler(mon))` line:

```go
	mux.HandleFunc("/api/hashes", hashesHandler(verdictEngineURL))
	mux.HandleFunc("/api/hashes/", hashDecisionHandler(verdictEngineURL))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go build ./... && go test ./... -v`
Expected: all PASS, including the full pre-existing suite.

- [ ] **Step 5: Commit**

```bash
git add backend/hashes.go backend/hashes_test.go backend/main.go
git commit -m "feat: proxy hash approval endpoints through the Go backend"
```

---

### Task 4: Frontend panel and audit log rendering

**Files:**
- Modify: `frontend/src/api.ts`
- Create: `frontend/src/components/PendingHashApprovals.tsx`
- Modify: `frontend/src/components/AuditLogTable.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `docs/concepts.md`

**Interfaces:**
- Consumes (from Task 3): `GET/POST /api/hashes`, `POST /api/hashes/{hash}/approve`, `POST /api/hashes/{hash}/reject`.
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Add API client functions**

In `frontend/src/api.ts`, add this type near the top (after the existing `import type { MirraEvent, Verdict } from "./types";` line):

```typescript
export type HashEntry = {
  hash: string;
  label: string;
  status: "pending" | "approved" | "rejected";
  source: "auto" | "manual";
  proposed_at: string;
  reviewed_at: string | null;
};
```

Add these functions at the end of the file (before the `connectLive` function, anywhere after `reconnectMonitor`):

```typescript
export async function fetchHashes(): Promise<HashEntry[]> {
  const res = await fetch(`${BASE}/api/hashes`);
  return res.json();
}

export async function submitHash(hash: string, label: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash, label }),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function approveHash(hash: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes/${hash}/approve`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}

export async function rejectHash(hash: string): Promise<void> {
  const res = await fetch(`${BASE}/api/hashes/${hash}/reject`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
}
```

- [ ] **Step 2: Create the panel component**

Create `frontend/src/components/PendingHashApprovals.tsx`:

```tsx
import { useEffect, useState } from "react";
import { approveHash, fetchHashes, rejectHash, submitHash } from "../api";
import type { HashEntry } from "../api";

export function PendingHashApprovals({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<HashEntry[]>([]);
  const [hashInput, setHashInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [busyHash, setBusyHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refetch() {
    fetchHashes()
      .then(setEntries)
      .catch(() => setEntries([]));
  }

  useEffect(refetch, [refreshKey]);

  const pending = entries.filter((e) => e.status === "pending");

  async function handleDecision(hash: string, decide: (h: string) => Promise<void>) {
    setBusyHash(hash);
    setError(null);
    try {
      await decide(hash);
      refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : "action failed");
    } finally {
      setBusyHash(null);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await submitHash(hashInput.trim(), labelInput.trim());
      setHashInput("");
      setLabelInput("");
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "submit failed");
    }
  }

  return (
    <div>
      <h2>Pending Hash Approvals</h2>
      {pending.length === 0 && <p>No pending hashes.</p>}
      {pending.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hash</th>
              <th>Label</th>
              <th>Source</th>
              <th>Proposed</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {pending.map((e) => (
              <tr key={e.hash}>
                <td>{e.hash.slice(0, 12)}...</td>
                <td>{e.label}</td>
                <td>{e.source}</td>
                <td>{e.proposed_at}</td>
                <td>
                  <button
                    disabled={busyHash === e.hash}
                    onClick={() => handleDecision(e.hash, approveHash)}
                  >
                    Approve
                  </button>
                  <button
                    disabled={busyHash === e.hash}
                    onClick={() => handleDecision(e.hash, rejectHash)}
                    style={{ marginLeft: "0.5rem" }}
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={handleSubmit} style={{ marginTop: "0.75rem" }}>
        <input
          placeholder="sha256 hash"
          value={hashInput}
          onChange={(e) => setHashInput(e.target.value)}
        />
        <input
          placeholder="label"
          value={labelInput}
          onChange={(e) => setLabelInput(e.target.value)}
          style={{ marginLeft: "0.5rem" }}
        />
        <button type="submit" style={{ marginLeft: "0.5rem" }}>
          Submit for approval
        </button>
      </form>
      {error && <p style={{ color: "#c0392b" }}>{error}</p>}
    </div>
  );
}
```

- [ ] **Step 3: Extend the audit log renderer for hash-action rows**

In `frontend/src/components/AuditLogTable.tsx`, change the `AuditRow` type from:

```typescript
type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
};
```

to:

```typescript
type AuditRow = Verdict & {
  action?: string;
  device_id?: string;
  record_id?: string;
  hash?: string;
};
```

Change the second `<td>` in the row rendering from:

```tsx
<td>{v.action ? `device: ${v.device_id}` : `${v.sample_hash.slice(0, 12)}...`}</td>
```

to:

```tsx
<td>
  {v.action
    ? v.device_id
      ? `device: ${v.device_id}`
      : v.hash
        ? `hash: ${v.hash.slice(0, 12)}...`
        : "—"
    : `${v.sample_hash.slice(0, 12)}...`}
</td>
```

- [ ] **Step 4: Wire the panel into App.tsx**

In `frontend/src/App.tsx`, add this import alongside the existing component imports:

```typescript
import { PendingHashApprovals } from "./components/PendingHashApprovals";
```

Change the WebSocket message handler from:

```typescript
    const ws = connectLive((msg) => {
      if (msg.type === "event") setEvents((prev) => [...prev, msg.data]);
      if (msg.type === "verdict") setVerdict(msg.data);
      if (msg.type === "isolated") setIsolated(true);
      if (msg.type === "reconnected") setIsolated(false);
    });
```

to:

```typescript
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

Add `<PendingHashApprovals refreshKey={refreshKey} />` in the JSX, right after the existing `<AuditLogTable refreshKey={refreshKey} />` line:

```tsx
      <AuditLogTable refreshKey={refreshKey} />
      <PendingHashApprovals refreshKey={refreshKey} />
```

- [ ] **Step 5: Manual verification**

Run: `docker compose up --build`

1. Upload a sample that trips the behavioral rules past 0.6 confidence (e.g. one that spawns a child process, writes to `/etc/`, and connects to a non-standard port) and confirm a new row appears in "Pending Hash Approvals" with source `auto`.
2. Submit a hash manually via the form; confirm it appears as `pending`, `source: manual`.
3. Click Approve on one entry, Reject on another; confirm both disappear from the pending table and both actions appear in the Audit Log table rendered as `hash: <shortened>` rather than `device: undefined`.
4. Re-upload a sample with the now-approved hash (or POST to `/score` with that `sample_hash` and no events) and confirm it now returns `Compromised` instantly via the hash match.
5. Confirm a rejected hash never affects `/score`.

- [ ] **Step 6: Update the tech notes**

In `docs/concepts.md`, replace the existing bullet:

```markdown
**Human-approval gate** (phase 2) — No automatically-generated rule or model update goes live on its own; a human has to review and approve it first. This mirrors a real security principle: never let an automated system silently change what it considers "safe" without oversight.
```

with:

```markdown
**Human-approval gate** — No automatically-generated rule or model update goes live on its own; a human has to review and approve it first. This mirrors a real security principle: never let an automated system silently change what it considers "safe" without oversight.
*In Mirraura:* scoped to known-bad hash entries (not behavioral rule weights, which would need the re-validation loop to review safely). A hash can be proposed automatically — when `/score` returns `Compromised` via the behavioral rules on a sample whose hash isn't already known — or manually via the dashboard. Either way it sits with `status: "pending"` in `known_bad_hashes.json` and `check_hash()` only ever matches `status: "approved"` entries, so a pending hash has zero effect on `/score` until a human clicks Approve. No new database: the same flat-file pattern the rest of Mirraura already uses, extended with a `status` field and a `threading.Lock()` guarding concurrent read-modify-write.
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/components/PendingHashApprovals.tsx frontend/src/components/AuditLogTable.tsx frontend/src/App.tsx docs/concepts.md
git commit -m "feat: add pending hash approval panel to the dashboard"
```
