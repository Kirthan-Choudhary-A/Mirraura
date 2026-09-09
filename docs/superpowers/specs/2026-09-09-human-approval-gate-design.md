# Mirraura — Human-Approval Gate (Sub-project 2, item 2)

Status: approved for implementation planning
Date: 2026-09-09
Scope: second item of the Sub-project 2 finishing phase. Builds on the completed prototype and the completed continuous-monitoring layer (both merged to `main`).

## 1. Problem & Context

The verdict engine's known-bad hash list (`verdict-engine/known_bad_hashes.json`) is a static file: any entry in it immediately and silently affects every future `/score` call. There is no review step — if a hash is ever added incorrectly (bad label, wrong hash, malicious tampering with the file), it takes effect instantly with no human in the loop. This sub-project adds that review step for known-bad hash entries specifically. `docs/concepts.md`'s existing "Human-approval gate" note ("no automatically-generated rule or model update goes live on its own; a human has to review and approve it first") describes the principle this implements.

Scope is deliberately narrower than "all rules": behavioral rule weights (`RULE_WEIGHTS`, `RAPID_FILE_CHANGE_THRESHOLD` in `rule_scorer.py`) are explicitly out of scope — approving a weight change well requires re-running it against history first, which is item 3 (re-validation loop), not this item. Bundling both now would mean building two different approval semantics at once for no demo benefit.

## 2. Goals

- A known-bad hash can be proposed two ways: automatically (when `/score` returns `Compromised` via the behavioral rules on a sample whose hash isn't already known) or manually (a person submits a hash + label via the dashboard).
- A proposed hash sits in a `pending` state and has **zero effect** on `/score` results until a human approves it.
- A human can approve or reject a pending entry from the dashboard; approving makes it affect `/score` immediately, rejecting discards it (but keeps a record).
- Every approve/reject action is recorded in the existing tamper-evident audit log, exactly like isolate/reconnect actions already are.

## 3. Non-goals

- No behavioral rule weight approval (deferred — see §1).
- No new database or new service (see §5 — this stays a flat file, consistent with the rest of Mirraura).
- No user accounts/authentication for "who approved" — Mirraura has no auth anywhere; this matches the existing Reconnect action, which also records no approver identity.
- No retrofit of the pre-existing, unrelated race condition in `AuditLog.append()` (concurrent `/score` calls could theoretically produce a broken hash chain today). That's a Sub-project 1 issue, out of scope here — only the *new* pending/approved hash state gets a concurrency guard.

## 4. Architecture

```
verdict-engine (FastAPI, single process, no new service)
  known_bad_hashes.json — now: [{hash, label, status, source, proposed_at, reviewed_at}]
  threading.Lock() guards every read-modify-write to this file.

POST /score:
  1. check_hash(sample_hash) — matches ONLY status == "approved" entries (unchanged
     behavior for everything already approved; pending/rejected are invisible here)
  2. if no hash match → existing behavioral rule scoring (score_events), unchanged
  3. if resulting verdict == "Compromised" via behavioral rules (not a hash match)
     AND sample_hash not already in the store under any status:
       auto-insert {hash: sample_hash, label: "auto-proposed from verdict <id>",
                    status: "pending", source: "auto", proposed_at: now}
     (best-effort: failure here is logged, never fails the /score response)
  4. Verdict response shape: UNCHANGED. The proposal is a side effect, not part
     of the response — the dashboard's pending panel polls its own endpoint.

New verdict-engine endpoints (in hash_lookup.py, not a new file):
  GET  /hashes                 — list all entries, any status
  POST /hashes                 — manual submit {hash, label} → pending, source: manual
                                   409 if hash already exists under any status
  POST /hashes/{hash}/approve  — pending → approved, sets reviewed_at
                                   404 unknown hash, 409 if not currently pending
  POST /hashes/{hash}/reject   — pending → rejected, sets reviewed_at
                                   same 404/409 rules
  Approve/reject both call audit_log.append() with
  {record_id, action: "hash_approved"|"hash_rejected", hash, label, timestamp}

Go backend proxies these (same pattern as the existing /api/verdicts proxy):
  GET  /api/hashes
  POST /api/hashes
  POST /api/hashes/{hash}/approve
  POST /api/hashes/{hash}/reject

Frontend: App.tsx already receives every verdict (upload + continuous-monitoring)
over the existing WebSocket "verdict" message — it bumps the existing refreshKey
on that message (currently only bumped after upload). PendingHashApprovals reads
that same refreshKey, same pattern AuditLogTable already uses. No new WebSocket
message type.
```

## 5. Why no database

Mirraura has no database anywhere — every piece of state (audit log, known-bad hash list) is a flat file the FastAPI process reads and writes directly. This feature follows that existing pattern rather than introducing new infrastructure: `known_bad_hashes.json` gains a `status` field instead of becoming a table in a new service.

The one real gap a flat file has that a database wouldn't: no transactional safety. Two concurrent read-modify-write operations (e.g. an auto-propose from `/score` racing a human's Approve click) could clobber each other. This is closed with a single `threading.Lock()` in the verdict-engine process, held around every read-modify-write to the hash file — sufficient because the verdict-engine runs as one process with no multi-worker setup. `AuditLog.append()` has an analogous unaddressed race today (concurrent `/score` calls reading the same "last hash"); that's a pre-existing Sub-project 1 gap and is explicitly not fixed as part of this item (§3).

Migrating to a real database was discussed and explicitly deferred — not part of Sub-project 2's five items, and doing it now (or right before a demo) would risk destabilizing the audit log, Mirraura's most tamper-evidence-critical component, for a feature that doesn't need it. Revisit if/when item 3 (re-validation loop) or item 5 (trained classifier) need real structured storage for captured event logs — that's a stronger, more concrete motivating reason than this feature alone.

## 6. Components

- **`verdict-engine/hash_lookup.py`** — extended with the status-tagged store, the `threading.Lock()`, and functions for propose/approve/reject/list. `check_hash()` gains an implicit approved-only filter.
- **`verdict-engine/known_bad_hashes.json`** — schema change: each entry gains `status`, `source`, `proposed_at`, `reviewed_at`. Existing seed entry (`EICAR-Test-File`) becomes `status: "approved", source: "manual"` on migration.
- **`verdict-engine/app.py`** — `/score` handler gains the auto-propose side effect (§4 step 3) and the three new `/hashes*` routes.
- **`backend/main.go`** — three new proxy routes, same shape as the existing `/api/verdicts` proxy.
- **`frontend/src/components/PendingHashApprovals.tsx`** (new) — pending-entries table with Approve/Reject buttons, plus a small manual-submission form. Same busy/error local-state pattern as `MonitorBanner`.
- **`frontend/src/api.ts`** — `fetchHashes()`, `submitHash(hash, label)`, `approveHash(hash)`, `rejectHash(hash)`.
- **`frontend/src/components/AuditLogTable.tsx`** — column-2 renderer gains a third branch: hash-action rows (`action` set, `device_id` absent, `hash` present) render `hash: <shortened>` instead of falling into the `device: undefined` case.
- **`frontend/src/App.tsx`** — bumps `refreshKey` on every incoming `verdict` WS message (not just after upload), and mounts `<PendingHashApprovals refreshKey={refreshKey} />`.

## 7. Error Handling

- Auto-propose failure inside `/score` (lock contention, disk error) → logged, `/score` response still returns normally. Scoring must never break because of this side effect (mirrors `monitor.go`'s `logAction`, which is already best-effort).
- `POST /hashes` with a hash that isn't exactly 64 lowercase hex characters (standard SHA-256 hex form — confirmed the existing seed entry matches this) → `400`.
- `POST /hashes` with a hash that already exists under any status → `409` (no duplicate entries; if it's pending, they should approve/reject the existing one; if already decided, resubmitting is a no-op that would confuse the review history).
- `POST /hashes/{hash}/approve` or `/reject` on an unknown hash → `404`.
- `POST /hashes/{hash}/approve` or `/reject` on a hash not currently `pending` → `409` (no re-deciding an already-decided entry).
- Audit-log write failure on approve/reject → logged, does not block the state transition (matches the existing isolate/reconnect pattern where audit logging is best-effort).

## 8. Testing

- **Python** (`verdict-engine/tests/`): `check_hash` matches only `approved` entries; a repeated `Compromised` verdict for the same hash does not create a second pending entry; manual submit creates a `pending` entry and rejects duplicates with `409`; approve/reject transitions and their `404`/`409` cases; a concurrency test that fires the lock from two threads and asserts the file stays valid JSON with no lost write (the actual check for the race-condition fix, not a happy-path test).
- **Go**: unit test for the three proxy handlers (thin — assert they forward to the right verdict-engine path and pass through status codes/bodies), following the existing proxy-handler test pattern for `/api/verdicts`.
- **Frontend**: no new Vitest coverage planned beyond what already exists for `api.ts`'s request/response shapes (matches the project's existing frontend test scope — one meaningful unit test file, not a suite per component).
- **Manual end-to-end**: trigger a Compromised verdict via behavioral rules (not a known hash), confirm a pending entry appears in the dashboard automatically; submit a hash manually; approve one, reject another; confirm the approved one now short-circuits `/score` to an instant `Compromised`, the rejected one has no effect; confirm both actions appear in the audit log table with the new hash-action rendering.

## 9. Global Constraints (for the implementation plan)

- Storage: `verdict-engine/known_bad_hashes.json`, extended in place — no new file, no new service, no database.
- Concurrency: a single module-level `threading.Lock()` in `hash_lookup.py` guards every read-modify-write to the hash file.
- `check_hash()` matches only `status == "approved"` entries — this is the entire enforcement mechanism for "pending has zero effect."
- Auto-propose trigger: `/score` returns `Compromised` via behavioral rules (not a hash match) AND `sample_hash` not already present under any status.
- No response-shape change to `Verdict` — auto-propose is a side effect, never part of `/score`'s response payload.
- No new WebSocket message type — the frontend refetches on the existing `verdict` message via the existing `refreshKey` mechanism.
- No authentication/approver-identity tracking — matches the existing Reconnect action's precedent.
- Behavioral rule weights (`RULE_WEIGHTS`, `RAPID_FILE_CHANGE_THRESHOLD`) are explicitly out of scope for this item.
- Hash format validation on `POST /hashes`: exactly 64 lowercase hex characters (standard SHA-256 hex form), matching the existing seed entry's format.
