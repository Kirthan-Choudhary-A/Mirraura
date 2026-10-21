# Admin-reviewed corpus for static-triage similarity matching

## Intent

`verdict-engine/known_bad_samples/` is currently a fixed, committed set of
files — adding a new known-bad sample means editing code and redeploying.
This promotes it to a Postgres-backed, admin-reviewed corpus with the
same propose/approve/reject shape `known_bad_hashes` already has, so an
admin can add detection coverage from the dashboard without a redeploy.

## Scope

In scope: the **similarity** corpus only (`verdict-engine/similarity.py`'s
comparison set).

Out of scope: YARA rule management. Compiling admin-submitted YARA rule
*source* at runtime is a materially different, riskier feature (rule
syntax validation, a bad rule breaking the whole scan) — a separate task
if it's ever wanted, not bundled into this one.

## Schema

New migration `verdict-engine/migrations/0003_create_known_bad_samples.sql`,
same shape and style as `0001_create_known_bad_hashes.sql`:

```sql
CREATE TABLE IF NOT EXISTS known_bad_samples (
  content_hash TEXT PRIMARY KEY,  -- sha256 hex of `content`
  content BYTEA NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  source TEXT NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  reviewed_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE, DELETE ON known_bad_samples TO {{ROLE_NAME}};
```
Seed the migration with the two samples currently hardcoded in
`known_bad_samples/` (`sensitive_write.sh`, `devtcp_reverse_shell.sh`),
pre-approved, the same way `0001` seeds the EICAR hash — so a fresh
install's demo still works without manual setup.

## Python (verdict-engine)

- **`verdict-engine/corpus_lookup.py`** — new file, mirrors
  `hash_lookup.py` exactly: `propose_sample`, `approve_sample`,
  `reject_sample`, `list_samples`, and `load_known_bad(pool) -> list[tuple[str, bytes]]`
  (label, content) for `status = 'approved'` rows only. Same exception
  shape (`SampleExistsError`, `SampleNotFoundError`, `SampleNotPendingError`).
- **`verdict-engine/similarity.py`** — change `compare`'s signature from
  `compare(data: bytes, corpus_dir: Path)` to
  `compare(data: bytes, corpus: list[tuple[str, bytes]])`, comparing
  against each `(label, content)` pair directly instead of reading a
  directory. This is piece 2's own file from the first round — update its
  existing tests (`tests/test_similarity.py`) to pass an in-memory corpus
  list instead of `known_bad_samples/`, no Docker-build-context gotcha
  possible since nothing reads from disk anymore.
- **`verdict-engine/static_triage.py`** — `run(data: bytes, pool)`, now
  takes `pool` and calls `corpus_lookup.load_known_bad(pool)` to build the
  corpus passed into `similarity.compare`. Still fails closed (a DB error
  here is logged and treated as no match, same as today).
- **`verdict-engine/app.py`** — new routes mirroring `/hashes`'s exactly:
  `GET /corpus`, `POST /corpus` (propose), `POST /corpus/{content_hash}/approve`,
  `POST /corpus/{content_hash}/reject`. `/triage`'s handler passes `_pool`
  through to `static_triage.run`.

## Go (backend)

- **`backend/corpus.go`** — new file, mirrors `backend/hashes.go` exactly
  (`corpusHandler` proxying GET/POST, `corpusDecisionHandler` proxying
  approve/reject).
- **`backend/main.go`** — register `/api/corpus` and `/api/corpus/` with
  the same `requireAuth(store)` / `requireAuth(store)(requireRole("admin")(...))`
  wrapping `/api/hashes`/`/api/hashes/` already use.

## Frontend

- **`frontend/src/api.ts`** — `fetchCorpusPending`, `approveCorpusEntry`,
  `rejectCorpusEntry`, mirroring the existing hash functions.
- **`frontend/src/components/CorpusReview.tsx`** — new component, same
  props shape and reused CSS as `PendingHashApprovals.tsx`/`QuarantineReview.tsx`.
- **`App.tsx`** — new "Corpus" tab alongside "Hashes" and "Quarantine".

## Testing

Entirely testable via `docker compose` on a normal machine — nothing in
this task touches the interceptor or needs a VM.
