# Static triage: YARA + content similarity

## Intent

Today a sample only gets judged two ways: an exact SHA-256 match against
`known_bad_hashes`, or a full dynamic detonation (spin up the shadow
container, trace it, score the behavior). Static triage adds a third,
much cheaper check that runs on the raw file content before detonation:
pattern matching (YARA) and near-duplicate detection against known-bad
samples. A decisive static hit skips detonation entirely — faster, and a
good demo beat ("we flagged it without even running it").

## Scope

In scope:
- A YARA scan of the raw sample bytes against a small custom ruleset.
- A content-similarity check against a small seeded corpus of known-bad
  samples (near-duplicate detection, not exact hash).
- Wiring both into the existing `/score` pipeline with a skip-detonation
  fast path on a decisive match.

Out of scope (later, if time remains):
- A Postgres-backed, admin-reviewed corpus for either mechanism
  (mirroring `known_bad_hashes`'s propose/approve/reject flow). V1 ships
  with a committed seed file, same pattern `known_bad_hashes.json`
  already uses as fixture data.
- True fuzzy hashing (ssdeep/TLSH). See "How it's built" below for why.
- Any change to the interceptor daemon or the continuous-monitoring path
  — this only touches the upload/intercept detonation pipeline.

## How it's built (my calls)

- **Similarity mechanism: Python's stdlib `difflib.SequenceMatcher`, not
  ssdeep/TLSH.** Both require compiling a C extension against a system
  library (`libfuzzy-dev` for ssdeep) with no prebuilt wheel for
  python:3.12-slim — real risk of eating hours of a tight timebox on a
  flaky Docker build instead of shipping the feature. This project's
  samples are all small text files (shell scripts), where
  `difflib`'s ratio works fine and ships with zero new system
  dependencies. Named `similarity.py`, not `fuzzy_hash.py`, to be honest
  about what it does.
- **Both mechanisms live in `verdict-engine/`** (Python), not the Go
  backend, keeping "scoring intelligence" in one place — same reasoning
  that put `rule_scorer.py` and `hash_lookup.py` there.
- **New endpoint, not a bigger `/score`.** `POST /triage` takes the raw
  bytes and returns matches; it does no audit-log writing of its own.
  The backend calls it first, and folds the result into the *existing*
  `/score` call via a new optional field — one audit-log write per
  sample, same as today, not two.
- **Skip-detonation threshold:** a YARA match OR similarity ratio ≥ 0.85
  against a known-bad corpus entry is decisive (skip detonation, verdict
  = Compromised, same style as the existing `known_bad_label` short
  circuit in `app.py`'s `/score`). Anything weaker is ignored for V1 —
  no blended scoring between static and dynamic signals, to keep the
  logic simple under time pressure.

## The two independent pieces

**Piece 1 — YARA** (`verdict-engine/yara_triage.py` + `verdict-engine/yara-rules/*.yar`)
```python
def scan(data: bytes) -> list[dict]:
    """Returns [{"rule": str, "meta": dict}, ...] for every rule that matched."""
```
Ruleset: an EICAR string-match rule (classic, trivial, proves the
mechanism works) plus 1-2 heuristic rules against this repo's own
`samples/` shell scripts (e.g. a rule flagging `nc `/reverse-shell-style
constructs, matching what `connect_odd_port.sh` does) so the demo has
something real to catch statically.
Dependency: `yara-python` (has prebuilt wheels for this image, no apt
changes needed). Add one line to `requirements.txt`.

**Piece 2 — similarity** (`verdict-engine/similarity.py` + `verdict-engine/known_bad_samples/`)
```python
def compare(data: bytes, corpus_dir: Path) -> list[dict]:
    """Returns [{"label": str, "ratio": float}, ...] for every corpus entry
    scoring >= 0.85, most similar first."""
```
Corpus: a small directory of committed known-bad sample files (start
with `spawn_and_write.sh` and `connect_odd_port.sh` copied in, labeled),
loaded and compared with `difflib.SequenceMatcher(None, data.decode(errors="replace"), corpus_text).ratio()`.
No new dependency.

Each piece gets its own small test file (`test_yara_triage.py`,
`test_similarity.py`) exercising it directly against files already in
`samples/` — no FastAPI, no Postgres, no Docker needed to test either
one.

## Integration (done once, after both pieces land, to avoid two people editing the same file)

- `verdict-engine/static_triage.py`: thin combiner, `run(data: bytes) -> list[dict]`
  calling both `yara_triage.scan` and `similarity.compare`, merging results.
  Degrades gracefully if one piece isn't built yet (empty list, not an error).
- `verdict-engine/app.py`: new `POST /triage` endpoint wrapping `static_triage.run`;
  `ScoreRequest` gets a new `static_matches: list[str] = []` field, and `/score`
  gets a new early branch (mirroring the existing `known_bad_label` check) that
  returns Compromised with the static match reasons in `causal_chain` when
  `static_matches` is non-empty.
- `backend/samples.go`: `detonateAndScore` POSTs the raw bytes to `/triage` right
  after computing `sampleHash`, before `CreateShadowNetwork`; on a decisive
  result, skips straight to `scoreWithVerdictEngine` (now taking an extra
  `staticMatches []string` param) without ever touching Docker.

## Split

- **Piece 1 (YARA)** — built directly in this session now.
- **Piece 2 (similarity)** — handed to the friend as a self-contained task brief
  (file paths, function signature, and the two sample files to seed the corpus
  with are all above; no other file in the repo needs touching).
- **Integration** — done by this session once Piece 2 is in, to avoid both
  people editing `app.py`/`samples.go` at the same time.
