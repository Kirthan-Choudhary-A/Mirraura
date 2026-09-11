# Trained Classifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A genuinely trained logistic-regression classifier, fit on synthetic labeled data, evaluated against `rule_scorer.py` on a held-out set with real accuracy numbers, and shipped as a `revalidate.py`-compatible candidate scorer module — not wired into live `/score`.

**Architecture:** `generate_training_data.py` produces labeled synthetic `Event` sequences from a ground-truth formula deliberately different from `rule_scorer.py`'s hand-picked `RULE_WEIGHTS`. `train.py` (training-time-only tooling, needs scikit-learn) fits a `LogisticRegression` on that data, evaluates it and `rule_scorer.py` on the same held-out split, and writes the learned weights to `trained_weights.json`. `trained_scorer.py` (the only piece that ships as part of the product) loads those weights at import time with zero ML-library dependency and reuses `rule_scorer.py`'s own feature-detection constants and `verdict_from_score` function directly.

**Tech Stack:** Python (verdict-engine, existing conventions — flat files, `pytest`, plain `assert`). scikit-learn is a new dependency, but training-time-only — never imported by the live service.

**Spec:** `docs/superpowers/specs/2026-09-11-trained-classifier-design.md`

## Global Constraints

- Feature set: exactly 4 boolean features — `child_process`, `sensitive_write`, `odd_port`, `rapid_file_changes` — using `rule_scorer.py`'s own `SENSITIVE_PREFIXES`, `STANDARD_PORTS`, `RAPID_FILE_CHANGE_THRESHOLD` constants (imported, not reimplemented with different values).
- Ground-truth label formula for synthetic data: weighted sum with weights `0.35` (child_process), `0.15` (sensitive_write), `0.35` (odd_port), `0.15` (rapid_file_changes), threshold `0.5`, plus ~5% random label flips — deliberately different from `RULE_WEIGHTS`' `0.3`/`0.25`/`0.2`/`0.25` @ `0.6` threshold.
- Dataset size: ~2000 total synthetic examples, roughly balanced across the 16 feature combinations, 80/20 train/test split, stratified.
- scikit-learn is training-time-only — never imported by `trained_scorer.py`.
- `trained_scorer.py` re-exports `rule_scorer.verdict_from_score` directly (no reimplementation) — only `score_events` differs.
- `rule_scorer.py` is not modified by this item.
- No live `/score` wiring — the trained model is a `revalidate.py --candidate`-loadable module only.
- No new subdirectory for source code — every new Python module is a flat file directly under `verdict-engine/`, matching every existing module there (no other subdirectory in the project holds importable source; pytest's import resolution relies on `verdict-engine/` itself being the one `sys.path` entry).
- `verdict-engine/training_reports/` is gitignored scratch space except a `.gitkeep`, matching `verdict-engine/revalidation_reports/`'s pattern; `trained_weights.json` itself IS committed.

---

### Task 1: Synthetic training data generator

**Files:**
- Create: `verdict-engine/generate_training_data.py`
- Create: `verdict-engine/tests/test_generate_training_data.py`

**Interfaces:**
- Consumes: nothing from other tasks (base layer).
- Produces (for Task 3): `generate_dataset(n: int, seed: int) -> List[Tuple[List[Event], bool]]` (raises `ValueError` if `n < 160`), `split_dataset(dataset, test_fraction: float, seed: int) -> Tuple[List[Tuple[List[Event], bool]], List[Tuple[List[Event], bool]]]` (stratified — both classes present in both halves).

- [ ] **Step 1: Write the failing tests**

Create `verdict-engine/tests/test_generate_training_data.py`:

```python
from generate_training_data import generate_dataset, split_dataset


def test_generate_dataset_returns_requested_count():
    dataset = generate_dataset(160, seed=1)
    assert len(dataset) == 160


def test_generate_dataset_is_deterministic_given_seed():
    a = generate_dataset(160, seed=1)
    b = generate_dataset(160, seed=1)
    a_labels = [label for _, label in a]
    b_labels = [label for _, label in b]
    assert a_labels == b_labels


def test_generate_dataset_covers_both_classes():
    dataset = generate_dataset(320, seed=2)
    labels = {label for _, label in dataset}
    assert labels == {True, False}


def test_generate_dataset_rejects_too_small_n():
    try:
        generate_dataset(10, seed=1)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_generate_dataset_events_are_valid_event_objects():
    dataset = generate_dataset(160, seed=1)
    events, _ = dataset[0]
    for e in events:
        assert e.event_type in ("process_spawn", "file_write", "network_connect")
        assert e.device_id == "synthetic"


def test_split_dataset_is_stratified():
    dataset = generate_dataset(320, seed=3)
    train, test = split_dataset(dataset, test_fraction=0.2, seed=3)
    assert len(train) + len(test) == len(dataset)
    train_labels = {label for _, label in train}
    test_labels = {label for _, label in test}
    assert train_labels == {True, False}
    assert test_labels == {True, False}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_generate_training_data.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'generate_training_data'`.

- [ ] **Step 3: Implement the generator**

Create `verdict-engine/generate_training_data.py`:

```python
import random
import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from schemas import Event, FileRef, NetworkRef, ProcessRef

# Deliberately different from rule_scorer.RULE_WEIGHTS (0.3/0.25/0.2/0.25 @
# 0.6) — see spec section 5. If these ever matched RULE_WEIGHTS exactly, the
# accuracy comparison in train.py would be a tautology.
GROUND_TRUTH_WEIGHTS = {
    "child_process": 0.35,
    "sensitive_write": 0.15,
    "odd_port": 0.35,
    "rapid_file_changes": 0.15,
}
GROUND_TRUTH_THRESHOLD = 0.5
LABEL_NOISE_RATE = 0.05

SENSITIVE_PATHS = ["/etc/passwd", "/etc/cron.d/job", "/bin/sh", "/usr/bin/foo", "/sbin/init"]
ODD_PORTS = [31337, 4444, 8081, 9001, 6667]
PROCESS_NAMES = ["sh", "bash", "touch", "curl", "nc", "python3"]


def _make_event(event_type: str, **refs) -> Event:
    return Event(
        event_id=str(uuid.uuid4()),
        device_id="synthetic",
        event_type=event_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        **refs,
    )


def _true_label(
    has_spawn: bool, has_sensitive_write: bool, has_odd_port: bool, has_rapid_changes: bool, rng: random.Random
) -> bool:
    score = (
        GROUND_TRUTH_WEIGHTS["child_process"] * has_spawn
        + GROUND_TRUTH_WEIGHTS["sensitive_write"] * has_sensitive_write
        + GROUND_TRUTH_WEIGHTS["odd_port"] * has_odd_port
        + GROUND_TRUTH_WEIGHTS["rapid_file_changes"] * has_rapid_changes
    )
    label = score >= GROUND_TRUTH_THRESHOLD
    if rng.random() < LABEL_NOISE_RATE:
        label = not label
    return label


def _generate_one(
    has_spawn: bool, has_sensitive_write: bool, has_odd_port: bool, has_rapid_changes: bool, rng: random.Random
) -> List[Event]:
    events: List[Event] = []
    if has_spawn:
        events.append(
            _make_event(
                "process_spawn",
                process_ref=ProcessRef(pid=rng.randint(2, 60000), name=rng.choice(PROCESS_NAMES), parent_pid=1),
            )
        )
    if has_sensitive_write:
        events.append(
            _make_event("file_write", file_ref=FileRef(path=rng.choice(SENSITIVE_PATHS), action="write"))
        )
    if has_odd_port:
        events.append(
            _make_event(
                "network_connect",
                network_ref=NetworkRef(
                    dst_ip=f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                    dst_port=rng.choice(ODD_PORTS),
                    protocol="tcp",
                ),
            )
        )
    if has_rapid_changes:
        n = rng.randint(6, 20)
        for i in range(n):
            events.append(_make_event("file_write", file_ref=FileRef(path=f"/tmp/f{i}", action="write")))
    else:
        for i in range(rng.randint(0, 3)):
            events.append(_make_event("file_write", file_ref=FileRef(path=f"/tmp/noise{i}", action="write")))
    rng.shuffle(events)
    return events


def generate_dataset(n: int, seed: int) -> List[Tuple[List[Event], bool]]:
    if n < 160:
        raise ValueError("n must be at least 160 to stratify across 16 feature combinations")
    rng = random.Random(seed)
    combos = [(bool(i & 1), bool(i & 2), bool(i & 4), bool(i & 8)) for i in range(16)]
    per_combo = n // 16
    dataset: List[Tuple[List[Event], bool]] = []
    for combo in combos:
        for _ in range(per_combo):
            events = _generate_one(*combo, rng)
            label = _true_label(*combo, rng)
            dataset.append((events, label))
    rng.shuffle(dataset)
    return dataset


def split_dataset(
    dataset: List[Tuple[List[Event], bool]], test_fraction: float, seed: int
) -> Tuple[List[Tuple[List[Event], bool]], List[Tuple[List[Event], bool]]]:
    rng = random.Random(seed)
    positives = [d for d in dataset if d[1]]
    negatives = [d for d in dataset if not d[1]]
    rng.shuffle(positives)
    rng.shuffle(negatives)

    def _split(items):
        cut = int(len(items) * (1 - test_fraction))
        return items[:cut], items[cut:]

    pos_train, pos_test = _split(positives)
    neg_train, neg_test = _split(negatives)
    train = pos_train + neg_train
    test = pos_test + neg_test
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/test_generate_training_data.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add verdict-engine/generate_training_data.py verdict-engine/tests/test_generate_training_data.py
git commit -m "feat: add synthetic training-data generator for the trained classifier"
```

---

### Task 2: Candidate scorer module (`trained_scorer.py`)

**Files:**
- Create: `verdict-engine/trained_scorer.py`
- Create: `verdict-engine/trained_weights.json`
- Create: `verdict-engine/tests/test_trained_scorer.py`

**Interfaces:**
- Consumes: `rule_scorer.SENSITIVE_PREFIXES`, `rule_scorer.STANDARD_PORTS`, `rule_scorer.RAPID_FILE_CHANGE_THRESHOLD`, `rule_scorer.verdict_from_score` (all already exist, unchanged).
- Produces (for Task 4's `revalidate.py --candidate` sanity check): `score_events(events: List[Event]) -> Tuple[float, List[str]]`, `verdict_from_score` (identical object to `rule_scorer.verdict_from_score`) — the exact contract `revalidate.py`'s `load_candidate` already expects.

- [ ] **Step 1: Ship a placeholder weights file**

Create `verdict-engine/trained_weights.json` — a hand-picked placeholder (NOT a real training result) so this module and its tests work standalone before `train.py` is ever run. Task 4's manual verification overwrites this file with real learned values, which is what stays committed:

```json
{
  "child_process": 0.3,
  "sensitive_write": 0.25,
  "odd_port": 0.2,
  "rapid_file_changes": 0.25,
  "intercept": -0.6
}
```

- [ ] **Step 2: Write the failing tests**

Create `verdict-engine/tests/test_trained_scorer.py`:

```python
import rule_scorer
import trained_scorer
from schemas import Event, FileRef, ProcessRef


def test_verdict_from_score_is_rule_scorer_function():
    assert trained_scorer.verdict_from_score is rule_scorer.verdict_from_score


def test_score_events_returns_valid_shape():
    events = [
        Event(
            event_id="e1",
            device_id="test",
            event_type="process_spawn",
            timestamp="2026-09-11T00:00:00Z",
            process_ref=ProcessRef(pid=1, name="sh", parent_pid=0),
        )
    ]
    confidence, chain = trained_scorer.score_events(events)
    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0
    assert isinstance(chain, list)
    assert all(isinstance(c, str) for c in chain)


def test_score_events_empty_events_gives_no_chain():
    confidence, chain = trained_scorer.score_events([])
    assert chain == []


def test_score_events_sensitive_write_appears_in_chain():
    events = [
        Event(
            event_id="e1",
            device_id="test",
            event_type="file_write",
            timestamp="2026-09-11T00:00:00Z",
            file_ref=FileRef(path="/etc/passwd", action="write"),
        )
    ]
    confidence, chain = trained_scorer.score_events(events)
    assert len(chain) == 1
    assert "sensitive path" in chain[0]
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd verdict-engine && python -m pytest tests/test_trained_scorer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'trained_scorer'`.

- [ ] **Step 4: Implement the scorer module**

Create `verdict-engine/trained_scorer.py`:

```python
"""
Trained classifier candidate scorer (Sub-project 2, item 5). Loadable via
revalidate.py --candidate: verdict-engine$ python revalidate.py --candidate trained_scorer.py

Requires trained_weights.json (produced by train.py, or the placeholder
this module ships with) to exist alongside this file. No scikit-learn
dependency at this layer -- inference is a plain dot-product + sigmoid.
"""
import json
import math
from pathlib import Path
from typing import List, Tuple

import rule_scorer
from rule_scorer import verdict_from_score  # re-exported unchanged
from schemas import Event

_WEIGHTS_PATH = Path(__file__).parent / "trained_weights.json"
_WEIGHTS = json.loads(_WEIGHTS_PATH.read_text())


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def score_events(events: List[Event]) -> Tuple[float, List[str]]:
    contributions = []

    spawns = [e for e in events if e.event_type == "process_spawn" and e.process_ref]
    if spawns:
        p = spawns[0].process_ref
        contributions.append(
            ("child_process", _WEIGHTS["child_process"], f"spawned child process '{p.name}' (pid {p.pid})")
        )

    sensitive = [
        e
        for e in events
        if e.event_type == "file_write"
        and e.file_ref
        and e.file_ref.path.startswith(rule_scorer.SENSITIVE_PREFIXES)
    ]
    if sensitive:
        contributions.append(
            (
                "sensitive_write",
                _WEIGHTS["sensitive_write"],
                f"wrote to sensitive path '{sensitive[0].file_ref.path}'",
            )
        )

    odd_conns = [
        e
        for e in events
        if e.event_type == "network_connect"
        and e.network_ref
        and e.network_ref.dst_port not in rule_scorer.STANDARD_PORTS
    ]
    if odd_conns:
        n = odd_conns[0].network_ref
        contributions.append(
            ("odd_port", _WEIGHTS["odd_port"], f"connected to non-standard port {n.dst_port} ({n.dst_ip})")
        )

    file_changes = [e for e in events if e.event_type in ("file_write", "file_delete")]
    if len(file_changes) > rule_scorer.RAPID_FILE_CHANGE_THRESHOLD:
        contributions.append(
            (
                "rapid_file_changes",
                _WEIGHTS["rapid_file_changes"],
                f"modified {len(file_changes)} files rapidly",
            )
        )

    active_weights_sum = sum(weight for _, weight, _ in contributions)
    confidence = _sigmoid(active_weights_sum + _WEIGHTS["intercept"])

    contributions.sort(key=lambda c: c[1], reverse=True)
    chain = [text for _, _, text in contributions]

    return confidence, chain
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd verdict-engine && python -m pytest tests/test_trained_scorer.py -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add verdict-engine/trained_scorer.py verdict-engine/trained_weights.json verdict-engine/tests/test_trained_scorer.py
git commit -m "feat: add trained-classifier candidate scorer (ships with placeholder weights)"
```

---

### Task 3: Training/evaluation script (`train.py`)

**Files:**
- Create: `verdict-engine/train.py`
- Create: `verdict-engine/tests/test_train.py`
- Create: `verdict-engine/training_reports/.gitkeep`
- Modify: `.gitignore`

**Interfaces:**
- Consumes (from Task 1): `generate_training_data.generate_dataset`, `generate_training_data.split_dataset`. Consumes `rule_scorer.SENSITIVE_PREFIXES`, `rule_scorer.STANDARD_PORTS`, `rule_scorer.RAPID_FILE_CHANGE_THRESHOLD`, `rule_scorer.score_events`, `rule_scorer.verdict_from_score` (all pre-existing).
- Produces (for Task 4): `extract_features(events: List[Event]) -> List[int]` (a 4-element `[child_process, sensitive_write, odd_port, rapid_file_changes]` list of `0`/`1`), `main() -> int` (the CLI entrypoint — trains, evaluates, writes `trained_weights.json` and a timestamped report under `training_reports/`).

- [ ] **Step 1: Write the failing test for the pure feature-extraction logic**

Create `verdict-engine/tests/test_train.py`:

```python
from train import extract_features
from schemas import Event, FileRef, NetworkRef, ProcessRef


def _event(event_type, **refs):
    return Event(
        event_id="e1",
        device_id="test",
        event_type=event_type,
        timestamp="2026-09-11T00:00:00Z",
        **refs,
    )


def test_extract_features_all_zero_for_no_events():
    assert extract_features([]) == [0, 0, 0, 0]


def test_extract_features_child_process():
    events = [_event("process_spawn", process_ref=ProcessRef(pid=1, name="sh", parent_pid=0))]
    assert extract_features(events) == [1, 0, 0, 0]


def test_extract_features_sensitive_write():
    events = [_event("file_write", file_ref=FileRef(path="/etc/passwd", action="write"))]
    assert extract_features(events) == [0, 1, 0, 0]


def test_extract_features_non_sensitive_write_is_not_flagged():
    events = [_event("file_write", file_ref=FileRef(path="/tmp/readme.txt", action="write"))]
    assert extract_features(events) == [0, 0, 0, 0]


def test_extract_features_odd_port():
    events = [_event("network_connect", network_ref=NetworkRef(dst_ip="127.0.0.1", dst_port=31337))]
    assert extract_features(events) == [0, 0, 1, 0]


def test_extract_features_standard_port_is_not_flagged():
    events = [_event("network_connect", network_ref=NetworkRef(dst_ip="127.0.0.1", dst_port=443))]
    assert extract_features(events) == [0, 0, 0, 0]


def test_extract_features_rapid_file_changes():
    events = [
        _event("file_write", file_ref=FileRef(path=f"/tmp/f{i}", action="write")) for i in range(6)
    ]
    assert extract_features(events) == [0, 0, 0, 1]


def test_extract_features_five_file_changes_is_not_rapid():
    events = [
        _event("file_write", file_ref=FileRef(path=f"/tmp/f{i}", action="write")) for i in range(5)
    ]
    assert extract_features(events) == [0, 0, 0, 0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd verdict-engine && python -m pytest tests/test_train.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'train'` (or an `ImportError` if `sklearn` isn't installed yet — either way, a clear failure since `train.py` doesn't exist).

- [ ] **Step 3: Install the training-time-only dependency**

```bash
python -m pip install scikit-learn
```

This installs scikit-learn into whatever Python environment `pytest`/`train.py` run in on this host. It is deliberately NOT added to `verdict-engine/requirements.txt` — the live service never imports it.

- [ ] **Step 4: Implement `train.py`**

Create `verdict-engine/train.py`:

```python
"""
Training-only tooling for Mirraura's trained classifier candidate scorer
(Sub-project 2, item 5). Requires scikit-learn, which is NOT a runtime
dependency of the live verdict-engine service:
    pip install scikit-learn

Usage: python train.py
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from sklearn.linear_model import LogisticRegression

import rule_scorer
from generate_training_data import generate_dataset, split_dataset
from schemas import Event

N_EXAMPLES = 2000
TEST_FRACTION = 0.2
SEED = 42

FEATURE_NAMES = ["child_process", "sensitive_write", "odd_port", "rapid_file_changes"]


def extract_features(events: List[Event]) -> List[int]:
    spawns = any(e.event_type == "process_spawn" and e.process_ref for e in events)
    sensitive = any(
        e.event_type == "file_write" and e.file_ref and e.file_ref.path.startswith(rule_scorer.SENSITIVE_PREFIXES)
        for e in events
    )
    odd_port = any(
        e.event_type == "network_connect"
        and e.network_ref
        and e.network_ref.dst_port not in rule_scorer.STANDARD_PORTS
        for e in events
    )
    file_changes = sum(1 for e in events if e.event_type in ("file_write", "file_delete"))
    rapid = file_changes > rule_scorer.RAPID_FILE_CHANGE_THRESHOLD
    return [int(spawns), int(sensitive), int(odd_port), int(rapid)]


def load_training_data() -> List[Tuple[List[Event], bool]]:
    return generate_dataset(N_EXAMPLES, SEED)


def evaluate_rule_scorer(test_set: List[Tuple[List[Event], bool]]) -> float:
    correct = 0
    for events, true_label in test_set:
        confidence, chain = rule_scorer.score_events(events)
        verdict = rule_scorer.verdict_from_score(confidence, chain, had_telemetry=len(events) > 0)
        predicted = verdict == "Compromised"
        if predicted == true_label:
            correct += 1
    return correct / len(test_set)


def main() -> int:
    dataset = load_training_data()
    train_set, test_set = split_dataset(dataset, TEST_FRACTION, SEED)

    X_train = [extract_features(events) for events, _ in train_set]
    y_train = [int(label) for _, label in train_set]
    X_test = [extract_features(events) for events, _ in test_set]
    y_test = [int(label) for _, label in test_set]

    model = LogisticRegression()
    model.fit(X_train, y_train)
    model_accuracy = model.score(X_test, y_test)

    rule_accuracy = evaluate_rule_scorer(test_set)

    report_lines = [
        "=== Trained Classifier vs Rule Scorer (held-out accuracy) ===",
        f"Dataset: {len(dataset)} examples ({len(train_set)} train / {len(test_set)} test)",
        f"Rule scorer (rule_scorer.py, hand-picked weights):     {rule_accuracy:.1%}",
        f"Trained model (logistic regression, learned weights):  {model_accuracy:.1%}",
    ]
    report_text = "\n".join(report_lines)
    print(report_text)

    weights = {name: float(coef) for name, coef in zip(FEATURE_NAMES, model.coef_[0])}
    weights["intercept"] = float(model.intercept_[0])

    weights_path = Path(__file__).parent / "trained_weights.json"
    weights_path.write_text(json.dumps(weights, indent=2))
    print(f"\nWeights written to {weights_path}")

    reports_dir = Path(__file__).parent / "training_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.txt"
    report_path.write_text(report_text)
    print(f"Report written to {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd verdict-engine && python -m pytest tests/test_train.py -v`
Expected: all PASS. (This only exercises `extract_features` — it does not run `main()`, which needs scikit-learn and takes a few seconds; that happens for real in Task 4's manual verification.)

- [ ] **Step 6: Scratch directory and gitignore**

Create `verdict-engine/training_reports/.gitkeep` (empty file).

Add to `.gitignore`, next to the existing `verdict-engine/revalidation_reports/*.json` / `.gitkeep` lines:

```
verdict-engine/training_reports/*.txt
!verdict-engine/training_reports/.gitkeep
```

- [ ] **Step 7: Run the full test suite to confirm no regressions**

Run: `cd verdict-engine && python -m pytest tests/ -v`
Expected: all PASS, including every pre-existing test from items 1-4.

- [ ] **Step 8: Commit**

```bash
git add verdict-engine/train.py verdict-engine/tests/test_train.py verdict-engine/training_reports/.gitkeep .gitignore
git commit -m "feat: add training/evaluation script for the trained classifier"
```

---

### Task 4: Real training run, docs, manual verification

**Files:**
- Modify: `verdict-engine/trained_weights.json` (overwritten by running `train.py` for real)
- Modify: `docs/concepts.md`

**Interfaces:**
- Consumes (from Tasks 1-3): `train.py`'s `main()`, `trained_scorer.py`, the existing `revalidate.py --candidate` mechanism from item 3.
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Run the real training script**

```bash
cd verdict-engine
python train.py
```

Expected: prints the two-line accuracy comparison (rule scorer vs. trained model on the held-out set) and confirms both `trained_weights.json` and a new file under `training_reports/` were written. Record the exact two accuracy percentages printed — they're needed for Step 3.

- [ ] **Step 2: Confirm the placeholder weights were genuinely replaced**

```bash
cat trained_weights.json
```

Expected: five real floats (four feature weights + `intercept`) that are NOT the placeholder values from Task 2's Step 1 (`0.3`, `0.25`, `0.2`, `0.25`, `-0.6`) — confirms this is now a real learned model, not the ship-with-the-code placeholder.

- [ ] **Step 3: Update the tech notes with the real numbers**

In `docs/concepts.md`, replace:

```markdown
**Rule-based scorer (v1) vs. trained ML classifier (later)** — Mirraura's verdict engine uses hand-written, weighted rules ("spawned child process: +0.3") instead of a trained model. This is a deliberate choice, not a shortcut you have to hide: with only synthetic demo samples, there isn't enough real data to train something meaningful yet, and a transparent rule set is *more* explainable, not less. It outputs the exact same shape (label + confidence + causal chain) a trained model would, so it's a clean drop-in replacement later — which becomes your "phase 2" story: replace the scorer with a trained classifier and show the detection rate improve.
```

with (filling in the two real percentages from Step 1's output — do not leave placeholder text):

```markdown
**Rule-based scorer (v1) vs. trained ML classifier (later)** — Mirraura's verdict engine uses hand-written, weighted rules ("spawned child process: +0.3") instead of a trained model. This is a deliberate choice, not a shortcut you have to hide: with only synthetic demo samples, there isn't enough real data to train something meaningful yet, and a transparent rule set is *more* explainable, not less. It outputs the exact same shape (label + confidence + causal chain) a trained model would, so it's a clean drop-in replacement later — which becomes your "phase 2" story: replace the scorer with a trained classifier and show the detection rate improve.
*In Mirraura:* `verdict-engine/train.py` fits a `scikit-learn` `LogisticRegression` over the same 4 features `rule_scorer.py` checks, on ~2000 synthetic examples labeled from a ground-truth weighting deliberately different from `RULE_WEIGHTS` (so the comparison isn't a tautology). On a held-out 20% split, the rule scorer scores **<RULE_ACCURACY>%** and the trained model scores **<MODEL_ACCURACY>%** — a real, reproducible number from an actual training run, not an assertion. The trained model ships as `verdict-engine/trained_scorer.py`, loadable the same way any hand-edited rule-weight candidate is (`python revalidate.py --candidate trained_scorer.py`) — it stays a candidate, not the live scorer; nothing here auto-promotes to production, same principle as the re-validation loop's rule-weight candidates.
```

(Replace `<RULE_ACCURACY>` and `<MODEL_ACCURACY>` with the actual percentages from Step 1's real output.)

- [ ] **Step 4: Bonus sanity check via the existing revalidate.py tooling**

```bash
python revalidate.py --candidate trained_scorer.py
```

Expected: the fixture-corpus table runs successfully (no crash) and reports an accuracy figure for the trained candidate against the item-3 fixtures — the fixtures weren't part of this model's training distribution, so this is a genuine out-of-distribution sanity check, not a re-test of the training run. Note the printed fixture accuracy in your final report to the user, but do not treat a lower score here as a blocker — the fixtures test different (hand-picked diagnostic) cases than the synthetic training distribution.

- [ ] **Step 5: Run the full test suite one more time**

Run: `cd verdict-engine && python -m pytest tests/ -v`
Expected: all PASS (the trained_weights.json content changed, but `test_trained_scorer.py`'s assertions don't depend on specific weight values, only on shape/identity, so they still pass against the real weights).

- [ ] **Step 6: Commit**

```bash
git add verdict-engine/trained_weights.json docs/concepts.md
git commit -m "feat: run real training pass and record measured accuracy in concepts.md"
```
