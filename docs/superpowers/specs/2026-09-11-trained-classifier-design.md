# Mirraura — Trained Classifier (Sub-project 2, item 5, optional)

Status: approved for implementation planning
Date: 2026-09-11
Scope: fifth and final item of the Sub-project 2 finishing phase, explicitly marked "Optional" in the original spec (§14). Builds on the completed continuous-monitoring layer, human-approval gate, re-validation loop, and Rust sensor rewrite (all merged to `main`).

## 1. Problem & Context

`docs/concepts.md`'s existing "Rule-based scorer (v1) vs. trained ML classifier (later)" note commits Mirraura to a specific "phase 2" story: replace the hand-picked `RULE_WEIGHTS` in `verdict-engine/rule_scorer.py` with a real trained model that outputs the exact same shape (label + confidence + causal chain), and show the detection rate improve. This item builds that.

The obstacle the original spec's "Optional" framing was probably anticipating: real training data barely exists. `samples/` has 4 demo scripts plus EICAR; `verdict-engine/event_archive.py` (built in item 3) only started archiving real `/score` calls going forward and currently holds nothing persisted to disk outside a live Docker run. There is no dataset here large or diverse enough to train a meaningful model on real captures alone.

## 2. Goals

- A genuinely trained `LogisticRegression` model (scikit-learn) over the same 4 feature dimensions `rule_scorer.py` already checks (child-process spawn, sensitive-path write, odd-port connect, rapid file changes), fit on a programmatically generated synthetic training set with honest, self-assigned ground truth.
- An honest train/test evaluation: a held-out synthetic test set scored by both the trained model and the real `rule_scorer.py`, reporting both accuracies side by side — a real, reproducible number, not an assertion.
- The trained model ships as a `revalidate.py`-compatible candidate scorer module (`score_events`/`verdict_from_score`, loadable via `--candidate`) — evaluatable the same way any hand-edited rule-weight candidate already is.
- `rule_scorer.py` itself is not modified and stays the live production scorer — matches item 3's established precedent that candidate-evaluation work never touches the live scorer.

## 3. Non-goals

- No live wiring into `/score` — the trained model is evaluated, never deployed. Promoting it to production, if ever, is a separate future decision a human makes after reading the report (same principle item 3 established for rule-weight candidates).
- No training on the real event archive yet. `train.py`'s data-loading step is a single, isolated function (`load_training_data()`) that today only calls the synthetic generator — swapping in real archive data later (using `verdict_at_capture` as a pseudo-label, consistent with item 3's honesty precedent for that data) is a clean, low-friction extension, but not built in this item.
- No change to `verdict-engine/revalidation_fixtures/` or its sanity test. That corpus (item 3) is deliberately small, diagnostic, and 100%-correct-by-construction against the *current* rule scorer; this item's held-out synthetic test set must legitimately include cases the current rules get wrong (that's the whole point of the comparison), which would violate that corpus's invariant if mixed in. This item's evaluation is a separate, purpose-built mechanism (`train.py`).
- No decision-tree or other model type — logistic regression only, for the reason in §5.
- No change to `verdict-engine/schemas.py`, `verdict-engine/app.py`, or anything outside the new files in §6.
- No new subdirectory under `verdict-engine/` for source code. Every existing Python module in `verdict-engine/` is a flat file in that one directory (`schemas.py`, `rule_scorer.py`, `app.py`, `audit_log.py`, `event_archive.py`, `revalidate.py`, `revalidation_report.py`, `hash_lookup.py`) — pytest's import resolution there relies on `verdict-engine/` itself being the one directory on `sys.path`, with no package/subpackage plumbing anywhere in the project. The only existing subdirectories (`revalidation_fixtures/`, `revalidation_candidates/`, `revalidation_reports/`) hold *data*, never importable source. This item's new modules follow the same flat-file convention.

## 4. Architecture

```
verdict-engine/ (new flat files, alongside the existing rule_scorer.py etc. — training-time tooling, not part of the live service except trained_scorer.py)
  generate_training_data.py
    generate_dataset(n: int, seed: int) -> List[Tuple[List[Event], bool]]
      For each of the 16 boolean combinations of the 4 feature dimensions,
      generates ~n/16 synthetic examples with randomized concrete detail
      (random pids/process names, random sensitive paths, random odd ports,
      random benign "noise" writes when rapid-changes is False). Ground
      truth label is NOT the rule scorer's own weights/threshold — see §5
      for the exact formula — so the comparison reflects a genuinely
      different (data-fit vs. hand-picked) decision boundary, not a
      tautology. ~5% random label flips to avoid a perfectly separable,
      unrealistically clean dataset.
      Split 80/20 train/test, stratified so both classes appear in both.

  train.py (run manually/offline — training-only tooling, not started by
            the live verdict-engine service)
    1. dataset = load_training_data()  # -> generate_dataset() today
    2. Fit sklearn.linear_model.LogisticRegression on the 4 extracted
       features (child_process, sensitive_write, odd_port,
       rapid_file_changes — all boolean, same binarization rule_scorer.py
       already uses) over the train split.
    3. Evaluate the fitted model's accuracy on the held-out test split.
    4. Evaluate rule_scorer.py's real score_events/verdict_from_score
       (Compromised-or-not, thresholded the same way) on the SAME held-out
       test split.
    5. Print both accuracies side by side, and write the same report to a
       timestamped file under verdict-engine/training_reports/.
    6. Write the 4 learned coefficients + intercept to
       verdict-engine/trained_weights.json.

  trained_scorer.py (the candidate scorer module — this IS part of what
                      ships, unlike generate_training_data.py/train.py
                      which are training-time-only tooling)
    Loads trained_weights.json at import time (pure JSON, no sklearn
    needed here — sklearn is a training-time-only dependency).
    score_events(events) -> (confidence, chain):
      extracts the same 4 features rule_scorer.py does (reusing its
      SENSITIVE_PREFIXES/STANDARD_PORTS/RAPID_FILE_CHANGE_THRESHOLD
      constants so the feature *definitions* stay identical — only the
      weights and aggregation formula differ), computes
      confidence = sigmoid(dot(features, learned_weights) + intercept),
      builds causal-chain strings (same phrasing style as rule_scorer.py)
      for whichever features fired, sorted by learned contribution.
    verdict_from_score = rule_scorer.verdict_from_score (re-exported
      directly, unchanged — the Suspicious/Compromised thresholds aren't
      part of what this item trains).
```

## 5. Why logistic regression, and why the ground-truth formula differs from `RULE_WEIGHTS`

Logistic regression over the same 4 boolean features `rule_scorer.py` already extracts is the model that best preserves the causal-chain requirement: its coefficients are directly interpretable per-feature contributions, sortable into the same style of human-readable reasons the rule scorer already produces — a decision tree's path-based explanation would need more translation work for comparatively little benefit here, and any lower-level feature representation would break the "same output shape" story `docs/concepts.md` already commits to.

For the accuracy comparison to mean anything, the synthetic dataset's true labels cannot be generated from `rule_scorer.py`'s own weights/threshold — that would make "the trained model matches the rules" the tautological best possible outcome, proving nothing. Instead, ground truth is assigned from a *different*, still-linear weighting (`0.35`/`0.15`/`0.35`/`0.15` for spawn/sensitive-write/odd-port/rapid-changes respectively, threshold `0.5`, plus ~5% random label noise) — representing the realistic scenario that hand-picked weights are rarely exactly optimal. Logistic regression fit via maximum-likelihood on labeled data will generally out-perform an arbitrary hand-picked weight vector on the distribution it was fit to, without needing engineered feature interactions — this is real, unrigged signal, not a constructed win.

## 6. Components

- **`verdict-engine/generate_training_data.py`** (new) — `generate_dataset(n, seed) -> List[Tuple[List[Event], bool]]`.
- **`verdict-engine/train.py`** (new) — the training/evaluation script described in §4.
- **`verdict-engine/trained_scorer.py`** (new) — the shipped candidate scorer module.
- **`verdict-engine/trained_weights.json`** (generated by `train.py`, committed once produced — the actual learned weights this item's demo report is based on) — `{"child_process": float, "sensitive_write": float, "odd_port": float, "rapid_file_changes": float, "intercept": float}`. A placeholder value (hand-picked, clearly not a real training result) ships with the code that reads it, so the module and its tests are usable even before `train.py` has ever been run for real; the manual-verification step overwrites it with the actually-learned weights, which is what stays committed.
- **`verdict-engine/training_reports/`** (new, gitignored scratch dir except a `.gitkeep`, matching `revalidation_reports/`'s existing pattern) — where `train.py` writes its printed report as a timestamped file, for later reference.
- **`docs/concepts.md`** — the existing "Rule-based scorer (v1) vs. trained ML classifier (later)" bullet gets an `*In Mirraura:*` addendum once this ships, following the same pattern items 2-4 used, stating the real measured accuracy numbers from the actual training run (not a template placeholder).
- **`verdict-engine/requirements.txt`** — unchanged. scikit-learn is documented as a training-time-only dependency (a comment at the top of `train.py`), not added here, since the live service never imports it.

## 7. Error Handling

- `trained_scorer.py` fails fast and clearly at import time if `trained_weights.json` is missing or malformed (this is a candidate module meant to be loaded via `revalidate.py --candidate`, which already has its own clear error-surfacing for a candidate that fails to load — no special handling needed beyond letting that propagate naturally).
- `train.py` requires scikit-learn to be installed in whatever environment runs it; if it's missing, the resulting `ImportError` is a clear, expected signal (not something to catch and paper over) since scikit-learn is a deliberate training-time-only dependency.
- `generate_dataset` is deterministic given a fixed `seed` (for reproducible reports and testable output), but does not need to gracefully handle `n` values too small to stratify across all 16 combinations — a `n` below roughly 160 (16 combos × minimum 10 each) can raise directly; this is training tooling run manually with a chosen `n`, not a runtime path needing defensive handling.

## 8. Testing

- **`verdict-engine/tests/test_generate_training_data.py`** — `generate_dataset` with a fixed seed produces the requested count, roughly stratified across the 16 feature combinations, and the train/test split is stratified (both classes present in both splits). Spot-check that a deterministic seed reproduces identical output (needed for `train.py`'s report to be reproducible).
- **`verdict-engine/tests/test_trained_scorer.py`** — using a small hand-crafted `trained_weights.json` fixture (not the real trained one, so this test doesn't depend on ever having run `train.py`), assert `score_events` returns a valid `(float, List[str])` shape for a few constructed event lists, and assert `trained_scorer.verdict_from_score is rule_scorer.verdict_from_score` (identity check — proves genuine re-export, not a coincidentally-matching reimplementation).
- No test asserts a specific accuracy-improvement number — that would be testing one random training run's outcome, not code correctness. `train.py`'s printed/written report is the demo artifact, not a CI-checked pass/fail.
- **Manual verification** (Claude drives this, same as prior items): actually run `train.py` end to end, confirm it produces a real report with two real, different accuracy numbers on the held-out set; then load `trained_scorer.py` through the existing `revalidate.py --candidate` against the item-3 fixtures/archive as a bonus sanity check (a reasonably good trained model should still get those basic diagnostic cases right too, even though they weren't part of its training distribution).

## 9. Global Constraints (for the implementation plan)

- Feature set: exactly 4 boolean features — `child_process`, `sensitive_write`, `odd_port`, `rapid_file_changes` — using the identical detection logic/constants `rule_scorer.py` already has (`SENSITIVE_PREFIXES`, `STANDARD_PORTS`, `RAPID_FILE_CHANGE_THRESHOLD`), imported not reimplemented with different values.
- Ground-truth label formula for synthetic data: weighted sum with weights `0.35` (child_process), `0.15` (sensitive_write), `0.35` (odd_port), `0.15` (rapid_file_changes), threshold `0.5`, plus ~5% random label flips — deliberately different from `RULE_WEIGHTS`' `0.3`/`0.25`/`0.2`/`0.25` @ `0.6` threshold.
- Dataset size: on the order of ~2000 total synthetic examples (roughly balanced across the 16 feature combinations), 80/20 train/test split, stratified.
- scikit-learn is a training-time-only dependency — never imported by `trained_scorer.py` or anything the live `verdict-engine` service loads at request time.
- `trained_scorer.py` re-exports `rule_scorer.verdict_from_score` directly (no reimplementation) — only `score_events` differs.
- `rule_scorer.py` is not modified by this item.
- No live `/score` wiring — the trained model is a `revalidate.py --candidate`-loadable module only.
- `verdict-engine/training_reports/` is gitignored scratch space except a `.gitkeep`, matching `verdict-engine/revalidation_reports/`'s existing pattern; `trained_weights.json` itself IS committed (it's the actual shipped model, not a scratch artifact).
- No new subdirectory for source code — `generate_training_data.py`, `train.py`, `trained_scorer.py`, `trained_weights.json` are flat files directly under `verdict-engine/`, matching every existing module there.
