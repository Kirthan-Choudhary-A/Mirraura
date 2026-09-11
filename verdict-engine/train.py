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
