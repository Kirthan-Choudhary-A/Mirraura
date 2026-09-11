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
    # Stratifies evenly across the 16 feature combos, so the returned dataset
    # size is n floored to the nearest multiple of 16 (e.g. n=200 -> 192).
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
