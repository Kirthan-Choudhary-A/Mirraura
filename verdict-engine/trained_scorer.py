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


def verdict_from_score(confidence: float, chain: List[str], had_telemetry: bool) -> str:
    if not had_telemetry:
        return "Inconclusive"
    # Unlike rule_scorer's additive score, this sigmoid-based confidence can
    # only approach 0.0 asymptotically and never hits it exactly, so a
    # confidence == 0.0 check (rule_scorer's check) would never fire and a
    # genuinely clean run would always come back "Suspicious". A small
    # threshold band gives a real Normal outcome instead.
    if confidence < 0.1:
        return "Normal"
    if confidence < 0.6:
        return "Suspicious"
    return "Compromised"
