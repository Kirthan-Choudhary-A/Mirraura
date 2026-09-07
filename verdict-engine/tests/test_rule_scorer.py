from schemas import Event, FileRef, NetworkRef, ProcessRef
from rule_scorer import score_events, verdict_from_score


def make_event(event_type, **refs) -> Event:
    return Event(
        event_id="e1",
        device_id="shadow-node",
        event_type=event_type,
        timestamp="2026-09-07T00:00:00Z",
        **refs,
    )


def test_no_events_no_rules_fire():
    confidence, chain = score_events([])
    assert confidence == 0.0
    assert chain == []


def test_child_process_and_sensitive_write():
    events = [
        make_event("process_spawn", process_ref=ProcessRef(pid=1, name="touch")),
        make_event(
            "file_write",
            file_ref=FileRef(path="/etc/mirraura-test-marker", action="write"),
        ),
    ]
    confidence, chain = score_events(events)
    assert confidence == 0.55
    assert len(chain) == 2


def test_odd_port_only():
    events = [
        make_event(
            "network_connect",
            network_ref=NetworkRef(dst_ip="127.0.0.1", dst_port=31337),
        )
    ]
    confidence, chain = score_events(events)
    assert confidence == 0.2
    assert len(chain) == 1


def test_verdict_banding():
    assert verdict_from_score(0.0, [], had_telemetry=False) == "Inconclusive"
    assert verdict_from_score(0.0, [], had_telemetry=True) == "Normal"
    assert verdict_from_score(0.2, ["x"], had_telemetry=True) == "Suspicious"
    assert verdict_from_score(0.55, ["x", "y"], had_telemetry=True) == "Suspicious"
    assert verdict_from_score(0.6, ["x"], had_telemetry=True) == "Compromised"
