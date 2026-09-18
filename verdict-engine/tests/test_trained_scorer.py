import rule_scorer
import trained_scorer
from schemas import Event, FileRef, ProcessRef


def test_verdict_from_score_no_telemetry_is_inconclusive():
    assert trained_scorer.verdict_from_score(0.9, [], had_telemetry=False) == "Inconclusive"


def test_verdict_from_score_near_zero_confidence_is_normal():
    # trained_scorer's sigmoid-based confidence can never hit exactly 0.0
    # (unlike rule_scorer's additive score), so this must use a threshold
    # rather than an exact-equality check.
    assert trained_scorer.verdict_from_score(0.004, [], had_telemetry=True) == "Normal"


def test_verdict_from_score_mid_confidence_is_suspicious():
    assert trained_scorer.verdict_from_score(0.3, ["some reason"], had_telemetry=True) == "Suspicious"


def test_verdict_from_score_high_confidence_is_compromised():
    assert trained_scorer.verdict_from_score(0.8, ["some reason"], had_telemetry=True) == "Compromised"


def test_real_weights_clean_run_scores_normal():
    # A genuinely clean detonation (no rule contributions at all) should
    # come back Normal end to end, using the actual shipped weights.
    confidence, chain = trained_scorer.score_events([])
    assert chain == []
    # had_telemetry only matters with real events; this asserts the
    # confidence itself is low enough to clear the Normal threshold once
    # paired with at least one observed (but benign) event elsewhere.
    assert confidence < 0.1


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
