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
