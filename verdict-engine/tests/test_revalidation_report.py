from schemas import Event

from revalidation_report import build_report, format_table, load_candidate, run_archive, run_fixtures


class _StubScorer:
    """Stands in for a real candidate module without needing a file on disk."""

    def __init__(self, confidence, chain):
        self.confidence = confidence
        self.chain = chain

    def score_events(self, events):
        return self.confidence, self.chain

    def verdict_from_score(self, confidence, chain, had_telemetry):
        if not had_telemetry:
            return "Inconclusive"
        if confidence == 0.0:
            return "Normal"
        if confidence < 0.6:
            return "Suspicious"
        return "Compromised"


def _event_dict():
    return Event(
        event_id="e1",
        device_id="shadow-node",
        event_type="process_spawn",
        timestamp="2026-09-11T00:00:00Z",
        process_ref={"pid": 1, "name": "sh", "parent_pid": 0},
    ).model_dump()


def test_run_fixtures_reports_before_after_correctness():
    fixtures = [{"name": "f1", "expected_verdict": "Suspicious", "events": [_event_dict()]}]
    current = _StubScorer(0.3, ["x"])
    candidate = _StubScorer(0.7, ["x", "y"])

    results = run_fixtures(fixtures, current, candidate)

    assert results[0]["before_verdict"] == "Suspicious"
    assert results[0]["before_correct"] is True
    assert results[0]["after_verdict"] == "Compromised"
    assert results[0]["after_correct"] is False


def test_run_archive_detects_flip():
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [_event_dict()],
            "verdict_at_capture": "Suspicious",
        }
    ]
    results = run_archive(entries, _StubScorer(0.9, ["x"]))

    assert results[0]["before_verdict"] == "Suspicious"
    assert results[0]["after_verdict"] == "Compromised"
    assert results[0]["flipped"] is True


def test_run_archive_no_flip():
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [],
            "verdict_at_capture": "Inconclusive",
        }
    ]
    results = run_archive(entries, _StubScorer(0.0, []))

    assert results[0]["flipped"] is False


def test_build_report_computes_accuracy():
    fixture_results = [
        {
            "name": "f1", "expected_verdict": "Normal", "before_verdict": "Normal",
            "before_confidence": 0.0, "before_correct": True,
            "after_verdict": "Normal", "after_confidence": 0.0, "after_correct": True,
        },
        {
            "name": "f2", "expected_verdict": "Compromised", "before_verdict": "Suspicious",
            "before_confidence": 0.4, "before_correct": False,
            "after_verdict": "Compromised", "after_confidence": 0.7, "after_correct": True,
        },
    ]
    report = build_report(fixture_results, [])

    assert report["fixtures"]["before_accuracy"] == 0.5
    assert report["fixtures"]["after_accuracy"] == 1.0


def test_build_report_archive_skipped_reason_is_preserved():
    report = build_report([], [], archive_skipped_reason="archive not found")
    assert report["archive"]["skipped_reason"] == "archive not found"


def test_format_table_includes_accuracy_and_flip_lines():
    fixture_results = [
        {
            "name": "f1", "expected_verdict": "Normal", "before_verdict": "Normal",
            "before_confidence": 0.0, "before_correct": True,
            "after_verdict": "Normal", "after_confidence": 0.0, "after_correct": True,
        },
    ]
    archive_results = [
        {
            "verdict_id": "v1", "sample_hash": "a" * 64, "source": "sample",
            "before_verdict": "Suspicious", "after_verdict": "Compromised",
            "after_confidence": 0.7, "flipped": True,
        },
    ]
    table = format_table(build_report(fixture_results, archive_results))

    assert "Fixture Corpus" in table
    assert "Archived Captures" in table
    assert "Suspicious -> Compromised" in table


def test_load_candidate_missing_functions_raises(tmp_path):
    bad = tmp_path / "bad_candidate.py"
    bad.write_text("x = 1\n")
    try:
        load_candidate(bad)
        assert False, "expected AttributeError"
    except AttributeError:
        pass


def test_load_candidate_loads_real_module(tmp_path):
    good = tmp_path / "good_candidate.py"
    good.write_text(
        "def score_events(events):\n"
        "    return 0.0, []\n"
        "def verdict_from_score(confidence, chain, had_telemetry):\n"
        "    return 'Normal'\n"
    )
    module = load_candidate(good)
    assert module.score_events([]) == (0.0, [])
