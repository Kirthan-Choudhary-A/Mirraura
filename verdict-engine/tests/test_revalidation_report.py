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


def test_run_archive_skips_known_bad_match_entries():
    # verdict_at_capture came from the hash short-circuit, never score_events();
    # even though the candidate would score these events completely differently
    # (Compromised, confidence 0.9), that must not be reported as a flip.
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [_event_dict()],
            "verdict_at_capture": "Compromised",
            "confidence_at_capture": 1.0,
            "known_bad_match": True,
        }
    ]
    results = run_archive(entries, _StubScorer(0.9, ["x"]))

    assert results[0]["skipped"] == "hash short-circuit, not scored"
    assert "flipped" not in results[0]
    assert "after_verdict" not in results[0]

    report = build_report([], results)
    assert report["archive"]["flipped_count"] == 0
    assert report["archive"]["skipped_count"] == 1
    assert report["archive"]["scored_total"] == 0

    # must not crash formatting a result with no after_verdict/flipped fields
    table = format_table(build_report([], results))
    assert "0 / 0 verdicts changed" in table


def test_run_archive_skips_timed_out_entries():
    # verdict_at_capture ("Inconclusive") came from app.py's timed-out
    # short-circuit, never score_events(); even though the candidate would
    # score these (truncated) events completely differently, that must not
    # be reported as a flip.
    entries = [
        {
            "verdict_id": "v1",
            "sample_hash": "a" * 64,
            "source": "sample",
            "events": [_event_dict()],
            "verdict_at_capture": "Inconclusive",
            "confidence_at_capture": 0.0,
            "timed_out": True,
        }
    ]
    results = run_archive(entries, _StubScorer(0.9, ["x"]))

    assert results[0]["skipped"] == "timed out, not scored"
    assert "flipped" not in results[0]
    assert "after_verdict" not in results[0]

    report = build_report([], results)
    assert report["archive"]["flipped_count"] == 0
    assert report["archive"]["skipped_count"] == 1
    assert report["archive"]["scored_total"] == 0


def test_run_archive_missing_known_bad_match_field_is_scored_normally():
    # old archive lines written before this field existed must still load and
    # score fine via entry.get(...), not raise a KeyError.
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


def test_load_candidate_nonexistent_file_raises(tmp_path):
    nonexistent = tmp_path / "nonexistent.py"
    try:
        load_candidate(nonexistent)
        assert False, "expected ImportError"
    except ImportError:
        pass


def test_load_candidate_syntax_error_raises(tmp_path):
    bad_syntax = tmp_path / "bad_syntax.py"
    bad_syntax.write_text("def this_is_broken(\n")
    try:
        load_candidate(bad_syntax)
        assert False, "expected ImportError"
    except ImportError:
        pass
