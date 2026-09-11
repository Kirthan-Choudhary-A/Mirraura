import json

from revalidate import main


def _write_fixture(fixtures_dir, name, expected_verdict, events):
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    (fixtures_dir / f"{name}.json").write_text(
        json.dumps({"expected_verdict": expected_verdict, "events": events})
    )


def _write_candidate(path):
    path.write_text(
        "def score_events(events):\n"
        "    return 0.0, []\n"
        "def verdict_from_score(confidence, chain, had_telemetry):\n"
        "    return 'Normal' if had_telemetry else 'Inconclusive'\n"
    )


def test_main_runs_fixtures_only_when_archive_missing(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    _write_fixture(fixtures_dir, "normal", "Normal", [])

    candidate = tmp_path / "candidate.py"
    _write_candidate(candidate)

    report_dir = tmp_path / "reports"
    missing_archive = tmp_path / "no_such_archive.jsonl"

    exit_code = main(
        [
            "--candidate", str(candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(report_dir),
            "--archive-path", str(missing_archive),
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Fixture Corpus" in out
    assert "skipped:" in out

    written = list(report_dir.glob("*.json"))
    assert len(written) == 1
    report = json.loads(written[0].read_text())
    assert report["fixtures"]["total"] == 1


def test_main_reports_skip_on_malformed_archive_instead_of_crashing(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    _write_fixture(fixtures_dir, "normal", "Normal", [])

    candidate = tmp_path / "candidate.py"
    _write_candidate(candidate)

    # exists but each line fails to parse into the expected archive-entry shape
    # (missing verdict_at_capture) -- must degrade to a skip, not crash main().
    bad_archive = tmp_path / "bad_archive.jsonl"
    bad_archive.write_text(json.dumps({"verdict_id": "v1", "events": []}) + "\n")

    exit_code = main(
        [
            "--candidate", str(candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(tmp_path / "reports"),
            "--archive-path", str(bad_archive),
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Fixture Corpus" in out
    assert "archive unreadable" in out


def test_main_reports_malformed_fixture_as_corpus_error_not_crash(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir(parents=True)
    _write_fixture(fixtures_dir, "good", "Normal", [])
    (fixtures_dir / "broken.json").write_text("not valid json{{{")

    candidate = tmp_path / "candidate.py"
    _write_candidate(candidate)

    exit_code = main(
        [
            "--candidate", str(candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(tmp_path / "reports"),
            "--archive-path", str(tmp_path / "no_such_archive.jsonl"),
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "broken: CORPUS ERROR" in out
    # the good fixture still gets scored and counted in accuracy
    written = list((tmp_path / "reports").glob("*.json"))
    report = json.loads(written[0].read_text())
    assert report["fixtures"]["total"] == 1
    assert any(e["name"] == "broken" for e in report["fixture_corpus_errors"])


def test_main_returns_1_on_bad_candidate(tmp_path, capsys):
    fixtures_dir = tmp_path / "fixtures"
    _write_fixture(fixtures_dir, "normal", "Normal", [])
    bad_candidate = tmp_path / "bad.py"
    bad_candidate.write_text("x = 1\n")

    exit_code = main(
        [
            "--candidate", str(bad_candidate),
            "--fixtures-dir", str(fixtures_dir),
            "--report-dir", str(tmp_path / "reports"),
        ]
    )

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "error loading candidate" in err
