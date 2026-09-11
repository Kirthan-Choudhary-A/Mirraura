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
