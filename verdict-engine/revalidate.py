import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import rule_scorer as current_scorer
from event_archive import EventArchive
from revalidation_report import build_report, format_table, load_candidate, run_archive, run_fixtures


def load_fixtures(fixtures_dir: Path) -> Tuple[List[dict], List[Tuple[str, str]]]:
    """Returns (fixtures, corpus_errors). A malformed fixture file is reported
    as a fixture-corpus error (named after the offending file), never an
    unhandled crash — it must not be misread as a candidate failure."""
    fixtures = []
    corpus_errors: List[Tuple[str, str]] = []
    for path in sorted(fixtures_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            if "events" not in data or "expected_verdict" not in data:
                raise KeyError("fixture must contain 'events' and 'expected_verdict'")
            data["name"] = path.stem
            fixtures.append(data)
        except Exception as e:
            corpus_errors.append((path.stem, str(e)))
    return fixtures, corpus_errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay archived event captures against a candidate rule scorer."
    )
    parser.add_argument(
        "--candidate", required=True, type=Path, help="path to a candidate scorer .py file"
    )
    parser.add_argument(
        "--archive-path",
        type=Path,
        default=Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")),
    )
    parser.add_argument(
        "--fixtures-dir", type=Path, default=Path(__file__).parent / "revalidation_fixtures"
    )
    parser.add_argument(
        "--report-dir", type=Path, default=Path(__file__).parent / "revalidation_reports"
    )
    args = parser.parse_args(argv)

    try:
        candidate_module = load_candidate(args.candidate)
    except (ImportError, AttributeError) as e:
        print(f"error loading candidate: {e}", file=sys.stderr)
        return 1

    fixtures, fixture_corpus_errors = load_fixtures(args.fixtures_dir)
    fixture_results = []
    for fx in fixtures:
        try:
            fixture_results.extend(run_fixtures([fx], current_scorer, candidate_module))
        except Exception as e:
            # A fixture that scores current_scorer's events but raises (e.g. a bad
            # Event shape) is a fixture-corpus problem, not a candidate failure.
            fixture_corpus_errors.append((fx.get("name", "?"), str(e)))

    archive_skipped_reason = None
    archive_results: List[dict] = []
    if not args.archive_path.exists():
        archive_skipped_reason = f"archive not found at {args.archive_path}"
    else:
        try:
            archive = EventArchive(args.archive_path)
            archive_results = run_archive(archive.all(), candidate_module)
        except Exception as e:
            archive_skipped_reason = f"archive unreadable: {e}"

    report = build_report(fixture_results, archive_results, archive_skipped_reason)
    if fixture_corpus_errors:
        report["fixture_corpus_errors"] = [
            {"name": name, "error": err} for name, err in fixture_corpus_errors
        ]
    print(format_table(report))
    if fixture_corpus_errors:
        print("\n=== Fixture Corpus Errors (not candidate failures) ===")
        for name, err in fixture_corpus_errors:
            print(f"  {name}: CORPUS ERROR: {err}")

    args.report_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.report_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nFull report written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
