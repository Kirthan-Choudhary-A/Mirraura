import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

import rule_scorer as current_scorer
from event_archive import EventArchive
from revalidation_report import build_report, format_table, load_candidate, run_archive, run_fixtures


def load_fixtures(fixtures_dir: Path) -> List[dict]:
    fixtures = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = json.loads(path.read_text())
        data["name"] = path.stem
        fixtures.append(data)
    return fixtures


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

    fixtures = load_fixtures(args.fixtures_dir)
    fixture_results = run_fixtures(fixtures, current_scorer, candidate_module)

    archive_skipped_reason = None
    archive_results: List[dict] = []
    if args.archive_path.exists():
        archive = EventArchive(args.archive_path)
        archive_results = run_archive(archive.all(), candidate_module)
    else:
        archive_skipped_reason = f"archive not found at {args.archive_path}"

    report = build_report(fixture_results, archive_results, archive_skipped_reason)
    print(format_table(report))

    args.report_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.report_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nFull report written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
