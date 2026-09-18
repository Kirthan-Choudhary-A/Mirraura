import importlib.util
from pathlib import Path
from typing import List, Optional, Tuple

from schemas import Event


def load_candidate(path: Path):
    spec = importlib.util.spec_from_file_location("revalidation_candidate", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load candidate module from {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise ImportError(f"cannot load candidate module from {path}: {e}") from e
    if not hasattr(module, "score_events") or not hasattr(module, "verdict_from_score"):
        raise AttributeError(
            f"candidate module {path} must define score_events and verdict_from_score"
        )
    return module


def score_with(module, events: List[Event]) -> Tuple[str, float, List[str]]:
    confidence, chain = module.score_events(events)
    verdict = module.verdict_from_score(confidence, chain, had_telemetry=len(events) > 0)
    return verdict, confidence, chain


def run_fixtures(fixtures: List[dict], current_module, candidate_module) -> List[dict]:
    results = []
    for fx in fixtures:
        events = [Event(**e) for e in fx["events"]]
        before_verdict, before_conf, _ = score_with(current_module, events)
        after_verdict, after_conf, _ = score_with(candidate_module, events)
        results.append(
            {
                "name": fx["name"],
                "expected_verdict": fx["expected_verdict"],
                "before_verdict": before_verdict,
                "before_confidence": before_conf,
                "before_correct": before_verdict == fx["expected_verdict"],
                "after_verdict": after_verdict,
                "after_confidence": after_conf,
                "after_correct": after_verdict == fx["expected_verdict"],
            }
        )
    return results


def run_archive(archive_entries: List[dict], candidate_module) -> List[dict]:
    results = []
    for entry in archive_entries:
        # A known-bad-hash short-circuit verdict never came from score_events() in
        # the first place (see app.py's score() handler), so there's nothing
        # honest to diff it against — re-scoring its events and comparing to
        # verdict_at_capture would report a meaningless "flip" on every entry.
        # Same reasoning applies to a timed-out run: its "Inconclusive" verdict
        # is assigned by fiat, not produced by score_events().
        if entry.get("known_bad_match") or entry.get("timed_out"):
            skipped_reason = (
                "hash short-circuit, not scored"
                if entry.get("known_bad_match")
                else "timed out, not scored"
            )
            results.append(
                {
                    "verdict_id": entry["verdict_id"],
                    "sample_hash": entry["sample_hash"],
                    "source": entry["source"],
                    "before_verdict": entry.get("verdict_at_capture"),
                    "skipped": skipped_reason,
                }
            )
            continue
        events = [Event(**e) for e in entry["events"]]
        after_verdict, after_conf, _ = score_with(candidate_module, events)
        before_verdict = entry["verdict_at_capture"]
        results.append(
            {
                "verdict_id": entry["verdict_id"],
                "sample_hash": entry["sample_hash"],
                "source": entry["source"],
                "before_verdict": before_verdict,
                "after_verdict": after_verdict,
                "after_confidence": after_conf,
                "flipped": after_verdict != before_verdict,
            }
        )
    return results


def build_report(
    fixture_results: List[dict],
    archive_results: List[dict],
    archive_skipped_reason: Optional[str] = None,
) -> dict:
    fixture_total = len(fixture_results)
    before_correct = sum(1 for r in fixture_results if r["before_correct"])
    after_correct = sum(1 for r in fixture_results if r["after_correct"])
    # .get(...) rather than [...]: known-bad-hash entries carry no "flipped" key
    # (they're never scored, see run_archive) and must never count as a flip.
    scored_results = [r for r in archive_results if not r.get("skipped")]
    skipped_results = [r for r in archive_results if r.get("skipped")]
    flips = [r for r in scored_results if r.get("flipped")]
    return {
        "fixtures": {
            "total": fixture_total,
            "before_accuracy": before_correct / fixture_total if fixture_total else 0.0,
            "after_accuracy": after_correct / fixture_total if fixture_total else 0.0,
            "results": fixture_results,
        },
        "archive": {
            "skipped_reason": archive_skipped_reason,
            "total": len(archive_results),
            "scored_total": len(scored_results),
            "skipped_count": len(skipped_results),
            "flipped_count": len(flips),
            "results": archive_results,
        },
    }


def format_table(report: dict) -> str:
    lines = []
    fx = report["fixtures"]
    lines.append("=== Fixture Corpus (ground-truth accuracy) ===")
    lines.append(
        f"Before: {fx['before_accuracy']:.0%}   After: {fx['after_accuracy']:.0%}   "
        f"({fx['total']} fixtures)"
    )
    for r in fx["results"]:
        before_mark = "PASS" if r["before_correct"] else "FAIL"
        after_mark = "PASS" if r["after_correct"] else "FAIL"
        lines.append(
            f"  {r['name']:<28} expected={r['expected_verdict']:<12} "
            f"before={r['before_verdict']:<12}[{before_mark}] "
            f"after={r['after_verdict']:<12}[{after_mark}]"
        )
    lines.append("")
    ar = report["archive"]
    lines.append("=== Archived Captures (verdict drift) ===")
    if ar["skipped_reason"]:
        lines.append(f"  skipped: {ar['skipped_reason']}")
    else:
        skip_note = f"  ({ar['skipped_count']} skipped: hash short-circuit)" if ar["skipped_count"] else ""
        lines.append(f"{ar['flipped_count']} / {ar['scored_total']} verdicts changed{skip_note}")
        for r in ar["results"]:
            if r.get("flipped"):
                lines.append(
                    f"  {r['verdict_id'][:8]}  {r['source']:<8} "
                    f"{r['before_verdict']} -> {r['after_verdict']}"
                )
    return "\n".join(lines)
