import json
from pathlib import Path

import rule_scorer
from schemas import Event

FIXTURES_DIR = Path(__file__).parent.parent / "revalidation_fixtures"


def test_seven_fixtures_present():
    assert len(sorted(FIXTURES_DIR.glob("*.json"))) == 7


def test_every_fixture_matches_current_rule_scorer():
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        events = [Event(**e) for e in data["events"]]
        confidence, chain = rule_scorer.score_events(events)
        verdict = rule_scorer.verdict_from_score(confidence, chain, had_telemetry=len(events) > 0)
        assert verdict == data["expected_verdict"], (
            f"{path.name}: expected {data['expected_verdict']}, "
            f"current rule_scorer produced {verdict} (confidence={confidence})"
        )
