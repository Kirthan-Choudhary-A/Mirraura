import json
from pathlib import Path
from typing import Dict, Optional

KNOWN_BAD_PATH = Path(__file__).parent / "known_bad_hashes.json"


def load_known_bad() -> Dict[str, str]:
    with open(KNOWN_BAD_PATH) as f:
        return {entry["hash"]: entry["label"] for entry in json.load(f)}


def check_hash(sample_hash: str, known_bad: Optional[Dict[str, str]] = None) -> Optional[str]:
    known_bad = known_bad if known_bad is not None else load_known_bad()
    return known_bad.get(sample_hash)
