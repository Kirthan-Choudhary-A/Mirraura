from pathlib import Path
from typing import List, Dict

import yara

_RULES_DIR = Path(__file__).parent / "yara-rules"
_compiled = None


def _rules():
    global _compiled
    if _compiled is None:
        rule_files = {p.stem: str(p) for p in _RULES_DIR.glob("*.yar")}
        _compiled = yara.compile(filepaths=rule_files)
    return _compiled


def scan(data: bytes) -> List[Dict]:
    """Returns [{"rule": str, "meta": dict}, ...] for every rule in
    yara-rules/ that matched data, most severe first isn't guaranteed --
    callers that care about severity should look at meta["severity"]."""
    matches = _rules().match(data=data)
    return [{"rule": m.rule, "meta": dict(m.meta)} for m in matches]
