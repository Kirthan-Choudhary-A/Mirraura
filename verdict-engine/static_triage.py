import logging
from typing import List

import corpus_lookup
import yara_triage
import similarity

logger = logging.getLogger(__name__)


def run(data: bytes, pool) -> List[str]:
    """Runs both static checks and returns a flat list of human-readable
    match descriptions, empty if neither found anything. A scan failure is
    logged and treated as no match, never appended here -- this list drives
    an automatic Compromised verdict upstream, so an error must never be
    mistaken for a match."""
    reasons: List[str] = []

    try:
        for m in yara_triage.scan(data):
            reasons.append(f"YARA rule '{m['rule']}' matched")
    except Exception:
        logger.warning("YARA scan failed, treating as no match", exc_info=True)

    try:
        for m in similarity.compare(data, corpus_lookup.load_known_bad(pool)):
            reasons.append(f"{m['ratio']:.0%} similar to known-bad sample '{m['label']}'")
    except Exception:
        logger.warning("similarity scan failed, treating as no match", exc_info=True)

    return reasons
