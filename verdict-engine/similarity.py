from difflib import SequenceMatcher
from typing import Dict, List, Tuple

_THRESHOLD = 0.85


def compare(data: bytes, corpus: List[Tuple[str, bytes]]) -> List[Dict]:
    """Returns [{"label": str, "ratio": float}, ...] for every (label, content)
    corpus entry scoring >= 0.85 against data, most similar first."""
    text = data.decode(errors="replace")
    # ponytail: SequenceMatcher is O(n*m) per entry -- fine for a small corpus
    # of capped-size scripts (see corpus_lookup.MAX_SAMPLE_BYTES), cache
    # decoded entries or prefilter if the corpus grows.
    matches = []
    for label, content in corpus:
        ratio = SequenceMatcher(None, text, content.decode(errors="replace")).ratio()
        if ratio >= _THRESHOLD:
            matches.append({"label": label, "ratio": ratio})
    return sorted(matches, key=lambda m: m["ratio"], reverse=True)
