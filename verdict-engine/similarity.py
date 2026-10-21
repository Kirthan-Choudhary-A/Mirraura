from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List

_THRESHOLD = 0.85


def compare(data: bytes, corpus_dir: Path) -> List[Dict]:
    """Returns [{"label": str, "ratio": float}, ...] for every corpus entry
    scoring >= 0.85, most similar first. An entry's label is its filename
    stem, so corpus files are named for what they are."""
    text = data.decode(errors="replace")
    # ponytail: re-reads the corpus on every call and SequenceMatcher is
    # O(n*m) -- fine for a handful of small scripts, cache/cap sizes if the
    # corpus grows.
    matches = []
    for p in sorted(corpus_dir.iterdir()):
        if not p.is_file():
            continue
        ratio = SequenceMatcher(None, text, p.read_bytes().decode(errors="replace")).ratio()
        if ratio >= _THRESHOLD:
            matches.append({"label": p.stem, "ratio": ratio})
    return sorted(matches, key=lambda m: m["ratio"], reverse=True)
