from pathlib import Path

from similarity import compare

# known_bad_samples/ is both the comparison corpus and, for these tests,
# the source of "incoming" bytes too -- it's inside the Docker build
# context (unlike the repo-level samples/, which verdict-engine/'s
# Dockerfile never copies in), and comparing an entry against itself is
# an equally valid way to exercise an exact (ratio == 1.0) match.
CORPUS_DIR = Path(__file__).parent.parent / "known_bad_samples"

HARMLESS = b'#!/bin/bash\necho "just printing some text"\n'


def test_compare_matches_spawn_and_write():
    data = (CORPUS_DIR / "sensitive_write.sh").read_bytes()
    matches = compare(data, CORPUS_DIR)
    assert matches[0] == {"label": "sensitive_write", "ratio": 1.0}


def test_compare_matches_connect_odd_port():
    data = (CORPUS_DIR / "devtcp_reverse_shell.sh").read_bytes()
    matches = compare(data, CORPUS_DIR)
    assert matches[0] == {"label": "devtcp_reverse_shell", "ratio": 1.0}


def test_compare_matches_lightly_modified_variant():
    data = (CORPUS_DIR / "devtcp_reverse_shell.sh").read_bytes().replace(b"31337", b"31338")
    labels = [m["label"] for m in compare(data, CORPUS_DIR)]
    assert labels == ["devtcp_reverse_shell"]


def test_compare_harmless_no_matches():
    assert compare(HARMLESS, CORPUS_DIR) == []


def test_compare_results_sorted_most_similar_first(tmp_path):
    base = (CORPUS_DIR / "sensitive_write.sh").read_bytes()
    (tmp_path / "exact").write_bytes(base)
    (tmp_path / "near").write_bytes(base + b"# x\n")
    ratios = [m["ratio"] for m in compare(base, tmp_path)]
    assert len(ratios) == 2 and ratios == sorted(ratios, reverse=True)
