from pathlib import Path

from similarity import compare

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples"
CORPUS_DIR = Path(__file__).parent.parent / "known_bad_samples"


def test_compare_matches_spawn_and_write():
    data = (SAMPLES_DIR / "spawn_and_write.sh").read_bytes()
    matches = compare(data, CORPUS_DIR)
    assert matches[0] == {"label": "sensitive_write", "ratio": 1.0}


def test_compare_matches_connect_odd_port():
    data = (SAMPLES_DIR / "connect_odd_port.sh").read_bytes()
    matches = compare(data, CORPUS_DIR)
    assert matches[0] == {"label": "devtcp_reverse_shell", "ratio": 1.0}


def test_compare_matches_lightly_modified_variant():
    data = (SAMPLES_DIR / "connect_odd_port.sh").read_bytes().replace(b"31337", b"31338")
    labels = [m["label"] for m in compare(data, CORPUS_DIR)]
    assert labels == ["devtcp_reverse_shell"]


def test_compare_harmless_no_matches():
    data = (SAMPLES_DIR / "harmless.sh").read_bytes()
    assert compare(data, CORPUS_DIR) == []


def test_compare_results_sorted_most_similar_first(tmp_path):
    base = (SAMPLES_DIR / "spawn_and_write.sh").read_bytes()
    (tmp_path / "exact").write_bytes(base)
    (tmp_path / "near").write_bytes(base + b"# x\n")
    ratios = [m["ratio"] for m in compare(base, tmp_path)]
    assert len(ratios) == 2 and ratios == sorted(ratios, reverse=True)
