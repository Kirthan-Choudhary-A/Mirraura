from similarity import compare

SENSITIVE_WRITE = b"#!/bin/bash\ntouch /etc/mirraura-test-marker\ncat /etc/hostname > /dev/null\n"
DEVTCP = b"#!/bin/bash\nexec 3<>/dev/tcp/127.0.0.1/31337 2>/dev/null || true\n"
CORPUS = [("sensitive_write", SENSITIVE_WRITE), ("devtcp_reverse_shell", DEVTCP)]

HARMLESS = b'#!/bin/bash\necho "just printing some text"\n'


def test_compare_exact_match():
    assert compare(SENSITIVE_WRITE, CORPUS)[0] == {"label": "sensitive_write", "ratio": 1.0}
    assert compare(DEVTCP, CORPUS)[0] == {"label": "devtcp_reverse_shell", "ratio": 1.0}


def test_compare_matches_lightly_modified_variant():
    labels = [m["label"] for m in compare(DEVTCP.replace(b"31337", b"31338"), CORPUS)]
    assert labels == ["devtcp_reverse_shell"]


def test_compare_harmless_no_matches():
    assert compare(HARMLESS, CORPUS) == []


def test_compare_empty_corpus_no_matches():
    assert compare(DEVTCP, []) == []


def test_compare_results_sorted_most_similar_first():
    corpus = [("near", SENSITIVE_WRITE + b"# x\n"), ("exact", SENSITIVE_WRITE)]
    assert [m["label"] for m in compare(SENSITIVE_WRITE, corpus)] == ["exact", "near"]
