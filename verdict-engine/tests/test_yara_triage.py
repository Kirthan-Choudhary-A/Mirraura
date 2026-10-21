from pathlib import Path

from yara_triage import scan

# known_bad_samples/, not the repo-level samples/ -- the latter is outside
# the Docker build context (verdict-engine/'s Dockerfile only COPYs this
# directory), so a path reaching for it works on a plain checkout but
# 404s inside the container. known_bad_samples/ already has content-
# identical copies of the two samples this needs.
CORPUS_DIR = Path(__file__).parent.parent / "known_bad_samples"

# Not read from samples/eicar.txt: that file is intentionally gitignored
# (see samples/EICAR.md) and real-time antivirus deletes it on sight, so
# the test constructs the signature in memory instead.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

HARMLESS = b'#!/bin/bash\necho "just printing some text"\n'


def test_scan_detects_eicar():
    rules = {m["rule"] for m in scan(EICAR)}
    assert "EICAR_Test_String" in rules


def test_scan_detects_devtcp_reverse_shell():
    data = (CORPUS_DIR / "devtcp_reverse_shell.sh").read_bytes()
    rules = {m["rule"] for m in scan(data)}
    assert "Shell_Dev_TCP_Redirect" in rules


def test_scan_detects_sensitive_write():
    data = (CORPUS_DIR / "sensitive_write.sh").read_bytes()
    rules = {m["rule"] for m in scan(data)}
    assert "Shell_Sensitive_Write" in rules


def test_scan_clean_file_no_matches():
    assert scan(HARMLESS) == []
