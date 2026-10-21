from pathlib import Path

from yara_triage import scan

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples"

# Not read from samples/eicar.txt: that file is intentionally gitignored
# (see samples/EICAR.md) and real-time antivirus deletes it on sight, so
# the test constructs the signature in memory instead.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_scan_detects_eicar():
    rules = {m["rule"] for m in scan(EICAR)}
    assert "EICAR_Test_String" in rules


def test_scan_detects_devtcp_reverse_shell():
    data = (SAMPLES_DIR / "connect_odd_port.sh").read_bytes()
    rules = {m["rule"] for m in scan(data)}
    assert "Shell_Dev_TCP_Redirect" in rules


def test_scan_detects_sensitive_write():
    data = (SAMPLES_DIR / "spawn_and_write.sh").read_bytes()
    rules = {m["rule"] for m in scan(data)}
    assert "Shell_Sensitive_Write" in rules


def test_scan_clean_file_no_matches():
    data = (SAMPLES_DIR / "harmless.sh").read_bytes()
    assert scan(data) == []
