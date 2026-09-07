import hashlib

from hash_lookup import check_hash

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_known_bad_hash_returns_label():
    assert check_hash(EICAR_HASH) == "EICAR-Test-File"


def test_unknown_hash_returns_none():
    assert check_hash("0" * 64) is None


def test_eicar_hash_constant_matches_real_bytes():
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert hashlib.sha256(eicar_bytes).hexdigest() == EICAR_HASH
