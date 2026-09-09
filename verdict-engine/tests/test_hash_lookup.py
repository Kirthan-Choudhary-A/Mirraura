import hashlib
import json
import threading

import hash_lookup
from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    propose_hash,
    reject_hash,
)

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_known_bad_hash_returns_label():
    assert check_hash(EICAR_HASH) == "EICAR-Test-File"


def test_unknown_hash_returns_none():
    assert check_hash("0" * 64) is None


def test_eicar_hash_constant_matches_real_bytes():
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert hashlib.sha256(eicar_bytes).hexdigest() == EICAR_HASH


def _seed(tmp_path, monkeypatch, entries):
    path = tmp_path / "known_bad_hashes.json"
    path.write_text(json.dumps(entries))
    monkeypatch.setattr(hash_lookup, "KNOWN_BAD_PATH", path)
    return path


def test_is_valid_hash():
    assert is_valid_hash("a" * 64) is True
    assert is_valid_hash("A" * 64) is False
    assert is_valid_hash("a" * 63) is False
    assert is_valid_hash("z" * 64) is False


def test_pending_hash_is_invisible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    assert check_hash("a" * 64) is None


def test_propose_hash_creates_pending_entry(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    entry = propose_hash("a" * 64, "test-label", source="manual")
    assert entry["status"] == "pending"
    assert entry["source"] == "manual"
    assert entry["reviewed_at"] is None


def test_propose_hash_duplicate_raises(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "first", source="manual")
    try:
        propose_hash("a" * 64, "second", source="auto")
        assert False, "expected HashExistsError"
    except HashExistsError:
        pass


def test_approve_hash_makes_it_visible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    entry = approve_hash("a" * 64)
    assert entry["status"] == "approved"
    assert entry["reviewed_at"] is not None
    assert check_hash("a" * 64) == "test-label"


def test_reject_hash_never_visible_to_check_hash(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    entry = reject_hash("a" * 64)
    assert entry["status"] == "rejected"
    assert check_hash("a" * 64) is None


def test_approve_unknown_hash_raises_not_found(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    try:
        approve_hash("a" * 64)
        assert False, "expected HashNotFoundError"
    except HashNotFoundError:
        pass


def test_approve_already_decided_hash_raises_not_pending(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "test-label", source="manual")
    approve_hash("a" * 64)
    try:
        approve_hash("a" * 64)
        assert False, "expected HashNotPendingError"
    except HashNotPendingError:
        pass


def test_list_hashes_returns_all_statuses(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [])
    propose_hash("a" * 64, "one", source="manual")
    propose_hash("b" * 64, "two", source="auto")
    approve_hash("a" * 64)
    entries = list_hashes()
    assert {e["hash"]: e["status"] for e in entries} == {"a" * 64: "approved", "b" * 64: "pending"}


def test_concurrent_propose_does_not_corrupt_file(tmp_path, monkeypatch):
    path = _seed(tmp_path, monkeypatch, [])
    hashes = [f"{i:064d}" for i in range(20)]

    def worker(h):
        propose_hash(h, "concurrent", source="manual")

    threads = [threading.Thread(target=worker, args=(h,)) for h in hashes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = json.loads(path.read_text())
    assert len(entries) == 20
    assert {e["hash"] for e in entries} == set(hashes)
