import os
import threading

import pytest

import hash_lookup
from db import new_pool, run_migrations
from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    load_known_bad,
    propose_hash,
    reject_hash,
)

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def pool():
    admin_url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    runtime_url = "postgres://verdict_role:verdict_test_pw@localhost:5432/mirraura"
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)
    propose_hash(p, EICAR_HASH, "EICAR-Test-File", source="manual")
    approve_hash(p, EICAR_HASH)
    yield p
    with p.connection() as conn:
        conn.execute("DELETE FROM known_bad_hashes")
        conn.commit()
    p.close()


def test_known_bad_hash_returns_label(pool):
    assert check_hash(pool, EICAR_HASH) == "EICAR-Test-File"


def test_unknown_hash_returns_none(pool):
    assert check_hash(pool, "0" * 64) is None


def test_propose_hash_rejects_invalid_hash(pool):
    with pytest.raises(ValueError):
        propose_hash(pool, "not-a-hash", "label", source="manual")


def test_propose_hash_rejects_duplicate(pool):
    propose_hash(pool, "1" * 64, "label", source="manual")
    with pytest.raises(HashExistsError):
        propose_hash(pool, "1" * 64, "label", source="manual")


def test_approve_hash_rejects_unknown_hash(pool):
    with pytest.raises(HashNotFoundError):
        approve_hash(pool, "2" * 64)


def test_approve_hash_rejects_already_decided_hash(pool):
    with pytest.raises(HashNotPendingError):
        approve_hash(pool, EICAR_HASH)  # already approved by the fixture


def test_concurrent_decisions_on_same_hash_dont_corrupt_state(pool):
    propose_hash(pool, "3" * 64, "race-test", source="manual")
    results = []

    def decide():
        try:
            approve_hash(pool, "3" * 64)
            results.append("approved")
        except HashNotPendingError:
            results.append("already-decided")

    threads = [threading.Thread(target=decide) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("approved") == 1
    assert results.count("already-decided") == 4
    entries = [e for e in list_hashes(pool) if e["hash"] == "3" * 64]
    assert len(entries) == 1
    assert entries[0]["status"] == "approved"
