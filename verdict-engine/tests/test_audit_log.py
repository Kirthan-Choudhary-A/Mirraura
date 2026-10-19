import os
import threading

import psycopg
import pytest

from audit_log import AuditLog
from db import new_pool, run_migrations

GENESIS_HASH = "0" * 64


@pytest.fixture
def admin_url():
    url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    return url


@pytest.fixture
def pool(admin_url):
    runtime_url = "postgres://verdict_role:verdict_test_pw@localhost:5432/mirraura"
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)
    yield p
    p.close()
    # verdict_role has no DELETE grant on audit_log (that's the point of this
    # task), so cleanup between tests has to go through the admin connection,
    # not the app-scoped pool above. RESTART IDENTITY resets the id sequence
    # too, so each test's first row is id=1, matching the "WHERE id = 1"
    # tampering tests below.
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("TRUNCATE audit_log RESTART IDENTITY")


def test_append_and_read_back(pool):
    log = AuditLog(pool)
    record = log.append({"verdict_id": "v1", "verdict": "Normal"})
    assert record["prev_log_hash"] == GENESIS_HASH
    assert "entry_hash" in record
    assert log.get("v1")["verdict_id"] == "v1"


def test_chain_links_entries(pool):
    log = AuditLog(pool)
    r1 = log.append({"verdict_id": "v1", "verdict": "Normal"})
    r2 = log.append({"verdict_id": "v2", "verdict": "Suspicious"})
    assert r2["prev_log_hash"] == r1["entry_hash"]
    assert log.verify_chain() is True


def test_concurrent_appends_dont_duplicate_prev_hash(pool):
    log = AuditLog(pool)

    def do_append(i):
        log.append({"verdict_id": f"v{i}"})

    threads = [threading.Thread(target=do_append, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert log.verify_chain() is True
    assert log.verify_chain_detail()["entries"] == 10


def test_app_role_cannot_update_audit_log(admin_url, pool):
    log = AuditLog(pool)
    log.append({"verdict_id": "v1", "verdict": "Normal"})

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with pool.connection() as conn:
            conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")
            conn.commit()


def test_superuser_tampering_is_still_detected(admin_url, pool):
    # Even though the app role can't tamper (previous test), prove the chain
    # math itself still catches it if someone with elevated access does --
    # the hash-chain property, not just the permission grant, is what makes
    # this tamper-evident end to end.
    log = AuditLog(pool)
    log.append({"verdict_id": "v1", "verdict": "Normal"})
    log.append({"verdict_id": "v2", "verdict": "Suspicious"})

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")

    assert AuditLog(pool).verify_chain() is False


def test_verify_chain_detail_reports_broken_entry_one_indexed(admin_url, pool):
    log = AuditLog(pool)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")

    result = AuditLog(pool).verify_chain_detail()
    assert result["intact"] is False
    assert result["entries"] == 2
    assert result["broken_at"] == 1
