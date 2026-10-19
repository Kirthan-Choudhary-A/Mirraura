import os
from pathlib import Path

import psycopg
import pytest

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)

# app.py requires these at import time (fail-fast, matching production) --
# set them before any test module imports app, deriving from
# MIRRAURA_TEST_DATABASE_URL so app.py's migrations/pool point at the same
# test Postgres every other Postgres-backed test in this suite uses.
_test_admin_url = os.environ.get("MIRRAURA_TEST_DATABASE_URL")
if _test_admin_url:
    os.environ.setdefault("VERDICT_MIGRATIONS_DATABASE_URL", _test_admin_url)
    os.environ.setdefault(
        "VERDICT_DATABASE_URL",
        "postgres://verdict_role:verdict_test_pw@localhost:5432/mirraura",
    )


@pytest.fixture(scope="session", autouse=True)
def _seed_known_bad_hashes():
    admin_url = os.environ.get("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        yield
        return
    with psycopg.connect(admin_url, autocommit=True) as conn:
        # Wipe leftovers from a previous run (test_app uses fixed hashes that would
        # otherwise 409 on the second run), then seed EICAR.
        conn.execute("DELETE FROM known_bad_hashes")
        conn.execute(
            "INSERT INTO known_bad_hashes (hash, label, status, source, proposed_at, reviewed_at) "
            "VALUES (%s, %s, 'approved', 'manual', now(), now()) ON CONFLICT (hash) DO NOTHING",
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File"),
        )
    yield


def pytest_sessionfinish(session, exitstatus):
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
