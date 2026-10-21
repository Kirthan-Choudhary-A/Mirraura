import hashlib
import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest

from db import run_migrations

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)


def runtime_url_for_role(admin_url: str, role: str, password: str) -> str:
    """Swaps admin_url's role/password for the given test role, keeping its
    host/port/database. Tests used to hardcode "localhost:5432/mirraura" for
    the runtime connection even when MIRRAURA_TEST_DATABASE_URL pointed
    elsewhere, silently ignoring the env var for half of every test's
    connections and risking collision with a real dev stack on the same
    host/port/database.
    """
    parsed = urlparse(admin_url)
    netloc = f"{role}:{password}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


# app.py requires this at import time (fail-fast, matching production) --
# set it before any test module imports app, pointing at the same test
# Postgres every other Postgres-backed test in this suite uses. app.py no
# longer runs migrations itself (that's now the standalone migrate.py's job,
# so the admin credential never reaches the long-running app process), so
# this module -- loaded by pytest before any test module is collected --
# must apply them here instead, or app.py's own pool.wait() fails because
# verdict_role/the tables don't exist yet.
_test_admin_url = os.environ.get("MIRRAURA_TEST_DATABASE_URL")
if _test_admin_url:
    _runtime_url_for_role = runtime_url_for_role(_test_admin_url, "verdict_role", "verdict_test_pw")
    os.environ.setdefault("VERDICT_DATABASE_URL", _runtime_url_for_role)
    run_migrations(
        _test_admin_url,
        _runtime_url_for_role,
        Path(__file__).parent.parent / "migrations",
    )


# Mirrors migrations/0003's seed rows -- the approved similarity corpus a
# fresh install starts with.
SEED_CORPUS = [
    ("sensitive_write", b"#!/bin/bash\ntouch /etc/mirraura-test-marker\ncat /etc/hostname > /dev/null\n"),
    ("devtcp_reverse_shell", b"#!/bin/bash\nexec 3<>/dev/tcp/127.0.0.1/31337 2>/dev/null || true\n"),
]


@pytest.fixture(scope="session", autouse=True)
def _seed_known_bad_hashes():
    admin_url = os.environ.get("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        yield
        return
    with psycopg.connect(admin_url, autocommit=True) as conn:
        # Wipe leftovers from a previous run (test_app uses fixed hashes that would
        # otherwise 409 on the second run), then seed EICAR. audit_log too:
        # test_app.py assumes it starts empty, and only test_audit_log.py
        # truncates it, so a run that skips that file would leave entries
        # behind for the next run.
        conn.execute("TRUNCATE audit_log RESTART IDENTITY")
        conn.execute("DELETE FROM known_bad_hashes")
        conn.execute(
            "INSERT INTO known_bad_hashes (hash, label, status, source, proposed_at, reviewed_at) "
            "VALUES (%s, %s, 'approved', 'manual', now(), now()) ON CONFLICT (hash) DO NOTHING",
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File"),
        )
        # Same for the similarity corpus: back to just the migration's seeds.
        conn.execute(
            "DELETE FROM known_bad_samples WHERE NOT (content_hash = ANY(%s))",
            ([hashlib.sha256(c).hexdigest() for _, c in SEED_CORPUS],),
        )
    yield


def pytest_sessionfinish(session, exitstatus):
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
