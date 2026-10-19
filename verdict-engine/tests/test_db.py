import os
import re
from pathlib import Path

import psycopg
import pytest

from db import new_pool, run_migrations


def _test_admin_url():
    url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    return url


def test_run_migrations_applies_in_order_and_is_idempotent(tmp_path):
    admin_url = _test_admin_url()
    runtime_url = "postgres://db_test_role_py:db_test_pw_py@localhost:5432/mirraura"
    (tmp_path / "0001_role_py.sql").write_text(
        """
DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS db_test_table_py (id INT PRIMARY KEY);
GRANT SELECT, INSERT ON db_test_table_py TO {{ROLE_NAME}};
"""
    )

    run_migrations(admin_url, runtime_url, tmp_path)
    run_migrations(admin_url, runtime_url, tmp_path)  # idempotent re-run

    with psycopg.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM schema_migrations WHERE version = %s", ("0001_role_py.sql",))
            assert cur.fetchone()[0] == 1
            cur.execute("DROP TABLE IF EXISTS db_test_table_py; DROP ROLE IF EXISTS db_test_role_py; DELETE FROM schema_migrations WHERE version = '0001_role_py.sql';")
            conn.commit()


def test_new_pool_fails_fast_on_bad_url():
    with pytest.raises(Exception):
        pool = new_pool("postgres://nope:nope@127.0.0.1:1/doesnotexist")
        pool.connection().__enter__()
