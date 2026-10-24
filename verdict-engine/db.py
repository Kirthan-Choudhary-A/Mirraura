from pathlib import Path
from urllib.parse import urlparse

import psycopg
from psycopg_pool import ConnectionPool


def new_pool(database_url: str) -> ConnectionPool:
    """Opens a connection pool against database_url and confirms it's reachable."""
    pool = ConnectionPool(database_url, open=True)
    pool.wait(timeout=5)
    return pool


# Session-level Postgres advisory lock held for the duration of
# run_migrations. Both backend and verdict-engine migrations apply against
# the same schema_migrations table in the same database, so without this,
# docker-compose starting both one-shot migrate services at once races on
# "CREATE TABLE IF NOT EXISTS schema_migrations" itself. Must match
# backend/db.go's migrationsLockKey.
MIGRATIONS_LOCK_KEY = 7418529630


def _role_credentials(database_url: str) -> tuple[str, str]:
    parsed = urlparse(database_url)
    if not parsed.username:
        raise ValueError("database url has no credentials")
    return parsed.username, parsed.password or ""


def run_migrations(admin_url: str, runtime_url: str, migrations_dir: Path) -> None:
    """Applies every *.sql file in migrations_dir, in filename order, not yet
    recorded in schema_migrations. admin_url must have CREATE/GRANT
    privileges; runtime_url's own role/password are substituted for
    {{ROLE_NAME}}/{{ROLE_PASSWORD}} placeholders so a migration can bootstrap
    that role.
    """
    role_name, role_password = _role_credentials(runtime_url)

    with psycopg.connect(admin_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (MIGRATIONS_LOCK_KEY,))
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        conn.commit()

        files = sorted(p for p in Path(migrations_dir).iterdir() if p.suffix == ".sql")
        for path in files:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = %s)",
                    (path.name,),
                )
                already_applied = cur.fetchone()[0]
            if already_applied:
                continue

            sql = path.read_text().replace("{{ROLE_NAME}}", role_name).replace(
                "{{ROLE_PASSWORD}}", role_password
            )
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
            conn.commit()
