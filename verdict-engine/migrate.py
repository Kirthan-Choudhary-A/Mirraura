"""One-shot migration runner: apply pending migrations, then exit.

Run via `python migrate.py`. This is the only place
VERDICT_MIGRATIONS_DATABASE_URL (the Postgres superuser) is used -- app.py
never reads it, so it's never present in the long-running app container's
environment.
"""
import os
import sys
from pathlib import Path

from db import run_migrations


def main() -> None:
    admin_url = os.getenv("VERDICT_MIGRATIONS_DATABASE_URL")
    runtime_url = os.getenv("VERDICT_DATABASE_URL")
    if not admin_url or not runtime_url:
        print("VERDICT_MIGRATIONS_DATABASE_URL and VERDICT_DATABASE_URL must both be set", file=sys.stderr)
        sys.exit(1)
    run_migrations(admin_url, runtime_url, Path(__file__).parent / "migrations")


if __name__ == "__main__":
    main()
