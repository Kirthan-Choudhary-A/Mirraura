import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psycopg

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class HashExistsError(Exception):
    pass


class HashNotFoundError(Exception):
    pass


class HashNotPendingError(Exception):
    pass


def is_valid_hash(value: str) -> bool:
    return bool(_HASH_RE.fullmatch(value))


def load_known_bad(pool) -> Dict[str, str]:
    with pool.connection() as conn:
        rows = conn.execute("SELECT hash, label FROM known_bad_hashes WHERE status = 'approved'").fetchall()
    return {row[0]: row[1] for row in rows}


def check_hash(pool, sample_hash: str) -> Optional[str]:
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT label FROM known_bad_hashes WHERE hash = %s AND status = 'approved'",
            (sample_hash,),
        ).fetchone()
    return row[0] if row else None


def list_hashes(pool) -> List[dict]:
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT hash, label, status, source, proposed_at, reviewed_at FROM known_bad_hashes ORDER BY proposed_at"
        ).fetchall()
    return [
        {
            "hash": r[0],
            "label": r[1],
            "status": r[2],
            "source": r[3],
            "proposed_at": r[4].isoformat(),
            "reviewed_at": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]


def propose_hash(pool, sample_hash: str, label: str, source: str) -> dict:
    # Validated here, not in the route: /score's auto-propose path is
    # unauthenticated and would otherwise write arbitrary strings into the
    # known-bad store.
    if not is_valid_hash(sample_hash):
        raise ValueError(f"not a valid sha256 hex hash: {sample_hash[:80]!r}")
    now = datetime.now(timezone.utc)
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO known_bad_hashes (hash, label, status, source, proposed_at) "
                "VALUES (%s, %s, 'pending', %s, %s)",
                (sample_hash, label, source, now),
            )
    except psycopg.errors.UniqueViolation as e:
        raise HashExistsError(sample_hash) from e
    return {
        "hash": sample_hash,
        "label": label,
        "status": "pending",
        "source": source,
        "proposed_at": now.isoformat(),
        "reviewed_at": None,
    }


def _decide(pool, sample_hash: str, new_status: str) -> dict:
    now = datetime.now(timezone.utc)
    with pool.connection() as conn:
        with conn.transaction():
            # SELECT ... FOR UPDATE serializes concurrent decisions on the
            # same row -- the second caller blocks until the first commits,
            # then sees status already changed and raises instead of
            # double-applying.
            row = conn.execute(
                "SELECT status, label FROM known_bad_hashes WHERE hash = %s FOR UPDATE",
                (sample_hash,),
            ).fetchone()
            if row is None:
                raise HashNotFoundError(sample_hash)
            status, label = row
            if status != "pending":
                raise HashNotPendingError(sample_hash)
            conn.execute(
                "UPDATE known_bad_hashes SET status = %s, reviewed_at = %s WHERE hash = %s",
                (new_status, now, sample_hash),
            )
    return {
        "hash": sample_hash,
        "label": label,
        "status": new_status,
        "reviewed_at": now.isoformat(),
    }


def approve_hash(pool, sample_hash: str) -> dict:
    return _decide(pool, sample_hash, "approved")


def reject_hash(pool, sample_hash: str) -> dict:
    return _decide(pool, sample_hash, "rejected")
