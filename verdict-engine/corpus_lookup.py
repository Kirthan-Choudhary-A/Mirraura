import hashlib
from datetime import datetime, timezone
from typing import List, Tuple

import psycopg

# similarity.compare is O(n*m) per corpus entry and runs on every /triage,
# and POST /corpus is open to any logged-in user -- an unbounded sample would
# let one proposal slow down every future scan once approved.
MAX_SAMPLE_BYTES = 64 * 1024
_PREVIEW_CHARS = 200


class SampleExistsError(Exception):
    pass


class SampleNotFoundError(Exception):
    pass


class SampleNotPendingError(Exception):
    pass


def load_known_bad(pool) -> List[Tuple[str, bytes]]:
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT label, content FROM known_bad_samples WHERE status = 'approved'"
        ).fetchall()
    return [(row[0], bytes(row[1])) for row in rows]


def list_samples(pool) -> List[dict]:
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT content_hash, label, status, source, proposed_at, reviewed_at, content "
            "FROM known_bad_samples ORDER BY proposed_at"
        ).fetchall()
    return [
        {
            "content_hash": r[0],
            "label": r[1],
            "status": r[2],
            "source": r[3],
            "proposed_at": r[4].isoformat(),
            "reviewed_at": r[5].isoformat() if r[5] else None,
            "size": len(r[6]),
            # Text preview so an admin can see what they're approving.
            "preview": bytes(r[6][:_PREVIEW_CHARS]).decode(errors="replace"),
        }
        for r in rows
    ]


def propose_sample(pool, content: bytes, label: str, source: str) -> dict:
    if not content:
        raise ValueError("sample is empty")
    if len(content) > MAX_SAMPLE_BYTES:
        raise ValueError(f"sample is {len(content)} bytes, max is {MAX_SAMPLE_BYTES}")
    content_hash = hashlib.sha256(content).hexdigest()
    now = datetime.now(timezone.utc)
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO known_bad_samples (content_hash, content, label, status, source, proposed_at) "
                "VALUES (%s, %s, %s, 'pending', %s, %s)",
                (content_hash, content, label, source, now),
            )
    except psycopg.errors.UniqueViolation as e:
        raise SampleExistsError(content_hash) from e
    return {
        "content_hash": content_hash,
        "label": label,
        "status": "pending",
        "source": source,
        "proposed_at": now.isoformat(),
        "reviewed_at": None,
    }


def _decide(pool, content_hash: str, new_status: str) -> dict:
    now = datetime.now(timezone.utc)
    with pool.connection() as conn:
        with conn.transaction():
            # Same FOR UPDATE serialization as hash_lookup._decide.
            row = conn.execute(
                "SELECT status, label FROM known_bad_samples WHERE content_hash = %s FOR UPDATE",
                (content_hash,),
            ).fetchone()
            if row is None:
                raise SampleNotFoundError(content_hash)
            status, label = row
            if status != "pending":
                raise SampleNotPendingError(content_hash)
            conn.execute(
                "UPDATE known_bad_samples SET status = %s, reviewed_at = %s WHERE content_hash = %s",
                (new_status, now, content_hash),
            )
    return {
        "content_hash": content_hash,
        "label": label,
        "status": new_status,
        "reviewed_at": now.isoformat(),
    }


def approve_sample(pool, content_hash: str) -> dict:
    return _decide(pool, content_hash, "approved")


def reject_sample(pool, content_hash: str) -> dict:
    return _decide(pool, content_hash, "rejected")
