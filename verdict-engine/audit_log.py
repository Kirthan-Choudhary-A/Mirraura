import hashlib
import json
from typing import List, Optional

GENESIS_HASH = "0" * 64

# A fixed, arbitrary key for the Postgres advisory lock that serializes
# appends -- any two processes passing the same integer to pg_advisory_xact_lock
# contend for the same lock, which is all that's needed here (one logical
# resource: "the end of this audit log").
_APPEND_LOCK_KEY = 847_362_910


class AuditLog:
    def __init__(self, pool):
        self.pool = pool

    def _last_hash(self, conn) -> str:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def append(self, verdict: dict) -> dict:
        with self.pool.connection() as conn:
            with conn.transaction():
                # Holds until this transaction commits or rolls back, so a
                # second concurrent append can't read the same "last hash"
                # as this one and silently fork the chain.
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_APPEND_LOCK_KEY,))
                prev_hash = self._last_hash(conn)
                entry = {**verdict, "prev_log_hash": prev_hash}
                entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
                conn.execute(
                    "INSERT INTO audit_log (entry_hash, prev_log_hash, data) VALUES (%s, %s, %s)",
                    (entry_hash, prev_hash, json.dumps(entry)),
                )
        return {**entry, "entry_hash": entry_hash}

    def all(self) -> List[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT data, entry_hash FROM audit_log ORDER BY id").fetchall()
        return [{**row[0], "entry_hash": row[1]} for row in rows]

    def get(self, verdict_id: str) -> Optional[dict]:
        for record in self.all():
            if record.get("verdict_id") == verdict_id:
                return record
        return None

    def verify_chain_detail(self) -> dict:
        prev_hash = GENESIS_HASH
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT data, entry_hash FROM audit_log ORDER BY id").fetchall()
        for i, (data, stored_entry_hash) in enumerate(rows):
            if data.get("prev_log_hash") != prev_hash:
                return {"intact": False, "entries": len(rows), "broken_at": i + 1}
            expected = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
            if expected != stored_entry_hash:
                return {"intact": False, "entries": len(rows), "broken_at": i + 1}
            prev_hash = stored_entry_hash
        return {"intact": True, "entries": len(rows), "broken_at": None}

    def verify_chain(self) -> bool:
        return self.verify_chain_detail()["intact"]
