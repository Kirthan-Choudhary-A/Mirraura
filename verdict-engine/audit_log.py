import hashlib
import json
from pathlib import Path
from typing import List, Optional

GENESIS_HASH = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def _read_lines(self) -> List[str]:
        with open(self.path) as f:
            return [line for line in f.read().splitlines() if line.strip()]

    def _last_hash(self) -> str:
        lines = self._read_lines()
        if not lines:
            return GENESIS_HASH
        return json.loads(lines[-1])["entry_hash"]

    def append(self, verdict: dict) -> dict:
        prev_hash = self._last_hash()
        entry = {**verdict, "prev_log_hash": prev_hash}
        entry_hash = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        record = {**entry, "entry_hash": entry_hash}
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def all(self) -> List[dict]:
        return [json.loads(line) for line in self._read_lines()]

    def get(self, verdict_id: str) -> Optional[dict]:
        for record in self.all():
            if record.get("verdict_id") == verdict_id:
                return record
        return None

    def verify_chain(self) -> bool:
        prev_hash = GENESIS_HASH
        for record in self.all():
            record = dict(record)
            stored_entry_hash = record.pop("entry_hash", None)
            if record.get("prev_log_hash") != prev_hash:
                return False
            expected = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()
            ).hexdigest()
            if expected != stored_entry_hash:
                return False
            prev_hash = stored_entry_hash
        return True
