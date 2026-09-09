import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

KNOWN_BAD_PATH = Path(
    os.getenv("KNOWN_BAD_HASHES_PATH", str(Path(__file__).parent / "known_bad_hashes.json"))
)

# ponytail: a single process-wide lock, not per-file — Mirraura runs the
# verdict-engine as one process with no multi-worker setup, so this is
# sufficient. Move to file locking (e.g. fcntl) only if that assumption
# changes.
_LOCK = threading.Lock()

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class HashExistsError(Exception):
    pass


class HashNotFoundError(Exception):
    pass


class HashNotPendingError(Exception):
    pass


def is_valid_hash(value: str) -> bool:
    return bool(_HASH_RE.fullmatch(value))


def _load_all() -> List[dict]:
    with open(KNOWN_BAD_PATH) as f:
        return json.load(f)


def _save_all(entries: List[dict]) -> None:
    with open(KNOWN_BAD_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def load_known_bad() -> Dict[str, str]:
    with _LOCK:
        return {e["hash"]: e["label"] for e in _load_all() if e.get("status") == "approved"}


def check_hash(sample_hash: str, known_bad: Optional[Dict[str, str]] = None) -> Optional[str]:
    known_bad = known_bad if known_bad is not None else load_known_bad()
    return known_bad.get(sample_hash)


def list_hashes() -> List[dict]:
    with _LOCK:
        return _load_all()


def propose_hash(sample_hash: str, label: str, source: str) -> dict:
    with _LOCK:
        entries = _load_all()
        if any(e["hash"] == sample_hash for e in entries):
            raise HashExistsError(sample_hash)
        entry = {
            "hash": sample_hash,
            "label": label,
            "status": "pending",
            "source": source,
            "proposed_at": datetime.now(timezone.utc).isoformat(),
            "reviewed_at": None,
        }
        entries.append(entry)
        _save_all(entries)
        return entry


def _decide(sample_hash: str, new_status: str) -> dict:
    with _LOCK:
        entries = _load_all()
        for e in entries:
            if e["hash"] == sample_hash:
                if e["status"] != "pending":
                    raise HashNotPendingError(sample_hash)
                e["status"] = new_status
                e["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                _save_all(entries)
                return e
        raise HashNotFoundError(sample_hash)


def approve_hash(sample_hash: str) -> dict:
    return _decide(sample_hash, "approved")


def reject_hash(sample_hash: str) -> dict:
    return _decide(sample_hash, "rejected")
