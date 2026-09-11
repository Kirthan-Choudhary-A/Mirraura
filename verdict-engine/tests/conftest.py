import os
import shutil
from pathlib import Path

# Point the verdict-engine's audit log and known-bad hash store at throwaway
# files for the whole test session, before app.py (or hash_lookup.py) is
# imported by any test module — otherwise they fall back to the hardcoded
# production paths and read/write real state.
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)

_TEST_KNOWN_BAD = Path(__file__).parent / "test_known_bad_hashes.json"
_SEED_KNOWN_BAD = Path(__file__).parent.parent / "known_bad_hashes.json"
shutil.copy(_SEED_KNOWN_BAD, _TEST_KNOWN_BAD)
os.environ["KNOWN_BAD_HASHES_PATH"] = str(_TEST_KNOWN_BAD)

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)


def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
    _TEST_KNOWN_BAD.unlink(missing_ok=True)
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
