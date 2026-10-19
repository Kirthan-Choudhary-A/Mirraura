import os
from pathlib import Path

# Point the verdict-engine's audit log at a throwaway file for the whole test
# session, before app.py is imported by any test module — otherwise it falls
# back to the hardcoded production path and reads/writes real state.
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)


def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
