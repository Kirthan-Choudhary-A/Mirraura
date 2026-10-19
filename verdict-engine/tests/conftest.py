import os
from pathlib import Path

_TEST_EVENT_ARCHIVE = Path(__file__).parent / "test_event_archive.jsonl"
_TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
os.environ["EVENT_ARCHIVE_PATH"] = str(_TEST_EVENT_ARCHIVE)


def pytest_sessionfinish(session, exitstatus):
    _TEST_EVENT_ARCHIVE.unlink(missing_ok=True)
