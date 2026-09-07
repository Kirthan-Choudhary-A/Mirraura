import os
from pathlib import Path

# Point the verdict-engine's audit log at a throwaway file for the whole test
# session, before app.py is imported by any test module — otherwise it falls
# back to the hardcoded /data/audit_log.jsonl and writes real state.
_TEST_AUDIT_LOG = Path(__file__).parent / "test_audit_log.jsonl"
_TEST_AUDIT_LOG.unlink(missing_ok=True)
os.environ["AUDIT_LOG_PATH"] = str(_TEST_AUDIT_LOG)


def pytest_sessionfinish(session, exitstatus):
    _TEST_AUDIT_LOG.unlink(missing_ok=True)
