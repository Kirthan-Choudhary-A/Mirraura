import hashlib
import os
import threading

import pytest

from conftest import SEED_CORPUS, runtime_url_for_role
from corpus_lookup import (
    MAX_SAMPLE_BYTES,
    SampleExistsError,
    SampleNotFoundError,
    SampleNotPendingError,
    approve_sample,
    list_samples,
    load_known_bad,
    propose_sample,
    reject_sample,
)
from db import new_pool, run_migrations
import static_triage


@pytest.fixture
def pool():
    admin_url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    runtime_url = runtime_url_for_role(admin_url, "verdict_role", "verdict_test_pw")
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)
    yield p
    # Back to just the migration's seed rows, so later test files see the
    # same corpus regardless of run order.
    with p.connection() as conn:
        conn.execute(
            "DELETE FROM known_bad_samples WHERE NOT (content_hash = ANY(%s))",
            ([hashlib.sha256(c).hexdigest() for _, c in SEED_CORPUS],),
        )
    p.close()


def _unique(tag: str) -> bytes:
    # Random-ish, script-unlike content so an approved test entry can't
    # near-match some other test's input.
    return f"{tag}:{os.urandom(32).hex()}".encode()


def test_migration_seeds_approved_corpus(pool):
    assert sorted(load_known_bad(pool)) == sorted(SEED_CORPUS)


def test_load_known_bad_returns_only_approved(pool):
    pending = _unique("pending")
    rejected = _unique("rejected")
    propose_sample(pool, pending, "p", source="manual")
    propose_sample(pool, rejected, "r", source="manual")
    reject_sample(pool, hashlib.sha256(rejected).hexdigest())
    contents = [c for _, c in load_known_bad(pool)]
    assert pending not in contents and rejected not in contents


def test_approve_adds_sample_to_corpus(pool):
    content = _unique("approve")
    entry = propose_sample(pool, content, "new-sample", source="manual")
    assert entry["content_hash"] == hashlib.sha256(content).hexdigest()
    assert entry["status"] == "pending"
    approve_sample(pool, entry["content_hash"])
    assert ("new-sample", content) in load_known_bad(pool)


def test_list_samples_includes_preview_not_raw_content(pool):
    content = _unique("list")
    propose_sample(pool, content, "listed", source="manual")
    row = next(s for s in list_samples(pool) if s["label"] == "listed")
    assert row["preview"] == content.decode()
    assert row["size"] == len(content)
    assert "content" not in row


def test_propose_rejects_empty_and_oversized(pool):
    with pytest.raises(ValueError):
        propose_sample(pool, b"", "empty", source="manual")
    with pytest.raises(ValueError):
        propose_sample(pool, b"x" * (MAX_SAMPLE_BYTES + 1), "big", source="manual")


def test_propose_rejects_duplicate(pool):
    content = _unique("dup")
    propose_sample(pool, content, "a", source="manual")
    with pytest.raises(SampleExistsError):
        propose_sample(pool, content, "b", source="manual")


def test_decide_unknown_and_already_decided(pool):
    with pytest.raises(SampleNotFoundError):
        approve_sample(pool, "0" * 64)
    content_hash = propose_sample(pool, _unique("twice"), "t", source="manual")["content_hash"]
    approve_sample(pool, content_hash)
    with pytest.raises(SampleNotPendingError):
        reject_sample(pool, content_hash)


def test_concurrent_decisions_only_one_wins(pool):
    content_hash = propose_sample(pool, _unique("race"), "race", source="manual")["content_hash"]
    results = []

    def decide(fn):
        try:
            fn(pool, content_hash)
            results.append("ok")
        except SampleNotPendingError:
            results.append("not-pending")

    threads = [threading.Thread(target=decide, args=(f,)) for f in (approve_sample, reject_sample)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["not-pending", "ok"]


def test_static_triage_uses_db_corpus(pool):
    reasons = static_triage.run(SEED_CORPUS[1][1], pool)
    assert any("devtcp_reverse_shell" in r for r in reasons)


def test_static_triage_db_error_is_no_match_not_crash(pool, monkeypatch):
    def boom(_pool):
        raise RuntimeError("db down")

    monkeypatch.setattr(static_triage.corpus_lookup, "load_known_bad", boom)
    reasons = static_triage.run(SEED_CORPUS[1][1], pool)
    assert not any("similar" in r for r in reasons)  # YARA may still match, similarity must not
