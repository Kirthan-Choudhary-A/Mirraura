import base64
import os

from fastapi.testclient import TestClient

from app import app
import app as app_module

client = TestClient(app)

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_score_hash_hit_is_compromised():
    resp = client.post("/score", json={"sample_hash": EICAR_HASH, "events": []})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "Compromised"
    assert body["confidence"] == 1.0
    assert "EICAR-Test-File" in body["causal_chain"][0]


def test_score_hash_hit_archives_known_bad_match():
    verdict_id = client.post(
        "/score", json={"sample_hash": EICAR_HASH, "events": []}
    ).json()["verdict_id"]

    matches = [r for r in app_module.event_archive.all() if r["verdict_id"] == verdict_id]
    assert len(matches) == 1
    assert matches[0]["known_bad_match"] is True
    assert matches[0]["verdict_at_capture"] == "Compromised"


def test_score_no_events_is_inconclusive():
    resp = client.post("/score", json={"sample_hash": "f" * 64, "events": []})
    body = resp.json()
    assert body["verdict"] == "Inconclusive"


def test_score_timed_out_is_inconclusive_with_reason():
    resp = client.post(
        "/score",
        json={"sample_hash": "8" * 64, "events": [], "timed_out": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "Inconclusive"
    assert body["confidence"] == 0.0
    assert "execution timeout" in body["causal_chain"][0]


def test_score_odd_port_is_suspicious():
    events = [
        {
            "event_id": "e1",
            "device_id": "shadow-node",
            "event_type": "network_connect",
            "network_ref": {"dst_ip": "127.0.0.1", "dst_port": 31337, "protocol": "tcp"},
            "timestamp": "2026-09-07T00:00:00Z",
            "baseline_deviation_score": 0.0,
        }
    ]
    resp = client.post("/score", json={"sample_hash": "a" * 64, "events": events})
    body = resp.json()
    assert body["verdict"] == "Suspicious"
    assert body["confidence"] == 0.2


def test_verdict_list_and_get_roundtrip():
    resp = client.post("/score", json={"sample_hash": "b" * 64, "events": []})
    verdict_id = resp.json()["verdict_id"]

    listed = client.get("/verdicts").json()
    assert any(v["verdict_id"] == verdict_id for v in listed)

    single = client.get(f"/verdicts/{verdict_id}")
    assert single.status_code == 200
    assert single.json()["verdict_id"] == verdict_id

    missing = client.get("/verdicts/does-not-exist")
    assert missing.status_code == 404


def test_log_action_appends_to_audit_log():
    resp = client.post("/audit/action", json={"action": "isolated", "device_id": "monitored-endpoint"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"] == "isolated"
    assert body["device_id"] == "monitored-endpoint"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "isolated" and r.get("device_id") == "monitored-endpoint"
        for r in listed
    )


def test_log_action_records_actor():
    resp = client.post(
        "/audit/action",
        json={"action": "reconnected", "device_id": "monitored-endpoint", "actor": "alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "alice"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "reconnected" and r.get("actor") == "alice"
        for r in listed
    )


def _compromised_events():
    return [
        {
            "event_id": "e1",
            "device_id": "shadow-node",
            "event_type": "process_spawn",
            "process_ref": {"pid": 100, "name": "sh", "parent_pid": 1},
            "timestamp": "2026-09-09T00:00:00Z",
            "baseline_deviation_score": 0.0,
        },
        {
            "event_id": "e2",
            "device_id": "shadow-node",
            "event_type": "file_write",
            "file_ref": {"path": "/etc/passwd", "action": "write"},
            "timestamp": "2026-09-09T00:00:01Z",
            "baseline_deviation_score": 0.0,
        },
        {
            "event_id": "e3",
            "device_id": "shadow-node",
            "event_type": "network_connect",
            "network_ref": {"dst_ip": "127.0.0.1", "dst_port": 31337, "protocol": "tcp"},
            "timestamp": "2026-09-09T00:00:02Z",
            "baseline_deviation_score": 0.0,
        },
    ]


def test_behavioral_compromised_auto_proposes_pending_hash():
    sample_hash = "c" * 64
    resp = client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})
    assert resp.json()["verdict"] == "Compromised"

    hashes = client.get("/hashes").json()
    matches = [h for h in hashes if h["hash"] == sample_hash]
    assert len(matches) == 1
    assert matches[0]["status"] == "pending"
    assert matches[0]["source"] == "auto"


def test_repeated_compromised_verdict_does_not_duplicate_proposal():
    sample_hash = "d" * 64
    client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})
    client.post("/score", json={"sample_hash": sample_hash, "events": _compromised_events()})

    hashes = client.get("/hashes").json()
    matches = [h for h in hashes if h["hash"] == sample_hash]
    assert len(matches) == 1


def test_manual_hash_submission_then_approve_flow():
    sample_hash = "1" * 64
    resp = client.post("/hashes", json={"hash": sample_hash, "label": "manual-test"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    # not yet approved: does not affect /score
    score_resp = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp.json()["verdict"] == "Inconclusive"

    approve_resp = client.post(f"/hashes/{sample_hash}/approve", json={})
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    score_resp2 = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp2.json()["verdict"] == "Compromised"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "hash_approved" and r.get("hash") == sample_hash for r in listed
    )


def test_manual_hash_submission_reject_flow():
    sample_hash = "2" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "reject-test"})
    reject_resp = client.post(f"/hashes/{sample_hash}/reject", json={})
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "rejected"

    score_resp = client.post("/score", json={"sample_hash": sample_hash, "events": []})
    assert score_resp.json()["verdict"] == "Inconclusive"

    listed = client.get("/verdicts").json()
    assert any(
        r.get("action") == "hash_rejected" and r.get("hash") == sample_hash for r in listed
    )


def test_submit_invalid_hash_format_rejected():
    resp = client.post("/hashes", json={"hash": "not-a-hash", "label": "bad"})
    assert resp.status_code == 400


def test_submit_duplicate_hash_conflicts():
    sample_hash = "3" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "first"})
    resp = client.post("/hashes", json={"hash": sample_hash, "label": "second"})
    assert resp.status_code == 409


def test_approve_unknown_hash_returns_404():
    resp = client.post(f"/hashes/{'4' * 64}/approve", json={})
    assert resp.status_code == 404


def test_approve_already_decided_hash_returns_409():
    sample_hash = "5" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "x"})
    client.post(f"/hashes/{sample_hash}/approve", json={})
    resp = client.post(f"/hashes/{sample_hash}/approve", json={})
    assert resp.status_code == 409


def test_approve_hash_records_actor():
    sample_hash = "e" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "actor-test"})
    resp = client.post(f"/hashes/{sample_hash}/approve", json={"actor": "alice"})
    assert resp.status_code == 200
    listed = client.get("/verdicts").json()
    match = next(r for r in listed if r.get("action") == "hash_approved" and r.get("hash") == sample_hash)
    assert match["actor"] == "alice"


def test_score_writes_event_archive_entry():
    events = [
        {
            "event_id": "e1",
            "device_id": "shadow-node",
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0},
            "timestamp": "2026-09-11T00:00:00Z",
            "baseline_deviation_score": 0.0,
        }
    ]
    resp = client.post(
        "/score", json={"sample_hash": "6" * 64, "events": events, "source": "sample"}
    )
    verdict_id = resp.json()["verdict_id"]

    matches = [r for r in app_module.event_archive.all() if r["verdict_id"] == verdict_id]
    assert len(matches) == 1
    assert matches[0]["sample_hash"] == "6" * 64
    assert matches[0]["source"] == "sample"
    assert matches[0]["verdict_at_capture"] == "Suspicious"
    assert matches[0]["confidence_at_capture"] == 0.3
    assert matches[0]["known_bad_match"] is False
    assert matches[0]["events"][0]["event_id"] == "e1"


def test_score_records_actor_in_audit_log():
    resp = client.post(
        "/score",
        json={"sample_hash": "9" * 64, "events": [], "actor": "alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "alice"


def test_archive_write_failure_does_not_break_score(monkeypatch):
    def boom(record):
        raise OSError("disk full")

    monkeypatch.setattr(app_module.event_archive, "append", boom)
    resp = client.post("/score", json={"sample_hash": "7" * 64, "events": []})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "Inconclusive"


def test_verify_route_returns_chain_status():
    resp = client.get("/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert "intact" in body and "entries" in body and "broken_at" in body


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_triage_matches_seeded_corpus():
    data = b"#!/bin/bash\nexec 3<>/dev/tcp/127.0.0.1/31337 2>/dev/null || true\n"
    resp = client.post("/triage", json={"sample_content_b64": _b64(data)})
    assert resp.status_code == 200
    assert any("devtcp_reverse_shell" in m for m in resp.json()["matches"])


def test_corpus_submit_approve_then_triage_matches():
    content = f"corpus-route-test:{os.urandom(32).hex()}".encode()
    resp = client.post("/corpus", json={"content_b64": _b64(content), "label": "route-test"})
    assert resp.status_code == 200
    content_hash = resp.json()["content_hash"]

    assert client.post("/triage", json={"sample_content_b64": _b64(content)}).json()["matches"] == []
    pending = [s for s in client.get("/corpus").json() if s["content_hash"] == content_hash]
    assert pending[0]["status"] == "pending"

    approve = client.post(f"/corpus/{content_hash}/approve", json={"actor": "alice"})
    assert approve.status_code == 200
    matches = client.post("/triage", json={"sample_content_b64": _b64(content)}).json()["matches"]
    assert any("route-test" in m for m in matches)

    logged = [r for r in client.get("/verdicts").json() if r.get("action") == "corpus_sample_approved"]
    assert logged[-1]["hash"] == content_hash and logged[-1]["actor"] == "alice"


def test_corpus_submit_rejects_bad_input():
    assert client.post("/corpus", json={"content_b64": "not base64!!", "label": "x"}).status_code == 400
    assert client.post("/corpus", json={"content_b64": "", "label": "x"}).status_code == 400


def test_corpus_submit_duplicate_conflicts():
    body = {"content_b64": _b64(os.urandom(32)), "label": "dup"}
    client.post("/corpus", json=body)
    assert client.post("/corpus", json=body).status_code == 409


def test_corpus_decide_unknown_and_already_decided():
    assert client.post(f"/corpus/{'0' * 64}/reject", json={}).status_code == 404
    content_hash = client.post("/corpus", json={"content_b64": _b64(os.urandom(32)), "label": "r"}).json()["content_hash"]
    assert client.post(f"/corpus/{content_hash}/reject", json={}).status_code == 200
    assert client.post(f"/corpus/{content_hash}/approve", json={}).status_code == 409


def test_detection_method_known_bad_hash():
    resp = client.post("/score", json={"sample_hash": EICAR_HASH, "events": []})
    assert resp.json()["detection_method"] == "known_bad_hash"


def test_detection_method_known_bad_hash_wins_over_static_matches():
    resp = client.post(
        "/score", json={"sample_hash": EICAR_HASH, "events": [], "static_matches": ["YARA rule 'EICAR_Test_String' matched"]}
    )
    assert resp.json()["detection_method"] == "known_bad_hash"


def test_detection_method_static_triage():
    resp = client.post(
        "/score", json={"sample_hash": "e1" * 32, "events": [], "static_matches": ["YARA rule 'X' matched"]}
    )
    body = resp.json()
    assert body["verdict"] == "Compromised"
    assert body["detection_method"] == "static_triage"


def test_detection_method_dynamic_when_timed_out():
    resp = client.post("/score", json={"sample_hash": "e2" * 32, "events": [], "timed_out": True})
    assert resp.json()["detection_method"] == "dynamic"


def test_detection_method_dynamic_when_scored():
    resp = client.post("/score", json={"sample_hash": "e3" * 32, "events": []})
    assert resp.json()["detection_method"] == "dynamic"


def test_detection_method_is_stored_in_audit_log():
    verdict_id = client.post(
        "/score", json={"sample_hash": "e4" * 32, "events": [], "static_matches": ["x"]}
    ).json()["verdict_id"]
    assert client.get(f"/verdicts/{verdict_id}").json()["detection_method"] == "static_triage"
    assert client.get("/verify").json()["intact"] is True


def test_score_defaults_source_to_sample():
    resp = client.post("/score", json={"sample_hash": "e5" * 32, "events": []})
    assert resp.json()["source"] == "sample"


def test_score_persists_monitor_source():
    resp = client.post("/score", json={"sample_hash": "e6" * 32, "events": [], "source": "monitor"})
    assert resp.json()["source"] == "monitor"


def test_source_is_stored_in_audit_log():
    verdict_id = client.post(
        "/score", json={"sample_hash": "e7" * 32, "events": [], "source": "monitor"}
    ).json()["verdict_id"]
    assert client.get(f"/verdicts/{verdict_id}").json()["source"] == "monitor"
