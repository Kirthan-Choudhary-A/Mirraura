from fastapi.testclient import TestClient

from app import app

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


def test_score_no_events_is_inconclusive():
    resp = client.post("/score", json={"sample_hash": "f" * 64, "events": []})
    body = resp.json()
    assert body["verdict"] == "Inconclusive"


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
