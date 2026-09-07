import json

from audit_log import AuditLog


def test_append_and_read_back(tmp_path):
    log = AuditLog(tmp_path / "audit_log.jsonl")
    record = log.append({"verdict_id": "v1", "verdict": "Normal"})
    assert record["prev_log_hash"] == "0" * 64
    assert "entry_hash" in record
    assert log.get("v1")["verdict_id"] == "v1"


def test_chain_links_entries(tmp_path):
    log = AuditLog(tmp_path / "audit_log.jsonl")
    r1 = log.append({"verdict_id": "v1", "verdict": "Normal"})
    r2 = log.append({"verdict_id": "v2", "verdict": "Suspicious"})
    assert r2["prev_log_hash"] == r1["entry_hash"]
    assert log.verify_chain() is True


def test_tampering_breaks_chain(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    log = AuditLog(log_path)
    log.append({"verdict_id": "v1", "verdict": "Normal"})
    log.append({"verdict_id": "v2", "verdict": "Suspicious"})

    lines = log_path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["verdict"] = "Compromised"
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")

    assert AuditLog(log_path).verify_chain() is False
