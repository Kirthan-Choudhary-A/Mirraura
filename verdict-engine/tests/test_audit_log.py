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


def test_verify_chain_detail_reports_intact_with_entry_count(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})
    result = log.verify_chain_detail()
    assert result == {"intact": True, "entries": 2, "broken_at": None}


def test_verify_chain_detail_reports_broken_entry_one_indexed(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})
    # Tamper the first line's stored hash, matching however the existing
    # "reports False when tampered" test corrupts a line — read that test
    # and reuse the same tampering technique for consistency.
    lines = log_path.read_text().splitlines()
    import json
    tampered = json.loads(lines[0])
    tampered["entry_hash"] = "0" * 64
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")

    result = AuditLog(log_path).verify_chain_detail()
    assert result["intact"] is False
    assert result["entries"] == 2
    assert result["broken_at"] == 1
