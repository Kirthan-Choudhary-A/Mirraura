import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from audit_log import AuditLog
from hash_lookup import check_hash
from rule_scorer import score_events, verdict_from_score
from schemas import Event, Verdict

app = FastAPI()
audit_log = AuditLog(Path(os.getenv("AUDIT_LOG_PATH", "/data/audit_log.jsonl")))


class ScoreRequest(BaseModel):
    sample_hash: str
    events: List[Event] = []


class ActionRequest(BaseModel):
    action: str
    device_id: str


def _strip_entry_hash(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != "entry_hash"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/score", response_model=Verdict)
def score(req: ScoreRequest):
    known_bad_label = check_hash(req.sample_hash)
    if known_bad_label:
        verdict, confidence, chain = (
            "Compromised",
            1.0,
            [f"sample hash matches known-bad entry '{known_bad_label}'"],
        )
    else:
        confidence, chain = score_events(req.events)
        verdict = verdict_from_score(confidence, chain, had_telemetry=len(req.events) > 0)

    record = {
        "verdict_id": str(uuid.uuid4()),
        "sample_hash": req.sample_hash,
        "verdict": verdict,
        "confidence": confidence,
        "causal_chain": chain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    stored = audit_log.append(record)
    return Verdict(**_strip_entry_hash(stored))


@app.get("/verdicts")
def list_verdicts():
    return [_strip_entry_hash(r) for r in audit_log.all()]


@app.get("/verdicts/{verdict_id}")
def get_verdict(verdict_id: str):
    record = audit_log.get(verdict_id)
    if not record:
        raise HTTPException(status_code=404, detail="verdict not found")
    return _strip_entry_hash(record)


@app.post("/audit/action")
def log_action(req: ActionRequest):
    record = {
        "record_id": str(uuid.uuid4()),
        "device_id": req.device_id,
        "action": req.action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return _strip_entry_hash(audit_log.append(record))
