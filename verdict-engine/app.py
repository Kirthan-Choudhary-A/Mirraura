import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from audit_log import AuditLog
from event_archive import EventArchive
from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    propose_hash,
    reject_hash,
)
from rule_scorer import score_events, verdict_from_score
from schemas import Event, Verdict

app = FastAPI()
audit_log = AuditLog(Path(os.getenv("AUDIT_LOG_PATH", "/data/audit_log.jsonl")))
event_archive = EventArchive(Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")))
logger = logging.getLogger(__name__)


class ScoreRequest(BaseModel):
    sample_hash: str
    sample_filename: str = ""
    timed_out: bool = False
    actor: str = ""
    events: List[Event] = []
    # "sample" = uploaded file (sample_hash is a real file identity, eligible for
    # auto-propose); "monitor" = continuous-monitoring event batch (the hash is of
    # a JSON event array, would never match a future upload).
    source: str = "sample"


class ActionRequest(BaseModel):
    action: str
    device_id: str
    actor: str = ""


class HashSubmitRequest(BaseModel):
    hash: str
    label: str


class HashDecisionRequest(BaseModel):
    actor: str = ""


def _strip_entry_hash(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != "entry_hash"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/score", response_model=Verdict)
def score(req: ScoreRequest):
    verdict_id = str(uuid.uuid4())
    known_bad_label = check_hash(req.sample_hash)
    if known_bad_label:
        verdict, confidence, chain = (
            "Compromised",
            1.0,
            [f"sample hash matches known-bad entry '{known_bad_label}'"],
        )
    elif req.timed_out:
        verdict, confidence, chain = (
            "Inconclusive",
            0.0,
            ["sample detonation aborted: sensor exceeded its execution timeout"],
        )
    else:
        confidence, chain = score_events(req.events)
        verdict = verdict_from_score(confidence, chain, had_telemetry=len(req.events) > 0)
        if verdict == "Compromised" and req.source == "sample":
            try:
                propose_hash(
                    req.sample_hash,
                    f"auto-proposed from verdict {verdict_id}",
                    source="auto",
                )
            except HashExistsError:
                pass
            except Exception:
                logger.warning(
                    "failed to auto-propose hash for verdict %s", verdict_id, exc_info=True
                )

    record = {
        "verdict_id": verdict_id,
        "sample_hash": req.sample_hash,
        "sample_filename": req.sample_filename,
        "actor": req.actor,
        "verdict": verdict,
        "confidence": confidence,
        "causal_chain": chain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    stored = audit_log.append(record)

    try:
        event_archive.append(
            {
                "verdict_id": verdict_id,
                "sample_hash": req.sample_hash,
                "sample_filename": req.sample_filename,
                "source": req.source,
                "events": [e.model_dump() for e in req.events],
                "verdict_at_capture": verdict,
                "confidence_at_capture": confidence,
                "known_bad_match": bool(known_bad_label),
                "timed_out": req.timed_out,
                "timestamp": record["timestamp"],
            }
        )
    except Exception:
        logger.warning(
            "failed to archive events for verdict %s", verdict_id, exc_info=True
        )

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
        "actor": req.actor,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return _strip_entry_hash(audit_log.append(record))


@app.get("/hashes")
def list_hashes_route():
    return list_hashes()


@app.post("/hashes")
def submit_hash_route(req: HashSubmitRequest):
    if not is_valid_hash(req.hash):
        raise HTTPException(status_code=400, detail="hash must be 64 lowercase hex characters")
    try:
        return propose_hash(req.hash, req.label, source="manual")
    except HashExistsError:
        raise HTTPException(status_code=409, detail="hash already exists")


@app.post("/hashes/{hash}/approve")
def approve_hash_route(hash: str, req: HashDecisionRequest):
    try:
        entry = approve_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_approved",
            "hash": entry["hash"],
            "label": entry["label"],
            "actor": req.actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry


@app.post("/hashes/{hash}/reject")
def reject_hash_route(hash: str, req: HashDecisionRequest):
    try:
        entry = reject_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_rejected",
            "hash": entry["hash"],
            "label": entry["label"],
            "actor": req.actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry
