from typing import List, Literal, Optional

from pydantic import BaseModel


class ProcessRef(BaseModel):
    pid: int
    name: str
    parent_pid: int = 0


class NetworkRef(BaseModel):
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"


class FileRef(BaseModel):
    path: str
    action: Literal["write", "delete", "create"]


class Event(BaseModel):
    event_id: str
    device_id: str
    event_type: Literal[
        "process_spawn", "file_write", "file_delete", "network_connect"
    ]
    process_ref: Optional[ProcessRef] = None
    network_ref: Optional[NetworkRef] = None
    file_ref: Optional[FileRef] = None
    timestamp: str
    baseline_deviation_score: float = 0.0


class Verdict(BaseModel):
    verdict_id: str
    sample_hash: str
    verdict: Literal["Normal", "Suspicious", "Compromised", "Inconclusive"]
    confidence: float
    causal_chain: List[str]
    timestamp: str
    prev_log_hash: str
