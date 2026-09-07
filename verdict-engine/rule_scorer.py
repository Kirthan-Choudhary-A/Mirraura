from typing import List, Tuple

from schemas import Event

RULE_WEIGHTS = {
    "child_process": 0.3,
    "sensitive_write": 0.25,
    "odd_port": 0.2,
    "rapid_file_changes": 0.25,
}
SENSITIVE_PREFIXES = ("/etc/", "/bin/", "/usr/", "/boot/", "/sbin/")
STANDARD_PORTS = {80, 443}
RAPID_FILE_CHANGE_THRESHOLD = 5


def score_events(events: List[Event]) -> Tuple[float, List[str]]:
    confidence = 0.0
    chain: List[str] = []

    spawns = [e for e in events if e.event_type == "process_spawn" and e.process_ref]
    if spawns:
        confidence += RULE_WEIGHTS["child_process"]
        p = spawns[0].process_ref
        chain.append(f"spawned child process '{p.name}' (pid {p.pid})")

    sensitive = [
        e
        for e in events
        if e.event_type == "file_write"
        and e.file_ref
        and e.file_ref.path.startswith(SENSITIVE_PREFIXES)
    ]
    if sensitive:
        confidence += RULE_WEIGHTS["sensitive_write"]
        chain.append(f"wrote to sensitive path '{sensitive[0].file_ref.path}'")

    odd_conns = [
        e
        for e in events
        if e.event_type == "network_connect"
        and e.network_ref
        and e.network_ref.dst_port not in STANDARD_PORTS
    ]
    if odd_conns:
        confidence += RULE_WEIGHTS["odd_port"]
        n = odd_conns[0].network_ref
        chain.append(f"connected to non-standard port {n.dst_port} ({n.dst_ip})")

    file_changes = [e for e in events if e.event_type in ("file_write", "file_delete")]
    if len(file_changes) > RAPID_FILE_CHANGE_THRESHOLD:
        confidence += RULE_WEIGHTS["rapid_file_changes"]
        chain.append(f"modified {len(file_changes)} files rapidly")

    return min(confidence, 1.0), chain


def verdict_from_score(confidence: float, chain: List[str], had_telemetry: bool) -> str:
    if not had_telemetry:
        return "Inconclusive"
    if confidence == 0.0:
        return "Normal"
    if confidence < 0.6:
        return "Suspicious"
    return "Compromised"
