from typing import Dict, List


def parse_ps_output(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    lines = text.strip().splitlines()
    for line in lines[1:] if lines else []:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            pid, name = parts
            result[pid] = name
    return result


def parse_ss_output(text: str) -> Dict[str, dict]:
    result: Dict[str, dict] = {}
    lines = text.strip().splitlines()
    for line in lines[1:] if lines else []:
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        peer = parts[4]
        ip, sep, port = peer.rpartition(":")
        if not sep:
            continue
        key = f"{ip}:{port}"
        result[key] = {"dst_ip": ip, "dst_port": int(port), "protocol": "tcp"}
    return result


def diff_snapshots(prev: dict, curr: dict) -> List[dict]:
    events: List[dict] = []
    prev_procs = prev.get("processes", {})
    curr_procs = curr.get("processes", {})
    for pid in sorted(set(curr_procs) - set(prev_procs)):
        events.append(
            {
                "event_type": "process_spawn",
                "process_ref": {"pid": int(pid), "name": curr_procs[pid], "parent_pid": 0},
            }
        )

    prev_conns = prev.get("connections", {})
    curr_conns = curr.get("connections", {})
    for key in sorted(set(curr_conns) - set(prev_conns)):
        events.append(
            {
                "event_type": "network_connect",
                "network_ref": curr_conns[key],
            }
        )
    return events
