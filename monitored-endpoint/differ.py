from typing import Dict, List

# ponytail: name-based exclusion of the poller's own toolchain (python3, ps, ss)
# so its own per-cycle subprocess spawns aren't misread as suspicious activity.
# Ceiling: an attacker-spawned python3/ps/ss inside the monitored container would
# also be silently excluded. Upgrade path: track the poller's own subprocess PID
# tree (e.g. via os.getpid()/psutil children) instead of matching by name, if
# that gap ever matters for a real deployment.
POLLER_OWN_PROCESSES = {"python3", "ps", "ss"}


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


def parse_dir_listing(names: list) -> set:
    return set(names)


def diff_snapshots(prev: dict, curr: dict) -> List[dict]:
    events: List[dict] = []
    prev_procs = prev.get("processes", {})
    curr_procs = curr.get("processes", {})
    for pid in sorted(set(curr_procs) - set(prev_procs)):
        name = curr_procs[pid]
        if name in POLLER_OWN_PROCESSES:
            continue
        events.append(
            {
                "event_type": "process_spawn",
                "process_ref": {"pid": int(pid), "name": name, "parent_pid": 0},
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

    prev_files = parse_dir_listing(prev.get("files", []))
    curr_files = parse_dir_listing(curr.get("files", []))
    for name in sorted(curr_files - prev_files):
        events.append(
            {
                "event_type": "file_write",
                "file_ref": {"path": f"/etc/{name}", "action": "write"},
            }
        )
    return events
