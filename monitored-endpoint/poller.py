import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from differ import diff_snapshots, parse_ps_output, parse_ss_output

STATE_PATH = Path("/var/run/poller_state.json")
DEVICE_ID = "monitored-endpoint"


def snapshot_dir(path: str = "/etc") -> list:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def capture_snapshot() -> dict:
    ps_out = subprocess.run(
        ["ps", "-eo", "pid,comm"], capture_output=True, text=True
    ).stdout
    ss_out = subprocess.run(["ss", "-tn"], capture_output=True, text=True).stdout
    return {
        "processes": parse_ps_output(ps_out),
        "connections": parse_ss_output(ss_out),
        "files": snapshot_dir(),
    }


def load_previous() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"processes": {}, "connections": {}}


def save_current(snapshot: dict) -> None:
    STATE_PATH.write_text(json.dumps(snapshot))


def main() -> None:
    prev = load_previous()
    curr = capture_snapshot()
    raw_events = diff_snapshots(prev, curr)
    save_current(curr)

    for raw in raw_events:
        event = {
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_deviation_score": 0.0,
            **raw,
        }
        print(json.dumps(event), flush=True)


if __name__ == "__main__":
    main()
