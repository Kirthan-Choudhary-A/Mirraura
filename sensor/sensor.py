import json
import sys
import time
import uuid
from datetime import datetime, timezone

from parser import parse_trace_log
from tracer import run_strace


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: sensor.py <path-to-sample>", file=sys.stderr)
        sys.exit(1)

    sample_path = sys.argv[1]
    device_id = "shadow-node"

    log_text = run_strace(sample_path)
    raw_events = parse_trace_log(log_text)

    for raw in raw_events:
        event = {
            "event_id": str(uuid.uuid4()),
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_deviation_score": 0.0,
            **raw,
        }
        print(json.dumps(event), flush=True)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
