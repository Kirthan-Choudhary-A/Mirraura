import os
import subprocess
import tempfile


def run_strace(sample_path: str, timeout: int = 15) -> str:
    fd, trace_path = tempfile.mkstemp(suffix=".trace")
    os.close(fd)
    try:
        subprocess.run(
            [
                "strace",
                "-f",
                "-e",
                "trace=execve,openat,connect",
                "-o",
                trace_path,
                "bash",
                sample_path,
            ],
            timeout=timeout,
            capture_output=True,
        )
        with open(trace_path) as f:
            return f.read()
    finally:
        os.remove(trace_path)
