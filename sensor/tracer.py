import os
import re
import subprocess
import tempfile

# strace's very first execve line is always the outer `bash sample_path`
# launch itself (how strace attaches to its traced command), not a spawn
# performed by the sample. Strip it so the sensor only reports genuine
# child-process spawns made by the sample.
ROOT_EXECVE_RE = re.compile(r'^\d+\s+execve\(')


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
            lines = f.readlines()
        for i, line in enumerate(lines):
            if ROOT_EXECVE_RE.match(line.strip()):
                del lines[i]
                break
        return "".join(lines)
    finally:
        os.remove(trace_path)
