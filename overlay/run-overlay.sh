#!/usr/bin/env bash
# Mirraura desktop download overlay.
# Run AFTER the Docker stack is up (./setup.sh or docker compose up --build).
# Needs a graphical Linux session; see README.md "Desktop download overlay".
set -euo pipefail
cd "$(dirname "$0")"

if command -v python3 >/dev/null; then
  PY=python3
else
  echo "python3 is required" >&2
  exit 1
fi

# Prefer the distro PyQt5 package if present; pip install the rest.
if ! "$PY" -c "import PyQt5" 2>/dev/null; then
  "$PY" -m pip install --user -r requirements.txt
fi

exec "$PY" overlay.py "$@"
