#!/bin/bash
# One-click launcher: brings up the Mirraura stack and opens the dashboard.
# Docker itself and the interceptor daemon already auto-start on boot via
# systemd (both enabled with `systemctl enable`) -- this only needs to
# start the Compose stack, which has no systemd unit of its own.
set -e
cd "$(dirname "$0")"

echo "Starting Mirraura..."
docker compose up -d

echo "Waiting for the dashboard to come up..."
until curl -fs http://localhost:5173 > /dev/null 2>&1; do
  sleep 1
done

echo "Mirraura is up."
echo
if systemctl is-active --quiet mirraura-interceptor; then
  echo "Interceptor: watching for downloads automatically."
else
  echo "Interceptor is NOT running -- start it with:"
  echo "  sudo systemctl start mirraura-interceptor"
fi

xdg-open http://localhost:5173 >/dev/null 2>&1 &

echo
read -r -p "Press Enter to close this window..."
