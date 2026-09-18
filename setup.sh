#!/bin/bash
# setup.sh — run once after cloning, or after pulling changes to shadow-image/sensor/
set -e

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi
if [ -z "$MIRRAURA_ADMIN_PASSWORD" ] || [ "${#MIRRAURA_ADMIN_PASSWORD}" -lt 12 ]; then
  echo "MIRRAURA_ADMIN_PASSWORD must be set in .env and at least 12 characters." >&2
  exit 1
fi

docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
docker compose up --build
