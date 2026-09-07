#!/bin/bash
# setup.sh — run once after cloning, or after pulling changes to shadow-image/sensor/
set -e
docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
docker compose up --build
