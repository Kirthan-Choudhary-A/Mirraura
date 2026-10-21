#!/bin/bash
exec 3<>/dev/tcp/127.0.0.1/31337 2>/dev/null || true
