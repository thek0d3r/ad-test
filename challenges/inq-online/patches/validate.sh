#!/usr/bin/env bash
# Build the exact Compose service and exercise its native saarCTF checker.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/..
REPO=$HERE/../../..
IP=${1:-127.0.0.1}
PY=${PYTHON:-python3}

(cd "$ROOT/service" && docker compose up -d --build)
for _ in $(seq 1 60); do
    curl -fsS "http://$IP:9421/health" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "http://$IP:9421/health" >/dev/null
"$PY" "$REPO/tests/smoke_checkers.py" inq-online "$IP"

echo "INQ Online image and native checker passed"
