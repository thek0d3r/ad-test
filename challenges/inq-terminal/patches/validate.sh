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
    if (exec 3<>/dev/tcp/"$IP"/9423; printf 'HELLO\n' >&3; head -1 <&3) \
            2>/dev/null | grep -q 'terminal/1'; then
        break
    fi
    sleep 1
done
"$PY" "$REPO/tests/smoke_checkers.py" inq-terminal "$IP"

echo "INQ Terminal image and native checker passed"
