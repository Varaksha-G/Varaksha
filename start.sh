#!/bin/bash
set -e

echo "[start.sh] Launching Python scoring sidecar on 127.0.0.1:8001..."
uvicorn services.api.sidecar:app --host 127.0.0.1 --port 8001 &
SIDECAR_PID=$!

echo "[start.sh] Waiting for sidecar to be ready..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8001/health > /dev/null 2>&1; then
    echo "[start.sh] Sidecar ready after ${i}s."
    break
  fi
  sleep 1
done

echo "[start.sh] Launching Rust gateway on port ${PORT:-8082}..."
./varaksha-gateway

kill $SIDECAR_PID 2>/dev/null || true
