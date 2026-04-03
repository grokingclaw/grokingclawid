#!/bin/bash
# Hello Agent — run script
# Executed by the daemon supervisor. Environment variables injected:
#   CLAWID_AGENT_NAME   — agent name
#   CLAWID_AGENT_ID     — agent UUID
#   CLAWID_DATA_DIR     — path to agent's data/ directory
#   CLAWID_PROXY_PORT   — sidecar proxy port (if running)
#   CLAWID_PROXY_URL    — http://127.0.0.1:$CLAWID_PROXY_PORT

set -e

INTERVAL=${HELLO_INTERVAL:-10}
NAME=${CLAWID_AGENT_NAME:-hello-agent}
ID=${CLAWID_AGENT_ID:-unknown}
DATA=${CLAWID_DATA_DIR:-.}
COUNT=0

echo "══════════════════════════════════════════════"
echo "  🤖 Hello Agent started"
echo "  Name:    $NAME"
echo "  ID:      $ID"
echo "  Proxy:   ${CLAWID_PROXY_URL:-none}"
echo "  Data:    $DATA"
echo "  Interval: ${INTERVAL}s"
echo "══════════════════════════════════════════════"

# Trap SIGTERM for graceful shutdown
trap 'echo "[$(date -u +%H:%M:%S)] Agent $NAME shutting down (heartbeats: $COUNT)"; exit 0' SIGTERM SIGINT

while true; do
  COUNT=$((COUNT + 1))
  echo "$COUNT" > /tmp/hello-agent-heartbeats.txt
  
  TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "[$TIMESTAMP] heartbeat #$COUNT | agent=$NAME pid=$$"
  
  # Write status to data dir for inspection
  cat > "$DATA/status.json" 2>/dev/null << EOF || true
{
  "agent": "$NAME",
  "id": "$ID",
  "pid": $$,
  "heartbeats": $COUNT,
  "proxy_port": "${CLAWID_PROXY_PORT:-null}",
  "timestamp": "$TIMESTAMP"
}
EOF
  
  sleep "$INTERVAL" &
  wait $!
done
