#!/bin/bash
# Hello Agent — health check script
# Exit 0 = healthy, non-zero = unhealthy.
# Called periodically by the daemon supervisor.

NAME=${CLAWID_AGENT_NAME:-hello-agent}
DATA=${CLAWID_DATA_DIR:-.}

# Check 1: status.json exists and was updated recently
STATUS_FILE="$DATA/status.json"
if [ ! -f "$STATUS_FILE" ]; then
  echo "UNHEALTHY: no status.json found"
  exit 1
fi

# Check 2: status.json was modified in the last 60 seconds
if [ "$(uname)" = "Darwin" ]; then
  # macOS: use stat -f
  MTIME=$(stat -f %m "$STATUS_FILE" 2>/dev/null || echo 0)
else
  # Linux: use stat -c
  MTIME=$(stat -c %Y "$STATUS_FILE" 2>/dev/null || echo 0)
fi
NOW=$(date +%s)
AGE=$((NOW - MTIME))

if [ "$AGE" -gt 60 ]; then
  echo "UNHEALTHY: status.json is ${AGE}s old (>60s)"
  exit 1
fi

# Check 3: heartbeat count is incrementing
HEARTBEATS=$(cat /tmp/hello-agent-heartbeats.txt 2>/dev/null || echo "0")
if [ "$HEARTBEATS" = "0" ]; then
  echo "UNHEALTHY: zero heartbeats"
  exit 1
fi

echo "HEALTHY: $HEARTBEATS heartbeats, status ${AGE}s old"
exit 0
