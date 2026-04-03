#!/bin/bash
# Hello Agent — install script
# Called once during birth, runs in the agent's data/ directory.

set -e

echo "[hello-agent] Installing..."
echo "  Agent: ${CLAWID_AGENT_NAME:-unknown}"
echo "  ID:    ${CLAWID_AGENT_ID:-unknown}"
echo "  Dir:   $(pwd)"

# Create a state file so the agent can track uptime
echo "0" > heartbeat_count.txt
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > installed_at.txt

# Write a small HTTP health responder (nc-based, no deps)
cat > health-server.sh << 'HEALTH_EOF'
#!/bin/bash
# Tiny HTTP health endpoint on $HEALTH_PORT
PORT=${HEALTH_PORT:-0}
if [ "$PORT" = "0" ]; then exit 0; fi

while true; do
  UPTIME=$(cat /tmp/hello-agent-heartbeats.txt 2>/dev/null || echo "0")
  RESPONSE="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\":\"healthy\",\"heartbeats\":${UPTIME}}"
  echo -e "$RESPONSE" | nc -l "$PORT" -w 1 > /dev/null 2>&1 || true
done
HEALTH_EOF
chmod +x health-server.sh

echo "[hello-agent] Install complete."
