#!/usr/bin/env python3
"""Hello Agent — optional Python companion.

This is an example of a more complex agent that could be launched by run.sh.
For the lab demo, run.sh uses pure bash. This file shows how a real agent
template might include Python/Node/etc code.
"""

import json
import os
import time
import sys

def main():
    name = os.environ.get("CLAWID_AGENT_NAME", "hello-agent")
    agent_id = os.environ.get("CLAWID_AGENT_ID", "unknown")
    proxy_url = os.environ.get("CLAWID_PROXY_URL", None)
    data_dir = os.environ.get("CLAWID_DATA_DIR", ".")
    
    print(f"Hello Agent (Python) started: {name} ({agent_id})")
    if proxy_url:
        print(f"  Proxy: {proxy_url}")
    
    count = 0
    while True:
        count += 1
        status = {
            "agent": name,
            "id": agent_id,
            "pid": os.getpid(),
            "heartbeats": count,
            "proxy_url": proxy_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        
        status_path = os.path.join(data_dir, "status.json")
        with open(status_path, "w") as f:
            json.dump(status, f, indent=2)
        
        print(f"[{status['timestamp']}] heartbeat #{count} | agent={name}")
        time.sleep(int(os.environ.get("HELLO_INTERVAL", "10")))

if __name__ == "__main__":
    main()
