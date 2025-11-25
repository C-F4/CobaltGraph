#!/usr/bin/env python3
"""
UltraThink - Modified for CobaltGraph integration
"""

import json
import time
import threading
import subprocess
from collections import deque, defaultdict

class UltraThinkModified:
    def __init__(self):
        self.data_streams = {
            "connections": deque(maxlen=200),
        }
        self.running = True

    def start(self):
        """Initialize all monitoring threads"""
        thread = threading.Thread(target=self.network_monitor, daemon=True)
        thread.start()
        while self.running:
            time.sleep(1)

    def network_monitor(self):
        """Real-time packet analysis - Track NEW connections only"""
        import sys
        print("🔍 Starting network monitor...", file=sys.stderr)
        seen_connections = set()

        while self.running:
            try:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True,
                    text=True
                )

                current_connections = set()

                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        state = parts[1]
                        local = parts[3]
                        remote = parts[4]

                        # Capture ESTAB, SYN-SENT, SYN-RECV (active connections)
                        if state in ["ESTAB", "SYN-SENT", "SYN-RECV"]:
                            try:
                                # Get the process name
                                process_info = parts[-1] if len(parts) > 5 else ""
                                process_name = ""
                                if "users:" in process_info:
                                    try:
                                        process_name = process_info.split("users:((\"")[1].split("\"")[0]
                                    except (IndexError, AttributeError):
                                        pass

                                local_ip, local_port = local.rsplit(':', 1)
                                remote_ip, remote_port = remote.rsplit(':', 1)

                                # Skip localhost connections
                                if remote_ip in ["127.0.0.1", "::1", "[::1]"]:
                                    continue

                                # Create unique connection ID
                                conn_id = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"
                                current_connections.add(conn_id)

                                # Only emit if NEW connection
                                if conn_id not in seen_connections:
                                    connection = {
                                        "type": "connection",
                                        "src_ip": local_ip,
                                        "dst_ip": remote_ip,
                                        "dst_port": int(remote_port),
                                        "metadata": {
                                            "protocol": parts[0].upper(),
                                            "state": state,
                                            "process": process_name
                                        }
                                    }
                                    print(json.dumps(connection), flush=True)
                                    seen_connections.add(conn_id)

                            except (ValueError, IndexError):
                                pass

                # Clean up closed connections from seen set
                closed = seen_connections - current_connections
                for conn in closed:
                    seen_connections.remove(conn)

            except Exception as e:
                print(f"⚠️  Monitor error: {e}", file=sys.stderr)

            time.sleep(0.5)  # Faster polling for better responsiveness

def main():
    ultra = UltraThinkModified()
    try:
        ultra.start()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
