#!/usr/bin/env python3
"""
Simple network capture - emits NEW connections only
"""
import json
import subprocess
import time
import sys

def capture_connections():
    """Capture connection lifecycle - NEW and CLOSED remote endpoints"""
    print("🔴 Remote endpoint monitoring active (NEW/CLOSED by destination)", file=sys.stderr)

    previous_endpoints = set()  # Track remote endpoints from previous scan
    scan_count = 0

    while True:
        scan_count += 1
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True,
                text=True,
                timeout=1
            )

            current_endpoints = set()

            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) < 6:  # Need at least 6 fields
                    continue

                state = parts[1]
                local = parts[4]   # Field 5: Local Address:Port
                remote = parts[5]  # Field 6: Peer Address:Port

                # Only ESTABLISHED connections
                if state != "ESTAB":
                    continue

                try:
                    # Parse IP:PORT - handle cases without port
                    if ':' not in local or ':' not in remote:
                        continue  # Skip malformed entries

                    local_ip, local_port = local.rsplit(':', 1)
                    remote_ip, remote_port = remote.rsplit(':', 1)

                    # Skip localhost
                    if remote_ip in ["127.0.0.1", "::1", "[::1]", "localhost"]:
                        continue

                    # Skip dashboard port
                    if remote_port == "8080":
                        continue

                    # Track by remote endpoint only (ignore ephemeral local ports)
                    endpoint_key = f"{remote_ip}:{remote_port}"

                    # Check if this is a NEW endpoint (not in previous AND not yet emitted in current scan)
                    is_new_endpoint = endpoint_key not in previous_endpoints and endpoint_key not in current_endpoints

                    # Always add to current_endpoints (for next scan comparison)
                    current_endpoints.add(endpoint_key)

                    # Only emit if this is the first time seeing this endpoint
                    if is_new_endpoint:
                        # Extract process
                        process = ""
                        if len(parts) > 5 and "users:" in parts[-1]:
                            try:
                                process = parts[-1].split('users:((\"')[1].split('\"')[0]
                            except:
                                pass

                        # Emit NEW connection event
                        connection = {
                            "type": "connection",
                            "event": "new",
                            "src_ip": local_ip,
                            "dst_ip": remote_ip,
                            "dst_port": int(remote_port),
                            "metadata": {
                                "protocol": parts[0].upper(),
                                "state": state,
                                "process": process
                            }
                        }

                        print(json.dumps(connection), flush=True)
                        print(f"🆕 NEW: {remote_ip}:{remote_port}", file=sys.stderr)

                except (ValueError, IndexError):
                    pass  # Skip parse errors silently

            # Detect CLOSED endpoints (in previous but not in current)
            # Disabled for now - only tracking NEW endpoints
            # closed_endpoints = previous_endpoints - current_endpoints
            # for endpoint in closed_endpoints:
            #     print(f"🔴 CLOSED: {endpoint}", file=sys.stderr)

            # Update previous state
            previous_endpoints = current_endpoints

            # Heartbeat every 10 scans (20 seconds) to keep pipe alive
            if scan_count % 10 == 0:
                heartbeat = {
                    "type": "heartbeat",
                    "scan_count": scan_count,
                    "active_endpoints": len(current_endpoints)
                }
                print(json.dumps(heartbeat), flush=True)
                print(f"💓 Heartbeat: {len(current_endpoints)} active endpoints", file=sys.stderr)

        except Exception as e:
            print(f"⚠️  Error: {e}", file=sys.stderr)

        time.sleep(2)  # Check for connection changes every 2 seconds

if __name__ == "__main__":
    try:
        capture_connections()
    except KeyboardInterrupt:
        pass
