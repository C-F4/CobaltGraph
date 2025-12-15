"""
CobaltGraph Device Monitor
Fallback capture for device-only mode (no promiscuous mode)

When network-wide capture is unavailable (no root, Windows, etc.),
use this module to monitor connections from THIS device only.

Methods:
- Socket statistics (ss command on Linux)
- /proc/net/tcp parsing
- netstat fallback
- Windows netstat
"""

import logging
import platform
import re
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DeviceMonitor:
    """
    Device-only network monitoring

    Captures connections originating from THIS machine
    without requiring root privileges or promiscuous mode.
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize device monitor"""
        self.os_type = platform.system().lower()
        self.config = config or {}
        self._callback: Optional[Callable] = None
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._seen_connections: Set[str] = set()
        self._poll_interval = self.config.get("poll_interval", 2.0)
        logger.info("📱 Device monitor initialized for %s", self.os_type)

    def set_callback(self, callback: Callable):
        """Set callback for new connections"""
        self._callback = callback

    def start(self):
        """Start monitoring in background thread"""
        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("📡 Device monitoring started (polling every %.1fs)", self._poll_interval)

    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3.0)
        logger.info("📡 Device monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        # Track when connections were last seen for TTL-based deduplication
        connection_timestamps: Dict[str, float] = {}
        DEDUP_TTL = 60.0  # Re-emit connection after 60 seconds

        while self._running:
            try:
                connections = self.get_connections()
                now = time.time()

                for conn in connections:
                    # Create unique key for deduplication
                    key = f"{conn.get('dst_ip')}:{conn.get('dst_port')}"

                    last_seen = connection_timestamps.get(key, 0)

                    # Emit if new or TTL expired
                    if now - last_seen > DEDUP_TTL:
                        connection_timestamps[key] = now

                        # Emit to callback
                        if self._callback:
                            self._callback(conn)

                # Cleanup old entries periodically (older than 5 minutes)
                if len(connection_timestamps) > 5000:
                    cutoff = now - 300
                    connection_timestamps = {
                        k: v for k, v in connection_timestamps.items()
                        if v > cutoff
                    }

            except Exception as e:
                logger.debug(f"Monitor loop error: {e}")

            time.sleep(self._poll_interval)

    def get_connections(self) -> List[Dict]:
        """
        Get current connections from this device

        Returns:
            List of connection dicts
        """
        if self.os_type == "linux":
            return self._get_connections_linux()
        elif self.os_type == "darwin":  # macOS
            return self._get_connections_macos()
        elif self.os_type == "windows":
            return self._get_connections_windows()
        else:
            logger.warning("Unsupported OS: %s", self.os_type)
            return []

    def _get_connections_linux(self) -> List[Dict]:
        """
        Get connections on Linux using ss command

        Returns:
            List of connections
        """
        connections = []

        try:
            # Use ss command (socket statistics)
            # -t: TCP, -u: UDP, -n: numeric, -a: all states, -H: no header
            result = subprocess.run(
                ["ss", "-tunH"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                # Fallback to /proc/net/tcp
                return self._parse_proc_net_tcp()

            for line in result.stdout.strip().splitlines():
                conn = self._parse_ss_line(line)
                if conn:
                    connections.append(conn)

        except FileNotFoundError:
            # ss not available, use /proc/net/tcp
            return self._parse_proc_net_tcp()
        except Exception as e:
            logger.debug(f"ss command failed: {e}")
            return self._parse_proc_net_tcp()

        return connections

    def _parse_ss_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single ss output line

        Format: Proto State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        Example: tcp   ESTAB 0      0      192.168.1.100:52234 142.250.80.46:443
        """
        try:
            parts = line.split()
            if len(parts) < 6:
                return None

            # Format: proto state recv-q send-q local peer
            proto = parts[0]  # tcp or udp
            state = parts[1]
            local_addr = parts[4]
            peer_addr = parts[5]

            # Only track established outbound connections
            if state not in ("ESTAB", "ESTABLISHED"):
                return None

            # Parse peer address
            if ":" not in peer_addr:
                return None

            # Handle IPv6 format [::1]:port
            if peer_addr.startswith("["):
                match = re.match(r'\[(.+)\]:(\d+)', peer_addr)
                if match:
                    dst_ip = match.group(1)
                    dst_port = int(match.group(2))
                else:
                    return None
            else:
                ip_port = peer_addr.rsplit(":", 1)
                if len(ip_port) != 2:
                    return None
                dst_ip = ip_port[0]
                try:
                    dst_port = int(ip_port[1])
                except ValueError:
                    return None

            # Parse local address for src_ip
            if local_addr.startswith("["):
                local_match = re.match(r'\[(.+)\]:(\d+)', local_addr)
                src_ip = local_match.group(1) if local_match else "local"
            else:
                src_ip = local_addr.rsplit(":", 1)[0] if ":" in local_addr else "local"

            # Skip localhost and link-local
            if dst_ip.startswith("127.") or dst_ip.startswith("::1"):
                return None
            if dst_ip.startswith("169.254."):
                return None

            # Skip private network destinations (internal traffic)
            if self._is_private_ip(dst_ip):
                return None

            return {
                "type": "connection",
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto.upper(),
                "metadata": {"source": "ss", "state": state},
            }

        except Exception as e:
            logger.debug(f"Failed to parse ss line: {e}")
            return None

    def _parse_proc_net_tcp(self) -> List[Dict]:
        """
        Parse /proc/net/tcp for connections (fallback)

        Returns:
            List of connections
        """
        connections = []

        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                conn = self._parse_proc_tcp_line(line)
                if conn:
                    connections.append(conn)

        except Exception as e:
            logger.debug(f"Failed to parse /proc/net/tcp: {e}")

        return connections

    def _parse_proc_tcp_line(self, line: str) -> Optional[Dict]:
        """
        Parse a line from /proc/net/tcp

        Format: sl local_address rem_address st tx_queue rx_queue ...
        Addresses are hex encoded: IP:PORT (both in hex)
        """
        try:
            parts = line.split()
            if len(parts) < 4:
                return None

            state = int(parts[3], 16)
            # Only track ESTABLISHED (01) connections
            if state != 0x01:
                return None

            # Parse remote address (hex format)
            rem_addr = parts[2]
            ip_hex, port_hex = rem_addr.split(":")

            # Convert hex IP to dotted decimal (little-endian)
            ip_int = int(ip_hex, 16)
            dst_ip = ".".join([
                str((ip_int >> 0) & 0xFF),
                str((ip_int >> 8) & 0xFF),
                str((ip_int >> 16) & 0xFF),
                str((ip_int >> 24) & 0xFF),
            ])
            dst_port = int(port_hex, 16)

            # Parse local address
            local_addr = parts[1]
            local_ip_hex = local_addr.split(":")[0]
            local_ip_int = int(local_ip_hex, 16)
            src_ip = ".".join([
                str((local_ip_int >> 0) & 0xFF),
                str((local_ip_int >> 8) & 0xFF),
                str((local_ip_int >> 16) & 0xFF),
                str((local_ip_int >> 24) & 0xFF),
            ])

            # Skip localhost
            if dst_ip.startswith("127.") or dst_ip == "0.0.0.0":
                return None

            # Skip private destinations
            if self._is_private_ip(dst_ip):
                return None

            return {
                "type": "connection",
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": "TCP",
                "metadata": {"source": "proc_net_tcp"},
            }

        except Exception as e:
            logger.debug(f"Failed to parse /proc/net/tcp line: {e}")
            return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        if ip.startswith("10."):
            return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except:
                pass
        return False

    def _get_connections_macos(self) -> List[Dict]:
        """
        Get connections on macOS using netstat

        Returns:
            List of connections
        """
        connections = []

        try:
            result = subprocess.run(
                ["netstat", "-an", "-p", "tcp"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            for line in result.stdout.splitlines():
                if "ESTABLISHED" not in line:
                    continue

                conn = self._parse_netstat_line(line)
                if conn:
                    connections.append(conn)

        except Exception as e:
            logger.debug(f"macOS netstat failed: {e}")

        return connections

    def _get_connections_windows(self) -> List[Dict]:
        """
        Get connections on Windows using netstat

        Returns:
            List of connections
        """
        connections = []

        try:
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                if "ESTABLISHED" not in line:
                    continue

                conn = self._parse_netstat_line(line)
                if conn:
                    connections.append(conn)

        except Exception as e:
            logger.debug(f"Windows netstat failed: {e}")

        return connections

    def _parse_netstat_line(self, line: str) -> Optional[Dict]:
        """Parse netstat output line (macOS/Windows)"""
        try:
            parts = line.split()

            # Find the foreign address column
            for i, part in enumerate(parts):
                if "." in part and ":" in part:
                    # Looks like IP:Port
                    ip_port = part.rsplit(":", 1)
                    if len(ip_port) == 2:
                        dst_ip = ip_port[0]
                        try:
                            dst_port = int(ip_port[1])
                        except ValueError:
                            continue

                        if self._is_private_ip(dst_ip):
                            continue
                        if dst_ip.startswith("127."):
                            continue

                        return {
                            "type": "connection",
                            "timestamp": time.time(),
                            "src_ip": "local",
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "metadata": {"source": "netstat"},
                        }
        except Exception:
            pass

        return None
