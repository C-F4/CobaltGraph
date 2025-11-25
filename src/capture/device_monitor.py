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
import subprocess
from typing import Dict, List

logger = logging.getLogger(__name__)


class DeviceMonitor:
    """
    Device-only network monitoring

    Captures connections originating from THIS machine
    without requiring root privileges or promiscuous mode.
    """

    def __init__(self):
        """Initialize device monitor"""
        self.os_type = platform.system().lower()
        logger.info("📱 Device monitor initialized for %s", self.os_type)

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
        try:
            # Use ss command (socket statistics)
            result = subprocess.run(
                ["ss", "-tunaH"],  # TCP/UDP, numeric, all, no header
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )

            connections = []
            for line in result.stdout.splitlines():
                # TODO: Parse ss output
                # Format: State Recv-Q Send-Q Local Address:Port Peer Address:Port
                pass

            return connections
        except Exception as e:
            logger.error("Failed to get Linux connections: %s", e)
            return []

    def _get_connections_macos(self) -> List[Dict]:
        """
        Get connections on macOS using netstat

        Returns:
            List of connections
        """
        # TODO: Implement macOS netstat parsing
        return []

    def _get_connections_windows(self) -> List[Dict]:
        """
        Get connections on Windows using netstat

        Returns:
            List of connections
        """
        # TODO: Implement Windows netstat parsing
        return []

    def start_monitoring(self, callback):
        """
        Start continuous monitoring

        Args:
            callback: Function to call with new connections
        """
        # TODO: Implement polling loop
        logger.info("📡 Starting device monitoring...")
