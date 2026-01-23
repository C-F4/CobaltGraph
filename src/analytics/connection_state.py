#!/usr/bin/env python3
"""
CobaltGraph Connection State Tracker

Tracks TCP connection states and completion rates for threat analysis.
Provides data to consensus scorers for anomaly detection.

Key metrics:
- Connection completion rate (SYN → SYN-ACK → ACK)
- RST rate (connection resets - potential blocking/scanning)
- Half-open connection rate (potential SYN flood or port scan)
- Connection duration patterns

Usage:
    tracker = ConnectionStateTracker()
    tracker.record_connection(dst_ip, tcp_state, dst_port)

    # Get metrics for scoring
    metrics = tracker.get_metrics(dst_ip)
    if metrics.completion_rate < 0.3:
        # Low completion rate - suspicious
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ConnectionMetrics:
    """Aggregated connection metrics for a destination"""
    dst_ip: str

    # Connection counts
    total_connections: int = 0
    completed_connections: int = 0  # Full handshake completed
    half_open_connections: int = 0  # SYN sent, no response
    reset_connections: int = 0      # RST received

    # Calculated rates (0.0 - 1.0)
    completion_rate: float = 0.0
    rst_rate: float = 0.0
    half_open_rate: float = 0.0

    # Port analysis
    unique_ports: int = 0
    common_ports_ratio: float = 0.0  # Ratio of well-known port connections

    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0
    avg_interval: float = 0.0  # Average time between connections

    def is_suspicious(self) -> bool:
        """Quick check if metrics indicate suspicious behavior"""
        return (
            self.completion_rate < 0.3 or
            self.rst_rate > 0.5 or
            self.half_open_rate > 0.4
        )


@dataclass
class ConnectionRecord:
    """Single connection state record"""
    timestamp: float
    tcp_state: str  # SYN, SYN-ACK, ESTABLISHED, RST, FIN, etc.
    dst_port: int
    bytes_sent: int = 0
    bytes_received: int = 0


class ConnectionStateTracker:
    """
    Tracks TCP connection states for behavioral analysis.

    Feeds into RuleScorer for anomaly detection:
    - Low completion rates suggest blocked/dead destinations
    - High RST rates suggest firewall blocks or port scanning
    - High half-open rates suggest SYN scanning
    """

    # Well-known ports (more likely to be legitimate)
    COMMON_PORTS = {
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
        465, 587, 993, 995, 3389, 8080, 8443
    }

    # Connection states that indicate completion
    COMPLETED_STATES = {"ESTABLISHED", "SYN-ACK", "FIN", "FIN-ACK"}

    # Connection states that indicate reset
    RESET_STATES = {"RST", "RST-ACK"}

    # Connection states that indicate half-open
    HALF_OPEN_STATES = {"SYN", "SYN-SENT"}

    # Retention settings
    RECORD_RETENTION = 3600  # 1 hour
    MAX_RECORDS_PER_IP = 1000
    MAX_TRACKED_IPS = 10000

    def __init__(self):
        """Initialize connection state tracker"""
        self._connections: Dict[str, List[ConnectionRecord]] = defaultdict(list)
        self._port_history: Dict[str, Set[int]] = defaultdict(set)
        self._lock = Lock()

        # Statistics
        self.stats = {
            "total_recorded": 0,
            "ips_tracked": 0,
            "suspicious_ips": 0,
        }

        logger.info("ConnectionStateTracker initialized")

    def record_connection(
        self,
        dst_ip: str,
        tcp_state: str,
        dst_port: int,
        timestamp: Optional[float] = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
    ):
        """
        Record a connection state observation.

        Args:
            dst_ip: Destination IP
            tcp_state: TCP state (SYN, ESTABLISHED, RST, etc.)
            dst_port: Destination port
            timestamp: Connection timestamp (default: now)
            bytes_sent: Bytes sent
            bytes_received: Bytes received
        """
        if timestamp is None:
            timestamp = time.time()

        record = ConnectionRecord(
            timestamp=timestamp,
            tcp_state=tcp_state.upper() if tcp_state else "UNKNOWN",
            dst_port=dst_port,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
        )

        with self._lock:
            self._connections[dst_ip].append(record)
            self._port_history[dst_ip].add(dst_port)
            self.stats["total_recorded"] += 1

            # Enforce limits
            self._enforce_limits(dst_ip)

            self.stats["ips_tracked"] = len(self._connections)

    def _enforce_limits(self, dst_ip: str):
        """Enforce memory limits for tracked data"""
        # Limit records per IP
        if len(self._connections[dst_ip]) > self.MAX_RECORDS_PER_IP:
            # Keep most recent
            self._connections[dst_ip] = self._connections[dst_ip][-self.MAX_RECORDS_PER_IP:]

        # Limit total tracked IPs
        if len(self._connections) > self.MAX_TRACKED_IPS:
            # Remove oldest IPs (those with oldest last record)
            ip_last_seen = {
                ip: records[-1].timestamp if records else 0
                for ip, records in self._connections.items()
            }
            oldest_ips = sorted(ip_last_seen.keys(), key=lambda x: ip_last_seen[x])
            for ip in oldest_ips[:len(self._connections) - self.MAX_TRACKED_IPS]:
                del self._connections[ip]
                if ip in self._port_history:
                    del self._port_history[ip]

    def get_metrics(self, dst_ip: str) -> ConnectionMetrics:
        """
        Get aggregated connection metrics for a destination.

        Args:
            dst_ip: Destination IP

        Returns:
            ConnectionMetrics with calculated rates
        """
        with self._lock:
            records = self._connections.get(dst_ip, [])
            ports = self._port_history.get(dst_ip, set())

        metrics = ConnectionMetrics(dst_ip=dst_ip)

        if not records:
            return metrics

        # Calculate counts
        now = time.time()
        cutoff = now - self.RECORD_RETENTION
        recent_records = [r for r in records if r.timestamp > cutoff]

        if not recent_records:
            return metrics

        metrics.total_connections = len(recent_records)
        metrics.first_seen = recent_records[0].timestamp
        metrics.last_seen = recent_records[-1].timestamp

        # Count by state
        completed = 0
        half_open = 0
        resets = 0

        for record in recent_records:
            if record.tcp_state in self.COMPLETED_STATES:
                completed += 1
            elif record.tcp_state in self.HALF_OPEN_STATES:
                half_open += 1
            elif record.tcp_state in self.RESET_STATES:
                resets += 1

        metrics.completed_connections = completed
        metrics.half_open_connections = half_open
        metrics.reset_connections = resets

        # Calculate rates
        total = metrics.total_connections
        if total > 0:
            metrics.completion_rate = completed / total
            metrics.rst_rate = resets / total
            metrics.half_open_rate = half_open / total

        # Port analysis
        metrics.unique_ports = len(ports)
        if ports:
            common_port_count = len(ports.intersection(self.COMMON_PORTS))
            metrics.common_ports_ratio = common_port_count / len(ports)

        # Calculate average interval
        if len(recent_records) > 1:
            intervals = [
                recent_records[i].timestamp - recent_records[i-1].timestamp
                for i in range(1, len(recent_records))
            ]
            metrics.avg_interval = sum(intervals) / len(intervals)

        return metrics

    def get_completion_rate(self, dst_ip: str) -> float:
        """
        Get connection completion rate for a destination.

        Returns:
            Ratio of completed to total connections (0.0 - 1.0)
        """
        metrics = self.get_metrics(dst_ip)
        return metrics.completion_rate

    def get_rst_rate(self, dst_ip: str) -> float:
        """
        Get RST (reset) rate for a destination.

        Returns:
            Ratio of RST connections to total (0.0 - 1.0)
        """
        metrics = self.get_metrics(dst_ip)
        return metrics.rst_rate

    def get_state_data(self, dst_ip: str) -> Optional[Dict]:
        """
        Get connection state data in dict format for scorers.

        Returns:
            Dict with state metrics, or None if no data
        """
        metrics = self.get_metrics(dst_ip)

        if metrics.total_connections == 0:
            return None

        return {
            "completion_rate": metrics.completion_rate,
            "rst_rate": metrics.rst_rate,
            "half_open_rate": metrics.half_open_rate,
            "unique_ports": metrics.unique_ports,
            "common_ports_ratio": metrics.common_ports_ratio,
            "total_connections": metrics.total_connections,
            "is_suspicious": metrics.is_suspicious(),
        }

    def is_scanning(self, src_ip: str, window_seconds: int = 60) -> bool:
        """
        Check if a source IP appears to be port scanning.

        Args:
            src_ip: Source IP to check
            window_seconds: Time window for scan detection

        Returns:
            True if port scanning pattern detected
        """
        # For this we need to track by source, not destination
        # This is a simplified check based on unique ports in window
        with self._lock:
            ports = self._port_history.get(src_ip, set())

        # Many unique ports in short time = likely scanning
        return len(ports) > 20

    def cleanup(self):
        """Remove old records"""
        now = time.time()
        cutoff = now - self.RECORD_RETENTION

        with self._lock:
            ips_to_remove = []

            for dst_ip, records in self._connections.items():
                # Keep only recent records
                self._connections[dst_ip] = [
                    r for r in records if r.timestamp > cutoff
                ]
                if not self._connections[dst_ip]:
                    ips_to_remove.append(dst_ip)

            for ip in ips_to_remove:
                del self._connections[ip]
                if ip in self._port_history:
                    del self._port_history[ip]

            self.stats["ips_tracked"] = len(self._connections)

    def get_suspicious_ips(self, min_connections: int = 5) -> List[str]:
        """
        Get list of IPs with suspicious connection patterns.

        Args:
            min_connections: Minimum connections to consider

        Returns:
            List of suspicious destination IPs
        """
        suspicious = []

        with self._lock:
            ips = list(self._connections.keys())

        for dst_ip in ips:
            metrics = self.get_metrics(dst_ip)
            if metrics.total_connections >= min_connections and metrics.is_suspicious():
                suspicious.append(dst_ip)

        self.stats["suspicious_ips"] = len(suspicious)
        return suspicious

    def get_stats(self) -> Dict:
        """Get tracker statistics"""
        return dict(self.stats)

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("ConnectionStateTracker shutdown complete")


# Factory function
def create_connection_tracker() -> ConnectionStateTracker:
    """Create a ConnectionStateTracker instance"""
    return ConnectionStateTracker()
