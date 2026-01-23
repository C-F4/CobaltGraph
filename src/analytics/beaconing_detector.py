#!/usr/bin/env python3
"""
CobaltGraph Beaconing Detector

Detects Command & Control (C2) beaconing patterns in network traffic.
Beaconing is characterized by regular, periodic connections to external hosts,
often with small jitter to evade simple detection.

Key indicators:
- Regular time intervals between connections
- Low jitter (variance) in timing
- Consistent packet sizes
- Persistent connection to same destination

Usage:
    detector = BeaconingDetector()
    detector.record_connection(dst_ip, timestamp, bytes_sent)

    # Periodically analyze
    results = detector.analyze_all()
    for result in results:
        if result.is_beaconing:
            print(f"Beaconing detected: {result.dst_ip}")
"""

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class BeaconingResult:
    """Result of beaconing analysis for a single destination"""
    dst_ip: str
    is_beaconing: bool = False

    # Timing analysis
    connection_count: int = 0
    interval_mean: float = 0.0  # Average seconds between connections
    interval_std: float = 0.0   # Standard deviation of intervals
    jitter_percent: float = 100.0  # Coefficient of variation (std/mean * 100)

    # Regularity score (0-1, higher = more regular/suspicious)
    regularity_score: float = 0.0

    # Additional context
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_bytes: int = 0
    avg_bytes_per_connection: float = 0.0

    # Classification
    beacon_type: str = "unknown"  # slow, fast, variable, none

    def get_beacon_type_display(self) -> str:
        """Human-readable beacon type"""
        types = {
            "slow": "Slow beacon (>5min intervals)",
            "fast": "Fast beacon (<1min intervals)",
            "medium": "Medium beacon (1-5min intervals)",
            "variable": "Variable beacon (irregular but patterned)",
            "none": "No beaconing detected",
        }
        return types.get(self.beacon_type, "Unknown pattern")


@dataclass
class ConnectionRecord:
    """Record of a single connection for beaconing analysis"""
    timestamp: float
    bytes_sent: int = 0
    bytes_received: int = 0
    dst_port: int = 0


class BeaconingDetector:
    """
    Detects C2-style beaconing patterns in network connections.

    Algorithm:
    1. Record all connections to each destination IP
    2. Calculate inter-arrival times (IAT) between connections
    3. Analyze IAT distribution for regularity
    4. Flag as beaconing if:
       - Sufficient connection count (>= 5)
       - Low jitter (<= 20% coefficient of variation)
       - Consistent over time window
    """

    # Detection thresholds
    MIN_CONNECTIONS = 5           # Minimum connections to analyze
    MAX_JITTER_PERCENT = 20.0     # Maximum jitter for beaconing
    MIN_INTERVAL_SECONDS = 10     # Minimum interval (filter out burst traffic)
    MAX_INTERVAL_SECONDS = 7200   # Maximum interval (2 hours)

    # Analysis windows
    ANALYSIS_WINDOW = 3600        # 1 hour lookback for analysis
    RECORD_RETENTION = 7200       # 2 hours record retention

    # Scoring thresholds
    HIGH_REGULARITY_THRESHOLD = 0.7
    MEDIUM_REGULARITY_THRESHOLD = 0.4

    def __init__(self, min_connections: int = 5, max_jitter: float = 20.0):
        """
        Initialize beaconing detector.

        Args:
            min_connections: Minimum connections required for analysis
            max_jitter: Maximum jitter percentage to classify as beaconing
        """
        self.min_connections = min_connections
        self.max_jitter = max_jitter

        # Connection records by destination IP
        self._connections: Dict[str, List[ConnectionRecord]] = defaultdict(list)
        self._lock = Lock()

        # Cache for analysis results
        self._result_cache: Dict[str, Tuple[BeaconingResult, float]] = {}
        self._cache_ttl = 60  # Cache results for 60 seconds

        # Statistics
        self.stats = {
            "connections_recorded": 0,
            "analyses_performed": 0,
            "beacons_detected": 0,
            "ips_tracked": 0,
        }

        logger.info(
            f"BeaconingDetector initialized "
            f"(min_conn={min_connections}, max_jitter={max_jitter}%)"
        )

    def record_connection(
        self,
        dst_ip: str,
        timestamp: Optional[float] = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        dst_port: int = 0,
    ):
        """
        Record a connection for beaconing analysis.

        Args:
            dst_ip: Destination IP address
            timestamp: Connection timestamp (default: now)
            bytes_sent: Bytes sent in connection
            bytes_received: Bytes received
            dst_port: Destination port
        """
        if timestamp is None:
            timestamp = time.time()

        record = ConnectionRecord(
            timestamp=timestamp,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            dst_port=dst_port,
        )

        with self._lock:
            self._connections[dst_ip].append(record)
            self.stats["connections_recorded"] += 1

            # Update tracked IPs count
            self.stats["ips_tracked"] = len(self._connections)

            # Cleanup old records for this IP
            self._cleanup_ip(dst_ip)

    def _cleanup_ip(self, dst_ip: str):
        """Remove old connection records for an IP"""
        cutoff = time.time() - self.RECORD_RETENTION
        self._connections[dst_ip] = [
            r for r in self._connections[dst_ip]
            if r.timestamp > cutoff
        ]

        # Remove IP entirely if no recent records
        if not self._connections[dst_ip]:
            del self._connections[dst_ip]

    def analyze(self, dst_ip: str, use_cache: bool = True) -> BeaconingResult:
        """
        Analyze a single destination IP for beaconing patterns.

        Args:
            dst_ip: Destination IP to analyze
            use_cache: Use cached result if available

        Returns:
            BeaconingResult with analysis data
        """
        # Check cache
        if use_cache and dst_ip in self._result_cache:
            result, cache_time = self._result_cache[dst_ip]
            if time.time() - cache_time < self._cache_ttl:
                return result

        with self._lock:
            records = self._connections.get(dst_ip, [])

        result = self._analyze_records(dst_ip, records)

        # Update cache
        self._result_cache[dst_ip] = (result, time.time())
        self.stats["analyses_performed"] += 1

        if result.is_beaconing:
            self.stats["beacons_detected"] += 1

        return result

    def _analyze_records(self, dst_ip: str, records: List[ConnectionRecord]) -> BeaconingResult:
        """Perform beaconing analysis on connection records"""
        result = BeaconingResult(dst_ip=dst_ip)

        # Need minimum connections
        if len(records) < self.min_connections:
            result.connection_count = len(records)
            result.beacon_type = "none"
            return result

        # Sort by timestamp
        sorted_records = sorted(records, key=lambda r: r.timestamp)
        result.connection_count = len(sorted_records)
        result.first_seen = sorted_records[0].timestamp
        result.last_seen = sorted_records[-1].timestamp

        # Calculate total bytes
        result.total_bytes = sum(r.bytes_sent + r.bytes_received for r in sorted_records)
        result.avg_bytes_per_connection = result.total_bytes / len(sorted_records)

        # Calculate inter-arrival times (IAT)
        intervals = []
        for i in range(1, len(sorted_records)):
            interval = sorted_records[i].timestamp - sorted_records[i-1].timestamp
            # Filter out very short intervals (likely retries/duplicates)
            if self.MIN_INTERVAL_SECONDS <= interval <= self.MAX_INTERVAL_SECONDS:
                intervals.append(interval)

        # Need enough valid intervals
        if len(intervals) < self.min_connections - 1:
            result.beacon_type = "none"
            return result

        # Calculate statistics
        result.interval_mean = sum(intervals) / len(intervals)
        variance = sum((x - result.interval_mean) ** 2 for x in intervals) / len(intervals)
        result.interval_std = math.sqrt(variance)

        # Calculate jitter (coefficient of variation)
        if result.interval_mean > 0:
            result.jitter_percent = (result.interval_std / result.interval_mean) * 100
        else:
            result.jitter_percent = 100.0

        # Calculate regularity score
        result.regularity_score = self._calculate_regularity_score(
            intervals, result.interval_mean, result.jitter_percent
        )

        # Classify beacon type based on interval
        if result.interval_mean < 60:
            result.beacon_type = "fast"
        elif result.interval_mean < 300:
            result.beacon_type = "medium"
        else:
            result.beacon_type = "slow"

        # Determine if beaconing
        result.is_beaconing = (
            result.jitter_percent <= self.max_jitter and
            result.regularity_score >= self.MEDIUM_REGULARITY_THRESHOLD and
            len(intervals) >= self.min_connections - 1
        )

        # Downgrade if regularity is borderline
        if result.is_beaconing and result.regularity_score < self.HIGH_REGULARITY_THRESHOLD:
            result.beacon_type = "variable"

        if not result.is_beaconing:
            result.beacon_type = "none"

        return result

    def _calculate_regularity_score(
        self,
        intervals: List[float],
        mean_interval: float,
        jitter_percent: float
    ) -> float:
        """
        Calculate regularity score based on multiple factors.

        Score components:
        1. Jitter score (low jitter = high score)
        2. Consistency score (intervals close to mean)
        3. Count score (more samples = higher confidence)
        """
        if not intervals or mean_interval == 0:
            return 0.0

        # Jitter score (0-1, lower jitter = higher score)
        # Map 0-50% jitter to 1-0 score
        jitter_score = max(0, 1 - (jitter_percent / 50))

        # Consistency score - what percentage of intervals are within 2 std of mean
        std = math.sqrt(sum((x - mean_interval) ** 2 for x in intervals) / len(intervals))
        within_2std = sum(1 for x in intervals if abs(x - mean_interval) <= 2 * std)
        consistency_score = within_2std / len(intervals)

        # Count score - more samples = higher confidence (cap at 20 samples)
        count_score = min(1.0, len(intervals) / 20)

        # Weighted combination
        regularity = (
            jitter_score * 0.5 +
            consistency_score * 0.3 +
            count_score * 0.2
        )

        return round(regularity, 3)

    def analyze_all(self, min_connections: Optional[int] = None) -> List[BeaconingResult]:
        """
        Analyze all tracked IPs for beaconing patterns.

        Args:
            min_connections: Override minimum connection threshold

        Returns:
            List of BeaconingResult for all IPs with sufficient data
        """
        threshold = min_connections or self.min_connections
        results = []

        with self._lock:
            ips_to_analyze = [
                ip for ip, records in self._connections.items()
                if len(records) >= threshold
            ]

        for dst_ip in ips_to_analyze:
            result = self.analyze(dst_ip)
            results.append(result)

        # Sort by regularity score (most suspicious first)
        results.sort(key=lambda r: r.regularity_score, reverse=True)

        return results

    def get_beacons(self) -> List[BeaconingResult]:
        """Get all currently detected beacons"""
        all_results = self.analyze_all()
        return [r for r in all_results if r.is_beaconing]

    def is_beaconing(self, dst_ip: str) -> bool:
        """Quick check if IP is currently flagged as beaconing"""
        result = self.analyze(dst_ip)
        return result.is_beaconing

    def get_beacon_data(self, dst_ip: str) -> Optional[Dict]:
        """
        Get beaconing data for a specific IP in dict format.
        Used by consensus scorers.
        """
        result = self.analyze(dst_ip)
        if not result.is_beaconing:
            return None

        return {
            "is_beaconing": True,
            "interval_seconds": result.interval_mean,
            "jitter_percent": result.jitter_percent,
            "regularity_score": result.regularity_score,
            "beacon_type": result.beacon_type,
            "connection_count": result.connection_count,
        }

    def cleanup(self):
        """Remove old records and clear stale cache entries"""
        now = time.time()
        cutoff = now - self.RECORD_RETENTION
        cache_cutoff = now - self._cache_ttl

        with self._lock:
            # Clean old connection records
            ips_to_remove = []
            for dst_ip, records in self._connections.items():
                self._connections[dst_ip] = [
                    r for r in records if r.timestamp > cutoff
                ]
                if not self._connections[dst_ip]:
                    ips_to_remove.append(dst_ip)

            for ip in ips_to_remove:
                del self._connections[ip]

            # Clean stale cache entries
            stale_cache = [
                ip for ip, (_, cache_time) in self._result_cache.items()
                if cache_time < cache_cutoff
            ]
            for ip in stale_cache:
                del self._result_cache[ip]

            self.stats["ips_tracked"] = len(self._connections)

    def get_stats(self) -> Dict:
        """Get detector statistics"""
        active_beacons = len(self.get_beacons())
        return {
            **self.stats,
            "active_beacons": active_beacons,
        }

    def shutdown(self):
        """Graceful shutdown"""
        logger.info("BeaconingDetector shutdown complete")


# Convenience factory
def create_beaconing_detector(
    min_connections: int = 5,
    max_jitter: float = 20.0
) -> BeaconingDetector:
    """Create a configured BeaconingDetector instance"""
    return BeaconingDetector(
        min_connections=min_connections,
        max_jitter=max_jitter,
    )
