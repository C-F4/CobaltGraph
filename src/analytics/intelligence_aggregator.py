#!/usr/bin/env python3
"""
Intelligence Aggregation Engine for CobaltGraph Dashboard
High-performance aggregation layer with sub-100ms query times

Features:
- Real-time threat posture calculation with trend analysis
- Organization intelligence aggregation with risk classification
- Geographic intelligence with threat scoring
- Temporal trends with 1-minute buckets
- In-memory caching for frequently accessed data
- Thread-safe operations
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock, RLock
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ThreatPosture:
    """Real-time threat posture metrics"""
    current_threat: float          # Weighted average threat score
    total_connections: int         # Total connections in window
    high_threats: int             # Connections with threat > 0.7
    medium_threats: int           # Connections with 0.4 < threat < 0.7
    baseline_threat: float        # Historical baseline
    trend: str                    # "increasing", "decreasing", "stable"
    trend_change: float           # Percentage change from baseline
    confidence: float             # Confidence in the calculation
    timestamp: float = field(default_factory=time.time)


@dataclass
class OrganizationIntel:
    """Organization-level intelligence"""
    org_name: str
    org_type: str
    connection_count: int
    avg_threat: float
    max_threat: float
    unique_ips: int
    trust_score: float
    risk_classification: str      # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    trend: str                    # "increasing", "stable", "decreasing"
    first_seen: float
    last_seen: float


@dataclass
class GeographicIntel:
    """Geographic intelligence"""
    country: str
    connection_count: int
    avg_threat: float
    max_threat: float
    unique_ips: int
    unique_asns: int
    risk_level: str               # "LOW", "MEDIUM", "HIGH", "CRITICAL"


@dataclass
class TemporalTrend:
    """Time-series trend data"""
    timestamp: float
    connection_count: int
    avg_threat: float
    high_threat_count: int
    unique_ips: int


class IntelligenceCache:
    """
    In-memory cache for frequently accessed intelligence data

    Thread-safe with TTL-based expiration
    """

    def __init__(self, ttl: float = 5.0):
        """
        Initialize cache

        Args:
            ttl: Time-to-live in seconds (default: 5s for real-time dashboard)
        """
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._lock = RLock()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    return value
                else:
                    # Expired, remove
                    del self._cache[key]
            return None

    def set(self, key: str, value: Any):
        """Set value in cache with current timestamp"""
        with self._lock:
            self._cache[key] = (value, time.time())

    def invalidate(self, key: str = None):
        """Invalidate specific key or entire cache"""
        with self._lock:
            if key:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    def size(self) -> int:
        """Get cache size"""
        with self._lock:
            return len(self._cache)


class IntelligenceAggregator:
    """
    Core intelligence aggregation engine

    Provides high-performance aggregations with caching for dashboard display
    Performance target: <100ms per query
    """

    # Time windows (seconds)
    WINDOW_5MIN = 300
    WINDOW_1HOUR = 3600
    WINDOW_24HOUR = 86400

    # Risk thresholds
    CRITICAL_THRESHOLD = 0.7
    WARNING_THRESHOLD = 0.4

    def __init__(self, db_connection=None, cache_ttl: float = 5.0):
        """
        Initialize aggregator

        Args:
            db_connection: Database connection object (from src.storage.database.Database)
            cache_ttl: Cache time-to-live in seconds
        """
        self.db = db_connection
        self.cache = IntelligenceCache(ttl=cache_ttl)
        self._lock = RLock()

        # Historical baseline for trend analysis
        self._baseline_threat: Optional[float] = None
        self._baseline_timestamp: float = 0
        self._baseline_update_interval = 300  # Update every 5 minutes

        # Performance metrics
        self.stats = {
            "queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_query_time_ms": 0.0,
        }

        logger.info("Intelligence Aggregator initialized (cache TTL: %.1fs)", cache_ttl)

    def _update_query_stats(self, query_time: float, cache_hit: bool):
        """Update performance statistics"""
        self.stats["queries"] += 1
        if cache_hit:
            self.stats["cache_hits"] += 1
        else:
            self.stats["cache_misses"] += 1

        # Running average of query time
        n = self.stats["queries"]
        prev_avg = self.stats["avg_query_time_ms"]
        self.stats["avg_query_time_ms"] = ((prev_avg * (n - 1)) + query_time) / n

    def calculate_threat_posture(self, time_window: int = WINDOW_5MIN) -> ThreatPosture:
        """
        Calculate current threat posture with baseline comparison and trend analysis

        Performance optimized: Uses database view + in-memory caching
        Target: <50ms

        Args:
            time_window: Time window in seconds (default: 5 minutes)

        Returns:
            ThreatPosture object with comprehensive metrics
        """
        start_time = time.time()
        cache_key = f"threat_posture_{time_window}"

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._update_query_stats((time.time() - start_time) * 1000, cache_hit=True)
            return cached

        # Query database
        if not self.db:
            logger.warning("No database connection, returning default posture")
            return ThreatPosture(0.0, 0, 0, 0, 0.0, "stable", 0.0, 0.0)

        try:
            # Ensure pending writes are flushed
            self.db.flush()

            with self.db.lock:
                now = time.time()
                cutoff = now - time_window

                # Single optimized query for all metrics
                cursor = self.db.conn.execute("""
                    SELECT
                        AVG(threat_score) as avg_threat,
                        COUNT(*) as total,
                        COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as high,
                        COUNT(CASE WHEN threat_score > 0.4 AND threat_score <= 0.7 THEN 1 END) as medium,
                        MAX(threat_score) as max_threat,
                        MIN(threat_score) as min_threat
                    FROM connections
                    WHERE timestamp > ?
                """, (cutoff,))

                row = cursor.fetchone()

                if not row or row[1] == 0:
                    # No data in window
                    posture = ThreatPosture(0.0, 0, 0, 0, 0.0, "stable", 0.0, 0.0)
                    self.cache.set(cache_key, posture)
                    self._update_query_stats((time.time() - start_time) * 1000, cache_hit=False)
                    return posture

                current_threat = row[0] or 0.0
                total_connections = row[1]
                high_threats = row[2] or 0
                medium_threats = row[3] or 0
                max_threat = row[4] or 0.0
                min_threat = row[5] or 0.0

                # Update baseline if needed
                if now - self._baseline_timestamp > self._baseline_update_interval:
                    self._update_baseline(cutoff)

                baseline = self._baseline_threat or 0.0

                # Calculate trend
                trend = "stable"
                trend_change = 0.0

                if baseline > 0.01:  # Avoid division by near-zero
                    trend_change = ((current_threat - baseline) / baseline) * 100

                    if trend_change > 10:
                        trend = "increasing"
                    elif trend_change < -10:
                        trend = "decreasing"

                # Confidence based on sample size and threat range
                confidence = min(1.0, total_connections / 100.0)  # Full confidence at 100+ connections
                threat_range = max_threat - min_threat
                if threat_range > 0.5:  # High variance reduces confidence
                    confidence *= 0.8

                posture = ThreatPosture(
                    current_threat=current_threat,
                    total_connections=total_connections,
                    high_threats=high_threats,
                    medium_threats=medium_threats,
                    baseline_threat=baseline,
                    trend=trend,
                    trend_change=trend_change,
                    confidence=confidence,
                )

                # Cache result
                self.cache.set(cache_key, posture)

                query_time_ms = (time.time() - start_time) * 1000
                self._update_query_stats(query_time_ms, cache_hit=False)
                logger.debug(f"Threat posture calculated in {query_time_ms:.2f}ms")

                return posture

        except Exception as e:
            logger.error(f"Failed to calculate threat posture: {e}")
            return ThreatPosture(0.0, 0, 0, 0, 0.0, "stable", 0.0, 0.0)

    def _update_baseline(self, current_cutoff: float):
        """Update threat baseline using historical data"""
        try:
            # Use 24-hour historical baseline
            baseline_cutoff = current_cutoff - self.WINDOW_24HOUR

            with self.db.lock:
                cursor = self.db.conn.execute("""
                    SELECT AVG(threat_score)
                    FROM connections
                    WHERE timestamp > ? AND timestamp <= ?
                """, (baseline_cutoff, current_cutoff))

                result = cursor.fetchone()
                if result and result[0] is not None:
                    self._baseline_threat = result[0]
                    self._baseline_timestamp = time.time()
                    logger.debug(f"Baseline updated: {self._baseline_threat:.4f}")

        except Exception as e:
            logger.error(f"Failed to update baseline: {e}")

    def aggregate_organization_intelligence(
        self,
        time_window: int = WINDOW_1HOUR,
        limit: int = 20
    ) -> List[OrganizationIntel]:
        """
        Aggregate organization-level intelligence with risk classification

        Performance optimized: Single query with grouping
        Target: <100ms

        Args:
            time_window: Time window in seconds (default: 1 hour)
            limit: Maximum number of organizations to return

        Returns:
            List of OrganizationIntel objects sorted by connection count
        """
        start_time = time.time()
        cache_key = f"org_intel_{time_window}_{limit}"

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._update_query_stats((time.time() - start_time) * 1000, cache_hit=True)
            return cached

        if not self.db:
            return []

        try:
            self.db.flush()

            with self.db.lock:
                cutoff = time.time() - time_window

                cursor = self.db.conn.execute("""
                    SELECT
                        dst_org,
                        dst_org_type,
                        COUNT(*) as conn_count,
                        AVG(threat_score) as avg_threat,
                        MAX(threat_score) as max_threat,
                        COUNT(DISTINCT dst_ip) as unique_ips,
                        AVG(COALESCE(org_trust_score, 0.5)) as avg_trust,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen
                    FROM connections
                    WHERE timestamp > ? AND dst_org IS NOT NULL
                    GROUP BY dst_org, dst_org_type
                    ORDER BY conn_count DESC
                    LIMIT ?
                """, (cutoff, limit))

                results = []
                previous_stats = self._get_previous_org_stats(time_window)

                for row in cursor.fetchall():
                    org_name = row[0]
                    org_type = row[1] or "unknown"
                    conn_count = row[2]
                    avg_threat = row[3] or 0.0
                    max_threat = row[4] or 0.0
                    unique_ips = row[5]
                    trust_score = row[6]
                    first_seen = row[7]
                    last_seen = row[8]

                    # Risk classification
                    if avg_threat >= self.CRITICAL_THRESHOLD:
                        risk_class = "CRITICAL"
                    elif avg_threat >= self.WARNING_THRESHOLD:
                        risk_class = "HIGH"
                    elif avg_threat >= 0.2:
                        risk_class = "MEDIUM"
                    else:
                        risk_class = "LOW"

                    # Trend analysis
                    trend = "stable"
                    if org_name in previous_stats:
                        prev_threat = previous_stats[org_name]
                        if avg_threat > prev_threat * 1.15:
                            trend = "increasing"
                        elif avg_threat < prev_threat * 0.85:
                            trend = "decreasing"

                    results.append(OrganizationIntel(
                        org_name=org_name,
                        org_type=org_type,
                        connection_count=conn_count,
                        avg_threat=avg_threat,
                        max_threat=max_threat,
                        unique_ips=unique_ips,
                        trust_score=trust_score,
                        risk_classification=risk_class,
                        trend=trend,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    ))

                # Cache results
                self.cache.set(cache_key, results)

                query_time_ms = (time.time() - start_time) * 1000
                self._update_query_stats(query_time_ms, cache_hit=False)
                logger.debug(f"Org intelligence aggregated in {query_time_ms:.2f}ms ({len(results)} orgs)")

                return results

        except Exception as e:
            logger.error(f"Failed to aggregate organization intelligence: {e}")
            return []

    def _get_previous_org_stats(self, time_window: int) -> Dict[str, float]:
        """Get previous period stats for trend comparison"""
        try:
            # Get stats from the previous equivalent window
            with self.db.lock:
                start = time.time() - (time_window * 2)
                end = time.time() - time_window

                cursor = self.db.conn.execute("""
                    SELECT dst_org, AVG(threat_score) as avg_threat
                    FROM connections
                    WHERE timestamp > ? AND timestamp <= ? AND dst_org IS NOT NULL
                    GROUP BY dst_org
                """, (start, end))

                return {row[0]: row[1] for row in cursor.fetchall()}

        except Exception:
            return {}

    def aggregate_geographic_intelligence(
        self,
        time_window: int = WINDOW_1HOUR,
        limit: int = 50
    ) -> List[GeographicIntel]:
        """
        Aggregate geographic intelligence with threat scoring

        Performance optimized: Single grouped query
        Target: <100ms

        Args:
            time_window: Time window in seconds (default: 1 hour)
            limit: Maximum number of countries to return

        Returns:
            List of GeographicIntel objects sorted by average threat
        """
        start_time = time.time()
        cache_key = f"geo_intel_{time_window}_{limit}"

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._update_query_stats((time.time() - start_time) * 1000, cache_hit=True)
            return cached

        if not self.db:
            return []

        try:
            self.db.flush()

            with self.db.lock:
                cutoff = time.time() - time_window

                cursor = self.db.conn.execute("""
                    SELECT
                        dst_country,
                        COUNT(*) as conn_count,
                        AVG(threat_score) as avg_threat,
                        MAX(threat_score) as max_threat,
                        COUNT(DISTINCT dst_ip) as unique_ips,
                        COUNT(DISTINCT dst_asn) as unique_asns
                    FROM connections
                    WHERE timestamp > ? AND dst_country IS NOT NULL
                    GROUP BY dst_country
                    ORDER BY avg_threat DESC
                    LIMIT ?
                """, (cutoff, limit))

                results = []

                for row in cursor.fetchall():
                    country = row[0]
                    conn_count = row[1]
                    avg_threat = row[2] or 0.0
                    max_threat = row[3] or 0.0
                    unique_ips = row[4]
                    unique_asns = row[5]

                    # Risk level
                    if avg_threat >= self.CRITICAL_THRESHOLD:
                        risk_level = "CRITICAL"
                    elif avg_threat >= self.WARNING_THRESHOLD:
                        risk_level = "HIGH"
                    elif avg_threat >= 0.2:
                        risk_level = "MEDIUM"
                    else:
                        risk_level = "LOW"

                    results.append(GeographicIntel(
                        country=country,
                        connection_count=conn_count,
                        avg_threat=avg_threat,
                        max_threat=max_threat,
                        unique_ips=unique_ips,
                        unique_asns=unique_asns,
                        risk_level=risk_level,
                    ))

                # Cache results
                self.cache.set(cache_key, results)

                query_time_ms = (time.time() - start_time) * 1000
                self._update_query_stats(query_time_ms, cache_hit=False)
                logger.debug(f"Geo intelligence aggregated in {query_time_ms:.2f}ms ({len(results)} countries)")

                return results

        except Exception as e:
            logger.error(f"Failed to aggregate geographic intelligence: {e}")
            return []

    def aggregate_temporal_trends(
        self,
        bucket_seconds: int = 60,
        window_minutes: int = 60
    ) -> List[TemporalTrend]:
        """
        Aggregate temporal trends with 1-minute buckets

        Performance optimized: Time-bucketed aggregation
        Target: <100ms

        Args:
            bucket_seconds: Bucket size in seconds (default: 60 = 1 minute)
            window_minutes: Total window in minutes (default: 60 = 1 hour)

        Returns:
            List of TemporalTrend objects with time-series data
        """
        start_time = time.time()
        cache_key = f"temporal_{bucket_seconds}_{window_minutes}"

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._update_query_stats((time.time() - start_time) * 1000, cache_hit=True)
            return cached

        if not self.db:
            return []

        try:
            self.db.flush()

            with self.db.lock:
                cutoff = time.time() - (window_minutes * 60)

                # Time bucketing using SQLite
                cursor = self.db.conn.execute("""
                    SELECT
                        CAST((timestamp / ?) AS INTEGER) * ? as bucket,
                        COUNT(*) as conn_count,
                        AVG(threat_score) as avg_threat,
                        COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as high_threat_count,
                        COUNT(DISTINCT dst_ip) as unique_ips
                    FROM connections
                    WHERE timestamp > ?
                    GROUP BY bucket
                    ORDER BY bucket ASC
                """, (bucket_seconds, bucket_seconds, cutoff))

                results = []

                for row in cursor.fetchall():
                    bucket_timestamp = row[0]
                    conn_count = row[1]
                    avg_threat = row[2] or 0.0
                    high_threat_count = row[3] or 0
                    unique_ips = row[4]

                    results.append(TemporalTrend(
                        timestamp=bucket_timestamp,
                        connection_count=conn_count,
                        avg_threat=avg_threat,
                        high_threat_count=high_threat_count,
                        unique_ips=unique_ips,
                    ))

                # Cache results
                self.cache.set(cache_key, results)

                query_time_ms = (time.time() - start_time) * 1000
                self._update_query_stats(query_time_ms, cache_hit=False)
                logger.debug(f"Temporal trends aggregated in {query_time_ms:.2f}ms ({len(results)} buckets)")

                return results

        except Exception as e:
            logger.error(f"Failed to aggregate temporal trends: {e}")
            return []

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get aggregator performance statistics"""
        cache_hit_rate = 0.0
        if self.stats["queries"] > 0:
            cache_hit_rate = (self.stats["cache_hits"] / self.stats["queries"]) * 100

        return {
            **self.stats,
            "cache_hit_rate": cache_hit_rate,
            "cache_size": self.cache.size(),
            "baseline_threat": self._baseline_threat,
            "baseline_age_seconds": time.time() - self._baseline_timestamp if self._baseline_timestamp else None,
        }

    def invalidate_cache(self):
        """Invalidate all cached data (useful after bulk data changes)"""
        self.cache.invalidate()
        logger.info("Intelligence cache invalidated")


# Convenience factory function
def create_intelligence_aggregator(db_connection=None, cache_ttl: float = 5.0) -> IntelligenceAggregator:
    """
    Create an IntelligenceAggregator instance

    Args:
        db_connection: Database connection from src.storage.database.Database
        cache_ttl: Cache time-to-live in seconds

    Returns:
        Configured IntelligenceAggregator
    """
    return IntelligenceAggregator(db_connection=db_connection, cache_ttl=cache_ttl)


if __name__ == "__main__":
    # Test with mock data
    logging.basicConfig(level=logging.DEBUG)

    print("=" * 70)
    print("Intelligence Aggregator Test")
    print("=" * 70)

    # This would normally use a real database connection
    aggregator = IntelligenceAggregator(db_connection=None)

    print(f"\nPerformance stats: {aggregator.get_performance_stats()}")
    print("\nNote: Connect to real database for full functionality")
