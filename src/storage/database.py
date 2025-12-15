"""
CobaltGraph Database Module - OPTIMIZED
High-performance SQLite operations with batching, WAL mode, and proper indexing

Performance optimizations:
- WAL (Write-Ahead Logging) for concurrent reads/writes
- Batch inserts with executemany()
- Connection pooling simulation with prepared statements
- Optimized PRAGMA settings for speed
- Composite indexes for common query patterns
- Async-friendly batch queue
"""

import logging
import sqlite3
import time
import threading
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, List, Optional, Tuple
from collections import deque
from contextlib import contextmanager

from src.utils.errors import DatabaseError

logger = logging.getLogger(__name__)


class Database:
    """
    High-performance SQLite database wrapper for CobaltGraph

    Features:
    - WAL mode for 10x faster concurrent writes
    - Batch inserts (100x faster than individual commits)
    - Prepared statement caching
    - Thread-safe operations with minimal lock contention
    - Auto-flush with configurable batch size and timeout
    """

    # Batch configuration
    BATCH_SIZE = 50  # Flush after N pending inserts
    BATCH_TIMEOUT = 0.5  # Flush after N seconds regardless of size (faster for dashboard)

    # Column definitions for batch operations
    INSERT_COLUMNS = [
        "timestamp", "src_mac", "src_ip", "dst_ip", "dst_port",
        "dst_country", "dst_lat", "dst_lon", "dst_org", "dst_hostname",
        "threat_score", "device_vendor", "protocol",
        "dst_asn", "dst_asn_name", "dst_org_type", "dst_cidr",
        "ttl_observed", "ttl_initial", "hop_count", "os_fingerprint", "org_trust_score",
        "confidence", "high_uncertainty", "scoring_method",
        # Individual scorer results (Phase 1 - Dashboard Evolution)
        "score_statistical", "score_rule_based", "score_ml_based", "score_organization",
        "anomaly_score", "score_spread"
    ]

    def __init__(self, db_path: str = "database/cobaltgraph.db"):
        """Initialize optimized database connection"""
        self.db_path = db_path
        self.lock = Lock()
        self.conn = None

        # Batch insert queue
        self._pending_inserts: deque = deque()
        self._batch_lock = Lock()
        self._last_flush = time.time()
        self._flush_thread: Optional[Thread] = None
        self._running = True

        # Statistics
        self.stats = {
            "total_inserts": 0,
            "batch_flushes": 0,
            "avg_batch_size": 0,
        }

        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise DatabaseError(f"Failed to create database directory: {e}")

        try:
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self._optimize_connection()
            self._init_schema()
            self._start_flush_thread()
            logger.info("📁 Database initialized (optimized): %s", self.db_path)
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}")

    def _optimize_connection(self):
        """Apply performance-critical PRAGMA settings"""
        pragmas = [
            # WAL mode - allows concurrent reads during writes
            "PRAGMA journal_mode=WAL",
            # Normal sync - faster, still safe (fsync on checkpoint only)
            "PRAGMA synchronous=NORMAL",
            # 64MB cache in memory
            "PRAGMA cache_size=-65536",
            # Store temp tables in memory
            "PRAGMA temp_store=MEMORY",
            # Enable memory-mapped I/O (256MB)
            "PRAGMA mmap_size=268435456",
            # Increase page size for better throughput
            "PRAGMA page_size=4096",
            # Optimize for concurrent access
            "PRAGMA wal_autocheckpoint=1000",
        ]

        for pragma in pragmas:
            try:
                self.conn.execute(pragma)
            except sqlite3.Error as e:
                logger.debug(f"PRAGMA setting skipped: {pragma} - {e}")

        self.conn.commit()
        logger.debug("Database optimizations applied (WAL mode, 64MB cache)")

    def _init_schema(self):
        """Initialize optimized database schema with proper indexes"""
        try:
            with self.lock:
                # Main connections table
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        src_mac TEXT,
                        src_ip TEXT,
                        dst_ip TEXT NOT NULL,
                        dst_port INTEGER NOT NULL,
                        dst_country TEXT,
                        dst_lat REAL,
                        dst_lon REAL,
                        dst_org TEXT,
                        dst_hostname TEXT,
                        threat_score REAL DEFAULT 0,
                        device_vendor TEXT,
                        protocol TEXT DEFAULT 'TCP',
                        dst_asn INTEGER,
                        dst_asn_name TEXT,
                        dst_org_type TEXT,
                        dst_cidr TEXT,
                        ttl_observed INTEGER,
                        ttl_initial INTEGER,
                        hop_count INTEGER,
                        os_fingerprint TEXT,
                        org_trust_score REAL,
                        confidence REAL DEFAULT 0,
                        high_uncertainty INTEGER DEFAULT 0,
                        scoring_method TEXT DEFAULT 'consensus',
                        -- Individual scorer results (Dashboard Evolution)
                        score_statistical REAL,
                        score_rule_based REAL,
                        score_ml_based REAL,
                        score_organization REAL,
                        anomaly_score REAL,
                        score_spread REAL
                    )
                """)

                # Performance indexes - covering indexes for common queries
                indexes = [
                    # Primary time-series access pattern
                    ("idx_timestamp_desc", "connections(timestamp DESC)"),
                    # Threat dashboard queries
                    ("idx_threat_time", "connections(threat_score DESC, timestamp DESC)"),
                    # Device tracking
                    ("idx_src_mac", "connections(src_mac)"),
                    # ASN analysis
                    ("idx_dst_asn", "connections(dst_asn)"),
                    # Organization type grouping
                    ("idx_org_type", "connections(dst_org_type)"),
                    # IP lookups
                    ("idx_dst_ip", "connections(dst_ip)"),
                    # Composite for geo-threat queries
                    ("idx_geo_threat", "connections(dst_country, threat_score DESC)"),
                    # Time-range with org type (dashboard filters)
                    ("idx_time_org", "connections(timestamp DESC, dst_org_type)"),
                ]

                for idx_name, idx_def in indexes:
                    try:
                        self.conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")
                    except sqlite3.Error:
                        pass  # Index might already exist

                self._migrate_schema()

                # Events table for logging and alerts
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT DEFAULT 'INFO',
                        message TEXT,
                        source_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        threat_score REAL,
                        org_name TEXT,
                        rule_matched TEXT,
                        metadata TEXT
                    )
                """)

                # Event indexes
                event_indexes = [
                    ("idx_event_time", "events(timestamp DESC)"),
                    ("idx_event_severity", "events(severity, timestamp DESC)"),
                    ("idx_event_type", "events(event_type, timestamp DESC)"),
                ]

                for idx_name, idx_def in event_indexes:
                    try:
                        self.conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")
                    except sqlite3.Error:
                        pass

                # Discovered devices table (network mode)
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        mac TEXT PRIMARY KEY,
                        ip_addresses TEXT,
                        vendor TEXT,
                        hostname TEXT,
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        packet_count INTEGER DEFAULT 0,
                        connection_count INTEGER DEFAULT 0,
                        threat_score_sum REAL DEFAULT 0,
                        high_threat_count INTEGER DEFAULT 0,
                        broadcast_count INTEGER DEFAULT 0,
                        arp_count INTEGER DEFAULT 0,
                        is_active INTEGER DEFAULT 1,
                        risk_flags TEXT,
                        notes TEXT
                    )
                """)

                # Device indexes
                device_indexes = [
                    ("idx_device_last_seen", "devices(last_seen DESC)"),
                    ("idx_device_threat", "devices(threat_score_sum DESC)"),
                    ("idx_device_active", "devices(is_active, last_seen DESC)"),
                ]

                for idx_name, idx_def in device_indexes:
                    try:
                        self.conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")
                    except sqlite3.Error:
                        pass

                # Create optimized views for intelligence dashboard
                self._create_intelligence_views()

                self.conn.commit()
                logger.debug("Optimized schema initialized with %d indexes", len(indexes))

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize schema: {e}")

    def _migrate_schema(self):
        """Migrate existing database to add new columns"""
        new_columns = [
            ("dst_asn", "INTEGER"),
            ("dst_asn_name", "TEXT"),
            ("dst_org_type", "TEXT"),
            ("dst_cidr", "TEXT"),
            ("ttl_observed", "INTEGER"),
            ("ttl_initial", "INTEGER"),
            ("hop_count", "INTEGER"),
            ("os_fingerprint", "TEXT"),
            ("org_trust_score", "REAL"),
            # Scoring metadata columns for dashboard
            ("confidence", "REAL DEFAULT 0"),
            ("high_uncertainty", "INTEGER DEFAULT 0"),
            ("scoring_method", "TEXT DEFAULT 'consensus'"),
            # Individual scorer results (Dashboard Evolution)
            ("score_statistical", "REAL"),
            ("score_rule_based", "REAL"),
            ("score_ml_based", "REAL"),
            ("score_organization", "REAL"),
            ("anomaly_score", "REAL"),
            ("score_spread", "REAL"),
        ]

        cursor = self.conn.execute("PRAGMA table_info(connections)")
        existing = {row[1] for row in cursor.fetchall()}

        for col_name, col_type in new_columns:
            if col_name not in existing:
                try:
                    self.conn.execute(f"ALTER TABLE connections ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Migrated: added column {col_name}")
                except sqlite3.Error:
                    pass

    def _create_intelligence_views(self):
        """
        Create optimized database views for intelligence aggregation

        These views provide pre-computed aggregations for dashboard queries,
        dramatically improving performance for common intelligence queries
        """
        try:
            # Threat posture view - 5 minute window
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS threat_posture_5min AS
                SELECT
                    AVG(threat_score) as current_threat,
                    COUNT(*) as total_connections,
                    COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as high_threats,
                    COUNT(CASE WHEN threat_score > 0.4 AND threat_score <= 0.7 THEN 1 END) as medium_threats,
                    MAX(timestamp) as latest_timestamp,
                    MIN(timestamp) as earliest_timestamp
                FROM connections
                WHERE timestamp > (SELECT MAX(timestamp) FROM connections) - 300
            """)

            # Organization intelligence view - 1 hour window
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS org_intelligence_1hour AS
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
                WHERE timestamp > (SELECT MAX(timestamp) FROM connections) - 3600
                  AND dst_org IS NOT NULL
                GROUP BY dst_org, dst_org_type
                ORDER BY conn_count DESC
            """)

            # Geographic intelligence view - 1 hour window
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS geo_intelligence_1hour AS
                SELECT
                    dst_country,
                    COUNT(*) as conn_count,
                    AVG(threat_score) as avg_threat,
                    MAX(threat_score) as max_threat,
                    COUNT(DISTINCT dst_ip) as unique_ips,
                    COUNT(DISTINCT dst_asn) as unique_asns
                FROM connections
                WHERE timestamp > (SELECT MAX(timestamp) FROM connections) - 3600
                  AND dst_country IS NOT NULL
                GROUP BY dst_country
                ORDER BY avg_threat DESC
            """)

            # Temporal trends view - 1 minute buckets, last hour
            # Note: This is a template; actual queries will use parameterized time buckets
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS temporal_trends_1hour AS
                SELECT
                    CAST((timestamp / 60) AS INTEGER) * 60 as time_bucket,
                    COUNT(*) as conn_count,
                    AVG(threat_score) as avg_threat,
                    COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as high_threat_count,
                    COUNT(DISTINCT dst_ip) as unique_ips
                FROM connections
                WHERE timestamp > (SELECT MAX(timestamp) FROM connections) - 3600
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """)

            # High-value connections view - for alert generation
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS high_value_connections AS
                SELECT
                    src_ip, src_mac, dst_ip, dst_port, dst_org, dst_org_type,
                    threat_score, timestamp, device_vendor,
                    dst_asn, dst_country, org_trust_score
                FROM connections
                WHERE threat_score > 0.4
                   OR dst_org_type IN ('tor_proxy', 'vpn', 'hosting')
                ORDER BY timestamp DESC
            """)

            # ASN intelligence view
            self.conn.execute("""
                CREATE VIEW IF NOT EXISTS asn_intelligence_1hour AS
                SELECT
                    dst_asn,
                    dst_asn_name,
                    COUNT(*) as conn_count,
                    AVG(threat_score) as avg_threat,
                    MAX(threat_score) as max_threat,
                    COUNT(DISTINCT dst_ip) as unique_ips,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM connections
                WHERE timestamp > (SELECT MAX(timestamp) FROM connections) - 3600
                  AND dst_asn IS NOT NULL
                GROUP BY dst_asn, dst_asn_name
                ORDER BY avg_threat DESC
            """)

            logger.debug("Intelligence views created successfully")

        except sqlite3.Error as e:
            logger.warning(f"Failed to create intelligence views: {e}")

    def _start_flush_thread(self):
        """Start background thread for periodic batch flushing"""
        self._flush_thread = Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def _flush_loop(self):
        """Background loop to flush batches on timeout"""
        while self._running:
            time.sleep(0.5)  # Check every 500ms

            with self._batch_lock:
                elapsed = time.time() - self._last_flush
                pending_count = len(self._pending_inserts)

            if pending_count > 0 and elapsed >= self.BATCH_TIMEOUT:
                self._flush_batch()

    def _conn_to_tuple(self, conn_data: Dict) -> Tuple:
        """Convert connection dict to tuple for batch insert"""
        return (
            conn_data.get("timestamp", time.time()),
            conn_data.get("src_mac"),
            conn_data.get("src_ip"),
            conn_data.get("dst_ip"),
            conn_data.get("dst_port"),
            conn_data.get("dst_country"),
            conn_data.get("dst_lat"),
            conn_data.get("dst_lon"),
            conn_data.get("dst_org"),
            conn_data.get("dst_hostname"),
            conn_data.get("threat_score", 0),
            conn_data.get("device_vendor"),
            conn_data.get("protocol", "TCP"),
            conn_data.get("dst_asn"),
            conn_data.get("dst_asn_name"),
            conn_data.get("dst_org_type"),
            conn_data.get("dst_cidr"),
            conn_data.get("ttl_observed"),
            conn_data.get("ttl_initial"),
            conn_data.get("hop_count"),
            conn_data.get("os_fingerprint"),
            conn_data.get("org_trust_score"),
            conn_data.get("confidence", 0),
            1 if conn_data.get("high_uncertainty") else 0,
            conn_data.get("scoring_method", "consensus"),
            # Individual scorer results (Phase 1 - Dashboard Evolution)
            conn_data.get("score_statistical"),
            conn_data.get("score_rule_based"),
            conn_data.get("score_ml_based"),
            conn_data.get("score_organization"),
            conn_data.get("anomaly_score"),
            conn_data.get("score_spread"),
        )

    def _flush_batch(self):
        """Flush pending inserts to database using executemany"""
        with self._batch_lock:
            if not self._pending_inserts:
                return

            # Grab all pending and clear queue
            batch = list(self._pending_inserts)
            self._pending_inserts.clear()
            self._last_flush = time.time()

        if not batch:
            return

        try:
            with self.lock:
                placeholders = ", ".join(["?"] * len(self.INSERT_COLUMNS))
                columns = ", ".join(self.INSERT_COLUMNS)

                self.conn.executemany(
                    f"INSERT INTO connections ({columns}) VALUES ({placeholders})",
                    batch
                )
                self.conn.commit()

            # Update stats
            self.stats["total_inserts"] += len(batch)
            self.stats["batch_flushes"] += 1
            self.stats["avg_batch_size"] = (
                self.stats["total_inserts"] / self.stats["batch_flushes"]
            )

            logger.debug(f"Batch flush: {len(batch)} connections (avg: {self.stats['avg_batch_size']:.1f})")

        except sqlite3.Error as e:
            logger.error(f"Batch insert failed: {e}")
            # Re-queue failed batch for retry
            with self._batch_lock:
                self._pending_inserts.extendleft(batch)

    def add_connection(self, conn_data: Dict):
        """
        Add connection to batch queue (non-blocking)

        Connections are queued and flushed in batches for 10-100x performance gain.
        """
        if not conn_data.get("dst_ip") or not conn_data.get("dst_port"):
            raise DatabaseError("Missing required fields: dst_ip and dst_port")

        conn_tuple = self._conn_to_tuple(conn_data)

        with self._batch_lock:
            self._pending_inserts.append(conn_tuple)
            pending_count = len(self._pending_inserts)

        # Flush if batch size reached
        if pending_count >= self.BATCH_SIZE:
            self._flush_batch()

    def add_connection_immediate(self, conn_data: Dict):
        """Add connection with immediate commit (for critical data)"""
        if not conn_data.get("dst_ip") or not conn_data.get("dst_port"):
            raise DatabaseError("Missing required fields: dst_ip and dst_port")

        try:
            with self.lock:
                placeholders = ", ".join(["?"] * len(self.INSERT_COLUMNS))
                columns = ", ".join(self.INSERT_COLUMNS)

                self.conn.execute(
                    f"INSERT INTO connections ({columns}) VALUES ({placeholders})",
                    self._conn_to_tuple(conn_data)
                )
                self.conn.commit()

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to add connection: {e}")

    def add_connections_batch(self, connections: List[Dict]):
        """Bulk insert multiple connections at once"""
        if not connections:
            return

        batch = [self._conn_to_tuple(c) for c in connections if c.get("dst_ip") and c.get("dst_port")]

        if not batch:
            return

        try:
            with self.lock:
                placeholders = ", ".join(["?"] * len(self.INSERT_COLUMNS))
                columns = ", ".join(self.INSERT_COLUMNS)

                self.conn.executemany(
                    f"INSERT INTO connections ({columns}) VALUES ({placeholders})",
                    batch
                )
                self.conn.commit()

            self.stats["total_inserts"] += len(batch)
            logger.debug(f"Bulk inserted {len(batch)} connections")

        except sqlite3.Error as e:
            raise DatabaseError(f"Bulk insert failed: {e}")

    def get_recent_connections(self, limit: int = 50) -> List[Dict]:
        """Get recent connections with optimized query"""
        # Flush pending to ensure we get latest data
        self._flush_batch()

        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon,
                           dst_org, dst_hostname, threat_score, timestamp, device_vendor, protocol,
                           dst_asn, dst_asn_name, dst_org_type, dst_cidr,
                           ttl_observed, ttl_initial, hop_count, os_fingerprint, org_trust_score
                    FROM connections
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

                columns = [
                    "src_mac", "src_ip", "dst_ip", "dst_port", "dst_country",
                    "dst_lat", "dst_lon", "dst_org", "dst_hostname", "threat_score",
                    "timestamp", "device_vendor", "protocol",
                    "dst_asn", "dst_asn_name", "dst_org_type", "dst_cidr",
                    "ttl_observed", "ttl_initial", "hop_count", "os_fingerprint", "org_trust_score"
                ]

                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve connections: {e}")

    def get_connection_count(self) -> int:
        """Fast connection count (cached in SQLite)"""
        try:
            with self.lock:
                cursor = self.conn.execute("SELECT COUNT(*) FROM connections")
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get count: {e}")

    def get_threat_summary(self) -> Dict:
        """Get aggregated threat statistics (single optimized query)"""
        self._flush_batch()

        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT
                        COUNT(*) as total,
                        AVG(threat_score) as avg_threat,
                        MAX(threat_score) as max_threat,
                        SUM(CASE WHEN threat_score >= 0.7 THEN 1 ELSE 0 END) as high_threats,
                        SUM(CASE WHEN threat_score >= 0.4 AND threat_score < 0.7 THEN 1 ELSE 0 END) as med_threats,
                        COUNT(DISTINCT dst_ip) as unique_ips,
                        COUNT(DISTINCT dst_asn) as unique_asns,
                        COUNT(DISTINCT dst_org_type) as org_types
                    FROM connections
                    WHERE timestamp > ?
                """, (time.time() - 3600,))  # Last hour

                row = cursor.fetchone()
                return {
                    "total_connections": row[0],
                    "avg_threat_score": row[1] or 0,
                    "max_threat_score": row[2] or 0,
                    "high_threat_count": row[3],
                    "medium_threat_count": row[4],
                    "unique_destinations": row[5],
                    "unique_asns": row[6],
                    "org_type_diversity": row[7],
                }

        except sqlite3.Error as e:
            logger.error(f"Failed to get threat summary: {e}")
            return {}

    def get_org_type_breakdown(self) -> List[Dict]:
        """Get connections grouped by organization type"""
        self._flush_batch()

        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT
                        COALESCE(dst_org_type, 'unknown') as org_type,
                        COUNT(*) as count,
                        AVG(threat_score) as avg_threat,
                        AVG(org_trust_score) as avg_trust
                    FROM connections
                    WHERE timestamp > ?
                    GROUP BY dst_org_type
                    ORDER BY count DESC
                """, (time.time() - 3600,))

                return [
                    {
                        "org_type": row[0],
                        "count": row[1],
                        "avg_threat": row[2] or 0,
                        "avg_trust": row[3] or 0.5,
                    }
                    for row in cursor.fetchall()
                ]

        except sqlite3.Error as e:
            logger.error(f"Failed to get org breakdown: {e}")
            return []

    def get_geo_heatmap_data(self, time_window: int = 3600) -> List[Dict]:
        """Get geographic aggregation for heatmap visualization"""
        self._flush_batch()

        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT
                        dst_lat, dst_lon, dst_country,
                        COUNT(*) as intensity,
                        AVG(threat_score) as avg_threat,
                        MAX(threat_score) as max_threat
                    FROM connections
                    WHERE timestamp > ? AND dst_lat IS NOT NULL
                    GROUP BY ROUND(dst_lat, 1), ROUND(dst_lon, 1)
                    ORDER BY intensity DESC
                    LIMIT 500
                """, (time.time() - time_window,))

                return [
                    {
                        "lat": row[0],
                        "lon": row[1],
                        "country": row[2],
                        "intensity": row[3],
                        "avg_threat": row[4] or 0,
                        "max_threat": row[5] or 0,
                    }
                    for row in cursor.fetchall()
                ]

        except sqlite3.Error as e:
            logger.error(f"Failed to get geo data: {e}")
            return []

    def vacuum(self):
        """Optimize database file (run during low activity)"""
        self._flush_batch()
        try:
            with self.lock:
                self.conn.execute("VACUUM")
                self.conn.execute("ANALYZE")
            logger.info("Database optimized (VACUUM + ANALYZE)")
        except sqlite3.Error as e:
            logger.warning(f"Vacuum failed: {e}")

    def flush(self):
        """Force flush pending batch"""
        self._flush_batch()

    def get_stats(self) -> Dict:
        """Get database performance statistics"""
        return {
            **self.stats,
            "pending_inserts": len(self._pending_inserts),
            "db_size_mb": Path(self.db_path).stat().st_size / (1024 * 1024) if Path(self.db_path).exists() else 0,
        }

    # =========================================================================
    # EVENT LOGGING METHODS
    # =========================================================================

    def log_event(self, event_type: str, message: str, severity: str = "INFO",
                  source_ip: str = None, dst_ip: str = None, dst_port: int = None,
                  threat_score: float = None, org_name: str = None,
                  rule_matched: str = None, metadata: str = None):
        """
        Log an event to the events table

        Args:
            event_type: Type of event (CONNECTION, THREAT, ALERT, SYSTEM, etc.)
            message: Human-readable event description
            severity: Event severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            source_ip: Source IP address (if applicable)
            dst_ip: Destination IP address (if applicable)
            dst_port: Destination port (if applicable)
            threat_score: Associated threat score (0.0-1.0)
            org_name: Organization name (if applicable)
            rule_matched: Rule/signature that triggered the event
            metadata: JSON string of additional metadata
        """
        try:
            with self.lock:
                self.conn.execute("""
                    INSERT INTO events (
                        timestamp, event_type, severity, message,
                        source_ip, dst_ip, dst_port, threat_score,
                        org_name, rule_matched, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    time.time(), event_type, severity, message,
                    source_ip, dst_ip, dst_port, threat_score,
                    org_name, rule_matched, metadata
                ))
                self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Failed to log event: {e}")

    def get_recent_events(self, limit: int = 100, severity: str = None,
                          event_type: str = None) -> List[Dict]:
        """
        Get recent events with optional filtering

        Args:
            limit: Maximum number of events to return
            severity: Filter by severity level (CRITICAL, HIGH, etc.)
            event_type: Filter by event type

        Returns:
            List of event dictionaries
        """
        try:
            with self.lock:
                query = """
                    SELECT timestamp, event_type, severity, message,
                           source_ip, dst_ip, dst_port, threat_score,
                           org_name, rule_matched, metadata
                    FROM events
                """
                params = []
                conditions = []

                if severity:
                    conditions.append("severity = ?")
                    params.append(severity)

                if event_type:
                    conditions.append("event_type = ?")
                    params.append(event_type)

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor = self.conn.execute(query, params)

                columns = [
                    "timestamp", "event_type", "severity", "message",
                    "source_ip", "dst_ip", "dst_port", "threat_score",
                    "org_name", "rule_matched", "metadata"
                ]

                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Failed to get events: {e}")
            return []

    def get_event_summary(self, time_window: int = 3600) -> Dict:
        """
        Get summary of events in time window

        Args:
            time_window: Seconds to look back (default: 1 hour)

        Returns:
            Dictionary with event counts by severity
        """
        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
                        SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END) as info
                    FROM events
                    WHERE timestamp > ?
                """, (time.time() - time_window,))

                row = cursor.fetchone()
                return {
                    "total": row[0] or 0,
                    "critical": row[1] or 0,
                    "high": row[2] or 0,
                    "medium": row[3] or 0,
                    "low": row[4] or 0,
                    "info": row[5] or 0,
                }

        except sqlite3.Error as e:
            logger.error(f"Failed to get event summary: {e}")
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def cleanup_old_events(self, max_age_days: int = 7):
        """
        Delete events older than specified age

        Args:
            max_age_days: Maximum age in days (default: 7)
        """
        try:
            with self.lock:
                cutoff = time.time() - (max_age_days * 86400)
                cursor = self.conn.execute(
                    "DELETE FROM events WHERE timestamp < ?", (cutoff,)
                )
                deleted = cursor.rowcount
                self.conn.commit()

                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} old events")

        except sqlite3.Error as e:
            logger.error(f"Failed to cleanup events: {e}")

    # =========================================================================
    # DEVICE DISCOVERY METHODS (Network Mode)
    # =========================================================================

    def upsert_device(self, mac: str, ip: str = None, vendor: str = None,
                      hostname: str = None, packet_type: str = None,
                      threat_score: float = 0.0):
        """
        Insert or update a discovered device

        Args:
            mac: MAC address (primary key)
            ip: IP address observed
            vendor: Vendor name from OUI lookup
            hostname: Hostname if discovered
            packet_type: Type of packet (arp, broadcast, connection)
            threat_score: Threat score from associated connection
        """
        import json
        now = time.time()

        try:
            with self.lock:
                # Check if device exists
                cursor = self.conn.execute(
                    "SELECT ip_addresses, packet_count, connection_count, "
                    "threat_score_sum, high_threat_count, broadcast_count, arp_count "
                    "FROM devices WHERE mac = ?",
                    (mac,)
                )
                existing = cursor.fetchone()

                if existing:
                    # Update existing device
                    ip_addresses = json.loads(existing[0]) if existing[0] else []
                    if ip and ip not in ip_addresses:
                        ip_addresses.append(ip)

                    packet_count = existing[1] + 1
                    connection_count = existing[2]
                    threat_sum = existing[3]
                    high_threat_count = existing[4]
                    broadcast_count = existing[5]
                    arp_count = existing[6]

                    # Update counters based on packet type
                    if packet_type == 'connection':
                        connection_count += 1
                        threat_sum += threat_score
                        if threat_score >= 0.5:
                            high_threat_count += 1
                    elif packet_type == 'broadcast':
                        broadcast_count += 1
                    elif packet_type == 'arp':
                        arp_count += 1

                    self.conn.execute("""
                        UPDATE devices SET
                            ip_addresses = ?,
                            vendor = COALESCE(?, vendor),
                            hostname = COALESCE(?, hostname),
                            last_seen = ?,
                            packet_count = ?,
                            connection_count = ?,
                            threat_score_sum = ?,
                            high_threat_count = ?,
                            broadcast_count = ?,
                            arp_count = ?,
                            is_active = 1
                        WHERE mac = ?
                    """, (
                        json.dumps(ip_addresses), vendor, hostname, now,
                        packet_count, connection_count, threat_sum,
                        high_threat_count, broadcast_count, arp_count, mac
                    ))
                else:
                    # Insert new device
                    ip_addresses = [ip] if ip else []
                    connection_count = 1 if packet_type == 'connection' else 0
                    broadcast_count = 1 if packet_type == 'broadcast' else 0
                    arp_count = 1 if packet_type == 'arp' else 0
                    high_threat_count = 1 if threat_score >= 0.5 else 0

                    self.conn.execute("""
                        INSERT INTO devices (
                            mac, ip_addresses, vendor, hostname,
                            first_seen, last_seen, packet_count,
                            connection_count, threat_score_sum, high_threat_count,
                            broadcast_count, arp_count, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 1)
                    """, (
                        mac, json.dumps(ip_addresses), vendor, hostname,
                        now, now, connection_count, threat_score,
                        high_threat_count, broadcast_count, arp_count
                    ))

                self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Failed to upsert device: {e}")

    def get_discovered_devices(self, active_only: bool = False,
                                limit: int = 100) -> List[Dict]:
        """
        Get list of discovered devices

        Args:
            active_only: Only return devices seen in last 5 minutes
            limit: Maximum number of devices to return

        Returns:
            List of device dictionaries with threat scoring
        """
        import json

        try:
            with self.lock:
                if active_only:
                    cutoff = time.time() - 300  # 5 minutes
                    cursor = self.conn.execute("""
                        SELECT mac, ip_addresses, vendor, hostname,
                               first_seen, last_seen, packet_count,
                               connection_count, threat_score_sum, high_threat_count,
                               broadcast_count, arp_count, risk_flags, notes
                        FROM devices
                        WHERE last_seen > ?
                        ORDER BY last_seen DESC
                        LIMIT ?
                    """, (cutoff, limit))
                else:
                    cursor = self.conn.execute("""
                        SELECT mac, ip_addresses, vendor, hostname,
                               first_seen, last_seen, packet_count,
                               connection_count, threat_score_sum, high_threat_count,
                               broadcast_count, arp_count, risk_flags, notes
                        FROM devices
                        ORDER BY last_seen DESC
                        LIMIT ?
                    """, (limit,))

                devices = []
                now = time.time()

                for row in cursor.fetchall():
                    mac = row[0]
                    ip_addresses = json.loads(row[1]) if row[1] else []
                    connection_count = row[7] or 0
                    threat_sum = row[8] or 0
                    high_threat_count = row[9] or 0
                    broadcast_count = row[10] or 0
                    arp_count = row[11] or 0

                    # Calculate average threat score
                    avg_threat = threat_sum / connection_count if connection_count > 0 else 0

                    # Calculate risk level based on available passive indicators
                    risk_flags = []
                    risk_score = 0.0

                    # Unknown vendor is suspicious
                    if not row[2]:
                        risk_flags.append("UNKNOWN_VENDOR")
                        risk_score += 0.2

                    # Multiple IPs could indicate spoofing
                    if len(ip_addresses) > 3:
                        risk_flags.append("MULTI_IP")
                        risk_score += 0.15

                    # High broadcast rate (relative)
                    if broadcast_count > 100:
                        risk_flags.append("HIGH_BROADCAST")
                        risk_score += 0.1

                    # High threat connections (if we see them)
                    if high_threat_count > 0:
                        risk_flags.append(f"HIGH_THREAT_CONNS:{high_threat_count}")
                        risk_score += min(0.4, high_threat_count * 0.1)

                    # Average threat from connections
                    risk_score += avg_threat * 0.3

                    # Determine threat level
                    if risk_score >= 0.5:
                        threat_level = "HIGH"
                    elif risk_score >= 0.25:
                        threat_level = "MEDIUM"
                    else:
                        threat_level = "LOW"

                    devices.append({
                        "mac": mac,
                        "ip_addresses": ip_addresses,
                        "primary_ip": ip_addresses[0] if ip_addresses else None,
                        "vendor": row[2] or "Unknown",
                        "hostname": row[3],
                        "first_seen": row[4],
                        "last_seen": row[5],
                        "packet_count": row[6] or 0,
                        "connection_count": connection_count,
                        "avg_threat": avg_threat,
                        "high_threat_count": high_threat_count,
                        "broadcast_count": broadcast_count,
                        "arp_count": arp_count,
                        "risk_score": min(1.0, risk_score),
                        "threat_level": threat_level,
                        "risk_flags": risk_flags,
                        "is_active": (now - row[5]) < 300,
                        "notes": row[13],
                    })

                return devices

        except sqlite3.Error as e:
            logger.error(f"Failed to get devices: {e}")
            return []

    def get_device_by_mac(self, mac: str) -> Optional[Dict]:
        """Get a single device by MAC address"""
        devices = self.get_discovered_devices(limit=1)
        # Re-query with filter
        import json
        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT mac, ip_addresses, vendor, hostname,
                           first_seen, last_seen, packet_count,
                           connection_count, threat_score_sum, high_threat_count,
                           broadcast_count, arp_count, risk_flags, notes
                    FROM devices WHERE mac = ?
                """, (mac,))
                row = cursor.fetchone()
                if row:
                    ip_addresses = json.loads(row[1]) if row[1] else []
                    connection_count = row[7] or 0
                    threat_sum = row[8] or 0
                    avg_threat = threat_sum / connection_count if connection_count > 0 else 0

                    return {
                        "mac": row[0],
                        "ip_addresses": ip_addresses,
                        "primary_ip": ip_addresses[0] if ip_addresses else None,
                        "vendor": row[2] or "Unknown",
                        "hostname": row[3],
                        "first_seen": row[4],
                        "last_seen": row[5],
                        "packet_count": row[6] or 0,
                        "connection_count": connection_count,
                        "avg_threat": avg_threat,
                    }
        except sqlite3.Error as e:
            logger.error(f"Failed to get device: {e}")
        return None

    def get_connections_by_device(self, mac: str, limit: int = 100) -> List[Dict]:
        """Get connections made by a specific device (for drill-down)"""
        self._flush_batch()

        try:
            with self.lock:
                cursor = self.conn.execute("""
                    SELECT src_mac, src_ip, dst_ip, dst_port, dst_country, dst_lat, dst_lon,
                           dst_org, dst_hostname, threat_score, timestamp, device_vendor, protocol,
                           dst_asn, dst_asn_name, dst_org_type, dst_cidr,
                           ttl_observed, ttl_initial, hop_count, os_fingerprint, org_trust_score
                    FROM connections
                    WHERE src_mac = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (mac, limit))

                columns = [
                    "src_mac", "src_ip", "dst_ip", "dst_port", "dst_country",
                    "dst_lat", "dst_lon", "dst_org", "dst_hostname", "threat_score",
                    "timestamp", "device_vendor", "protocol",
                    "dst_asn", "dst_asn_name", "dst_org_type", "dst_cidr",
                    "ttl_observed", "ttl_initial", "hop_count", "os_fingerprint", "org_trust_score"
                ]

                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Failed to get device connections: {e}")
            return []

    def get_device_count(self, active_only: bool = False) -> int:
        """Get count of discovered devices"""
        try:
            with self.lock:
                if active_only:
                    cutoff = time.time() - 300
                    cursor = self.conn.execute(
                        "SELECT COUNT(*) FROM devices WHERE last_seen > ?",
                        (cutoff,)
                    )
                else:
                    cursor = self.conn.execute("SELECT COUNT(*) FROM devices")
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Failed to get device count: {e}")
            return 0

    def update_device_activity(self):
        """Mark devices as inactive if not seen recently"""
        try:
            with self.lock:
                cutoff = time.time() - 300  # 5 minutes
                self.conn.execute(
                    "UPDATE devices SET is_active = 0 WHERE last_seen < ? AND is_active = 1",
                    (cutoff,)
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to update device activity: {e}")

    def close(self):
        """Close database with final flush"""
        self._running = False

        # Final flush
        self._flush_batch()

        if self._flush_thread:
            self._flush_thread.join(timeout=2.0)

        if self.conn:
            try:
                # Checkpoint WAL before close
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.conn.close()
                logger.info("📁 Database closed (flushed %d total connections)", self.stats["total_inserts"])
            except sqlite3.Error as e:
                logger.warning(f"Error closing database: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
