#!/usr/bin/env python3
"""
CobaltGraph Enhanced Base Reconnaissance Dashboard

Unified base framework for device and network mode dashboards with:
- Integrated DeviceReconnaissanceEngine for device tracking
- 3-Color Theme: Cyan (primary), Yellow (warning), Red (danger)
- Mode-aware reconnaissance visualization
- Pipeline event integration with device state machine

Provides a solid foundation for both DeviceDashboard and NetworkDashboard
with consistent reconnaissance capabilities.
"""

import logging
import sqlite3
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional
import time

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer
from textual.reactive import reactive

from src.ui.reconnaissance import DeviceReconnaissanceEngine, DeviceReconRecord

logger = logging.getLogger(__name__)

# 3-Color Theming: Cyan (primary), Yellow (warning), Red (danger)
THEME_COLORS = {
    "primary": "$cyan",      # Cyan for primary elements
    "warning": "$yellow",    # Yellow for warnings/caution
    "danger": "$red",        # Red for high-threat/critical
}


class BaseReconnaissanceDashboard(App):
    """
    Enhanced base dashboard with reconnaissance capabilities

    Features:
    - Unified database access with caching
    - Device reconnaissance engine (device state machine)
    - Mode detection (device vs network)
    - Consistent refresh intervals (2s data, 1s UI)
    - Shared keyboard bindings
    - Performance monitoring
    - 3-color theme consistency
    """

    # CSS styling with 3-color theme
    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        dock: top;
        height: 2;
        background: $surface;
        color: $text;
        border: solid $cyan;
    }

    Footer {
        dock: bottom;
        height: 2;
        background: $surface;
        color: $text;
        border: solid $cyan;
    }
    """

    # Reactive properties
    stats = reactive(dict)
    mode = reactive(str)
    is_connected = reactive(bool, init=False)

    # Threat level colors (using 3-color palette)
    THREAT_COLORS = {
        'LOW': 'green',
        'MEDIUM': 'yellow',           # Yellow warning
        'HIGH': 'bold yellow',
        'CRITICAL': 'red',            # Red danger
        'SEVERE': 'bold red',
    }

    def __init__(
        self,
        db_path: str = "data/cobaltgraph.db",
        mode: str = "device",
        pipeline=None
    ):
        """
        Initialize base reconnaissance dashboard

        Args:
            db_path: Path to SQLite database
            mode: "device" or "network"
            pipeline: DataPipeline reference for live updates
        """
        super().__init__()
        self.db_path = Path(db_path)
        self.mode = mode
        self.is_connected = False
        self.pipeline = pipeline

        # Device reconnaissance engine
        self.recon_engine = DeviceReconnaissanceEngine(
            max_devices=10000,
            activity_ttl=3600  # 1 hour
        )

        # Statistics tracking
        self.stats = {
            'total_connections': 0,
            'high_threat_count': 0,
            'unique_devices': 0,
            'unique_organizations': 0,
            'anomalies_detected': 0,
            'active_devices': 0,
            'max_threat': 0.0,
            'avg_threat': 0.0,
            'last_update': 0.0,
            'refresh_rate': 0.0,
        }

        # Live data buffers
        self.recent_connections: deque = deque(maxlen=100)
        self.recent_events: deque = deque(maxlen=50)
        self.recent_devices: Dict[str, Dict] = {}

        # Data caching
        self._connection_cache: List[Dict] = []
        self._device_cache: List[Dict] = []
        self._org_cache: Dict[str, Dict] = {}
        self._last_db_update = 0.0
        self._cache_ttl = 2.0

        # Performance tracking
        self._query_times: List[float] = []
        self._render_times: List[float] = []

    def compose(self) -> ComposeResult:
        """Layout method - must be implemented by subclasses"""
        yield Header()
        yield Footer()

    def on_mount(self) -> None:
        """Initialize dashboard after mounting"""
        self.title = f"CobaltGraph - {self.mode.title()} Mode [Reconnaissance]"
        self._connect_database()

        # Subscribe to pipeline events
        if self.pipeline:
            self.pipeline.subscribe(self._on_connection_event)
            logger.info(f"Dashboard subscribed to pipeline events (mode: {self.mode})")

        # Set up refresh intervals
        self.set_interval(2.0, self._refresh_data)
        self.set_interval(1.0, self._update_ui)

        # Initial data load
        self._refresh_data()

    def on_unmount(self) -> None:
        """Clean up on exit"""
        self._disconnect_database()

    def _connect_database(self) -> None:
        """Connect to SQLite database"""
        try:
            if not self.db_path.exists():
                logger.error(f"Database not found at {self.db_path}")
                self.is_connected = False
                return

            self.db_conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            self.db_conn.row_factory = sqlite3.Row
            self.is_connected = True
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            self.is_connected = False

    def _disconnect_database(self) -> None:
        """Disconnect from database"""
        if hasattr(self, 'db_conn') and self.db_conn:
            self.db_conn.close()
            self.is_connected = False

    def _execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute database query with timing"""
        if not self.is_connected:
            return []

        start_time = time.time()
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
            elapsed = time.time() - start_time

            # Track query performance
            self._query_times.append(elapsed)
            if len(self._query_times) > 100:
                self._query_times.pop(0)

            return results
        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}\nQuery: {query}")
            return []

    def _refresh_data(self) -> None:
        """Refresh all data from database and reconnaissance engine"""
        if not self.is_connected:
            return

        current_time = time.time()
        if current_time - self._last_db_update < self._cache_ttl:
            return

        # Load connections and feed to recon engine
        self._load_connections()

        # Load devices (network mode only)
        if self.mode == "network":
            self._load_devices()

        # Update statistics from recon engine
        self._update_statistics()

        self._last_db_update = current_time
        self.stats = self.stats.copy()

    def _load_connections(self) -> None:
        """Load recent connections and update reconnaissance engine"""
        query = """
        SELECT
            timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
            threat_score, dst_org, dst_org_type, org_trust_score,
            dst_country, hop_count, os_fingerprint, dst_asn, device_vendor,
            ttl_observed, ttl_initial
        FROM connections
        ORDER BY timestamp DESC
        LIMIT 100
        """

        if self.mode == "device":
            # Device mode: filter to local connections only
            query = """
            SELECT
                timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
                threat_score, dst_org, dst_org_type, org_trust_score,
                dst_country, hop_count, os_fingerprint, dst_asn, device_vendor,
                ttl_observed, ttl_initial
            FROM connections
            WHERE src_ip IN (
                SELECT DISTINCT src_ip FROM connections
                WHERE src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%' AND src_ip NOT LIKE '192.168.%'
                ORDER BY timestamp DESC LIMIT 1
            ) OR src_ip = '127.0.0.1'
            ORDER BY timestamp DESC
            LIMIT 100
            """

        rows = self._execute_query(query)
        self._connection_cache = [dict(row) for row in rows]

        # Feed connections to reconnaissance engine
        for conn in self._connection_cache:
            device_key = self.recon_engine.process_connection(conn)
            if device_key:
                device = self.recon_engine.get_device(device_key)
                if device:
                    self.recent_devices[device_key] = device.to_dict()

    def _load_devices(self) -> None:
        """Load devices from database (network mode only)"""
        if self.mode != "network":
            return

        query = """
        SELECT
            mac, vendor, ip_addresses, packet_count, connection_count,
            threat_score, is_active, first_seen, last_seen
        FROM devices
        WHERE is_active = 1
        ORDER BY threat_score DESC, connection_count DESC
        LIMIT 50
        """

        rows = self._execute_query(query)
        self._device_cache = [dict(row) for row in rows]

    def _update_statistics(self) -> None:
        """Update statistics from reconnaissance engine and database"""
        # Get summary from recon engine
        summary = self.recon_engine.get_device_summary()

        self.stats['unique_devices'] = summary['total_devices']
        self.stats['active_devices'] = summary['active_devices']
        self.stats['max_threat'] = summary['max_threat']
        self.stats['avg_threat'] = summary['average_threat']

        # Total connections
        total_query = "SELECT COUNT(*) as count FROM connections"
        total_result = self._execute_query(total_query)
        self.stats['total_connections'] = total_result[0]['count'] if total_result else 0

        # High threat count
        threat_query = "SELECT COUNT(*) as count FROM connections WHERE threat_score >= 0.7"
        threat_result = self._execute_query(threat_query)
        self.stats['high_threat_count'] = threat_result[0]['count'] if threat_result else 0

        # Unique organizations
        org_query = "SELECT COUNT(DISTINCT dst_org) as count FROM connections WHERE dst_org IS NOT NULL"
        org_result = self._execute_query(org_query)
        self.stats['unique_organizations'] = org_result[0]['count'] if org_result else 0

        # Anomalies
        anomaly_query = "SELECT COUNT(*) as count FROM events WHERE event_type = 'anomaly'"
        anomaly_result = self._execute_query(anomaly_query)
        self.stats['anomalies_detected'] = anomaly_result[0]['count'] if anomaly_result else 0

        self.stats['last_update'] = time.time()

    def _on_connection_event(self, event) -> None:
        """Called when pipeline receives a new connection event"""
        if not hasattr(event, 'to_dict'):
            return

        conn_dict = event.to_dict() if callable(event.to_dict) else event

        # Add to recent connections
        self.recent_connections.append(conn_dict)

        # Feed to reconnaissance engine
        device_key = self.recon_engine.process_connection(conn_dict)
        if device_key:
            device = self.recon_engine.get_device(device_key)
            if device:
                self.recent_devices[device_key] = device.to_dict()

    def _update_ui(self) -> None:
        """Update UI elements - called every 1 second"""
        # Placeholder for reactive UI updates
        pass

    def get_device_records(
        self,
        filter_threat_min: float = 0.0,
        limit: Optional[int] = None
    ) -> List[DeviceReconRecord]:
        """Get device records from reconnaissance engine"""
        devices = self.recon_engine.get_devices(sort_by="threat", limit=limit)
        return [d for d in devices if d.threat_score >= filter_threat_min]

    def get_active_devices(self, limit: Optional[int] = None) -> List[DeviceReconRecord]:
        """Get active devices from reconnaissance engine"""
        return self.recon_engine.get_devices(sort_by="activity", limit=limit)
