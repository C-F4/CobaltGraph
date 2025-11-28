#!/usr/bin/env python3
"""
CobaltGraph Base Dashboard
Abstract base class for mode-specific dashboards (device vs network)

Provides:
- Shared database initialization and queries
- Common event handlers and keyboard bindings
- Consistent refresh intervals and data updates
- Mode-aware layout decisions
"""

import logging
import sqlite3
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class BaseDashboard(App):
    """
    Abstract base dashboard class for CobaltGraph

    Features:
    - Unified database access with caching
    - Mode detection (device vs network)
    - Consistent refresh intervals (2 seconds for data, 1 second for UI)
    - Shared keyboard bindings
    - Performance monitoring
    """

    # CSS styling
    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        dock: top;
        height: 1;
        background: $surface;
        color: $text;
        border: solid $primary;
    }

    Footer {
        dock: bottom;
        height: 2;
        background: $surface;
        color: $text;
        border: solid $primary;
    }
    """

    # Reactive properties
    stats = reactive(dict)
    mode = reactive(str)
    is_connected = reactive(bool, init=False)

    # Threat level colors (consistent across modes)
    THREAT_COLORS = {
        'LOW': 'green',
        'MEDIUM': 'yellow',
        'HIGH': 'bold yellow',
        'CRITICAL': 'red',
        'SEVERE': 'bold red',
    }

    def __init__(self, db_path: str = "data/cobaltgraph.db", mode: str = "device", pipeline=None):
        """Initialize base dashboard"""
        super().__init__()
        self.db_path = Path(db_path)
        self.mode = mode  # "device" or "network"
        self.is_connected = False
        self.pipeline = pipeline  # DataPipeline reference for live updates

        # Statistics tracking
        self.stats = {
            'total_connections': 0,
            'high_threat_count': 0,
            'unique_devices': 0,
            'unique_organizations': 0,
            'anomalies_detected': 0,
            'last_update': 0.0,
            'refresh_rate': 0.0,
        }

        # Live data buffers (for real-time updates from pipeline)
        self.recent_connections: deque = deque(maxlen=100)  # Last 100 connections
        self.recent_events: deque = deque(maxlen=50)  # Last 50 events
        self.recent_devices: Dict[str, Dict] = {}  # Live device map

        # Data caching
        self._connection_cache: List[Dict] = []
        self._device_cache: List[Dict] = []
        self._org_cache: Dict[str, Dict] = {}
        self._last_db_update = 0.0
        self._cache_ttl = 2.0  # 2 seconds cache

        # Performance tracking
        self._query_times: List[float] = []
        self._render_times: List[float] = []

    def compose(self) -> ComposeResult:
        """
        Layout method - must be implemented by subclasses
        Should yield Header, Footer, and mode-specific widgets
        """
        yield Header()
        yield Footer()

    def on_mount(self) -> None:
        """Initialize dashboard after mounting"""
        self.title = f"CobaltGraph - {self.mode.title()} Mode"
        self._connect_database()

        # Subscribe to pipeline events (if pipeline available)
        if self.pipeline:
            self.pipeline.subscribe(self._on_connection_event)
            logger.info(f"Dashboard subscribed to pipeline events (mode: {self.mode})")

        # Set up refresh intervals
        # Data refresh: 2 seconds (for DB sync)
        self.set_interval(2.0, self._refresh_data)
        # UI update: 1 second (for animations and reactive updates)
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

            # Create connection with timeout and row factory
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
        """
        Refresh all data from database
        Called every 2 seconds - override in subclasses for mode-specific logic
        """
        if not self.is_connected:
            return

        current_time = time.time()
        if current_time - self._last_db_update < self._cache_ttl:
            return  # Use cache

        # Load connections
        self._load_connections()

        # Load devices (network mode only)
        if self.mode == "network":
            self._load_devices()

        # Update statistics
        self._update_statistics()

        self._last_db_update = current_time
        self.stats = self.stats.copy()  # Trigger reactive update

    def _load_connections(self) -> None:
        """Load recent connections from database"""
        query = """
        SELECT
            timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
            threat_score, dst_org, dst_org_type, org_trust_score,
            dst_country, hop_count, os_fingerprint, dst_asn, device_vendor
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
                dst_country, hop_count, os_fingerprint, dst_asn, device_vendor
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
        # Convert sqlite3.Row objects to dictionaries
        self._connection_cache = [dict(row) for row in rows]

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
        # Convert sqlite3.Row objects to dictionaries
        self._device_cache = [dict(row) for row in rows]

    def _update_statistics(self) -> None:
        """Update statistics from database"""
        # Total connections
        total_query = "SELECT COUNT(*) as count FROM connections"
        total_result = self._execute_query(total_query)
        self.stats['total_connections'] = total_result[0]['count'] if total_result else 0

        # High threat count
        threat_query = "SELECT COUNT(*) as count FROM connections WHERE threat_score >= 0.7"
        threat_result = self._execute_query(threat_query)
        self.stats['high_threat_count'] = threat_result[0]['count'] if threat_result else 0

        # Unique devices (network mode)
        if self.mode == "network":
            device_query = "SELECT COUNT(DISTINCT mac) as count FROM devices WHERE is_active = 1"
            device_result = self._execute_query(device_query)
            self.stats['unique_devices'] = device_result[0]['count'] if device_result else 0
        else:
            self.stats['unique_devices'] = 1  # Device mode = local device only

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
        """
        Called when pipeline receives a new connection event
        This is the live data callback from the data capture pipeline
        """
        try:
            # Convert event to dictionary for consistency
            if hasattr(event, 'to_dict'):
                conn_dict = event.to_dict()
            else:
                conn_dict = dict(event) if isinstance(event, dict) else {}

            # Store in recent connections buffer
            self.recent_connections.append(conn_dict)

            # Update statistics in real-time
            if conn_dict.get('threat_score', 0) >= 0.7:
                self.stats['high_threat_count'] += 1
            self.stats['total_connections'] += 1
            self.stats['last_update'] = time.time()

            # Trigger reactive update to refresh UI
            self.stats = self.stats.copy()

            # Call subclass handler if it exists
            if hasattr(self, '_on_live_connection'):
                self._on_live_connection(conn_dict)

        except Exception as e:
            logger.error(f"Error processing connection event: {e}")

    def _update_ui(self) -> None:
        """Called every second for UI animations and updates"""
        # Update connection table if subclass implements it
        if hasattr(self, 'connection_table') and self.connection_table:
            # Convert deque to list and update
            try:
                self.connection_table.update_connections(list(self.recent_connections))
            except Exception as e:
                logger.debug(f"Error updating connection table: {e}")

        # Update device panel if subclass implements it
        if hasattr(self, 'devices_panel') and self.devices_panel:
            try:
                devices = list(self.recent_devices.values())
                self.devices_panel.update_devices(devices)
            except Exception as e:
                logger.debug(f"Error updating devices panel: {e}")

        # Update topology if subclass implements it
        if hasattr(self, 'topology_panel') and self.topology_panel:
            try:
                self.topology_panel.update_flows(
                    list(self.recent_connections),
                    list(self.recent_devices.values())
                )
            except Exception as e:
                logger.debug(f"Error updating topology: {e}")

    def get_threat_color(self, score: float) -> str:
        """Get color string for threat score"""
        if score < 0.3:
            return self.THREAT_COLORS['LOW']
        elif score < 0.5:
            return self.THREAT_COLORS['MEDIUM']
        elif score < 0.7:
            return self.THREAT_COLORS['HIGH']
        elif score < 0.9:
            return self.THREAT_COLORS['CRITICAL']
        else:
            return self.THREAT_COLORS['SEVERE']

    def get_threat_label(self, score: float) -> str:
        """Get threat label for score"""
        if score < 0.3:
            return 'LOW'
        elif score < 0.5:
            return 'MEDIUM'
        elif score < 0.7:
            return 'HIGH'
        elif score < 0.9:
            return 'CRITICAL'
        else:
            return 'SEVERE'

    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()

    def action_refresh(self) -> None:
        """Manually refresh data"""
        self._last_db_update = 0.0  # Force cache invalidation
        self._refresh_data()

    def action_export(self) -> None:
        """Export data to JSON/CSV (override in subclasses)"""
        pass

    def action_show_help(self) -> None:
        """Show help information"""
        pass


# Mode-specific base classes

class DeviceDashboardBase(BaseDashboard):
    """Base class for device mode dashboards"""

    def __init__(self, db_path: str = "data/cobaltgraph.db", pipeline=None):
        super().__init__(db_path=db_path, mode="device", pipeline=pipeline)

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "filter", "Filter"),
        ("i", "inspect", "Inspect"),
        ("e", "export", "Export"),
        ("a", "alerts", "Alerts"),
        ("o", "organization", "Organization"),
        ("?", "show_help", "Help"),
    ]


class NetworkDashboardBase(BaseDashboard):
    """Base class for network mode dashboards"""

    def __init__(self, db_path: str = "data/cobaltgraph.db", pipeline=None):
        super().__init__(db_path=db_path, mode="network", pipeline=pipeline)

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("d", "devices", "Devices"),
        ("t", "topology", "Topology"),
        ("g", "globe", "Globe"),
        ("f", "filter", "Filter"),
        ("e", "export", "Export"),
        ("p", "fingerprinting", "Fingerprint"),
        ("?", "show_help", "Help"),
    ]
