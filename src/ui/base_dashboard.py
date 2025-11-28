#!/usr/bin/env python3
"""
CobaltGraph Base Dashboard
Abstract base class for mode-specific dashboards (device vs network)

Provides:
- Shared database initialization with caching strategy
- Data pipeline integration with real-time events
- Unified visualization component orchestration
- Mode-aware layout and refresh intervals

Architecture:
- BaseDashboard: Abstract App base (database, caching, pipelines)
- DataManager: Unified data access with TTL-based caching
- VisualizationManager: Component orchestration and update routing
- DeviceDashboardBase/NetworkDashboardBase: Mode implementations
"""

import logging
import sqlite3
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Any
import time
from abc import ABC, abstractmethod

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class DataManager:
    """
    Unified data access layer with TTL-based caching
    Handles database queries, result conversion, and cache management
    """

    def __init__(self, db_path: str, cache_ttl: float = 2.0):
        self.db_path = Path(db_path)
        self.cache_ttl = cache_ttl
        self.db_conn = None
        self.is_connected = False

        # Cache storage
        self._connection_cache: List[Dict] = []
        self._device_cache: List[Dict] = []
        self._stats_cache: Dict[str, Any] = {}
        self._last_update = 0.0

        # Performance tracking
        self._query_times: deque = deque(maxlen=100)

    def connect(self) -> bool:
        """Establish database connection"""
        try:
            if not self.db_path.exists():
                logger.error(f"Database not found: {self.db_path}")
                return False

            self.db_conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            self.db_conn.row_factory = sqlite3.Row
            self.is_connected = True
            logger.info(f"DataManager connected to {self.db_path}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close database connection"""
        if self.db_conn:
            self.db_conn.close()
            self.is_connected = False

    def execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute query with timing and error handling"""
        if not self.is_connected:
            return []

        start_time = time.time()
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
            elapsed = time.time() - start_time
            self._query_times.append(elapsed)
            return results
        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []

    def is_cache_valid(self) -> bool:
        """Check if cached data is still fresh"""
        return time.time() - self._last_update < self.cache_ttl

    def invalidate_cache(self) -> None:
        """Force cache refresh on next access"""
        self._last_update = 0.0

    def get_avg_query_time(self) -> float:
        """Get average query execution time"""
        return sum(self._query_times) / len(self._query_times) if self._query_times else 0.0


class VisualizationManager:
    """
    Orchestrates visualization components with data binding
    Routes component updates, manages subscriptions, and coordinates rendering
    """

    def __init__(self):
        self._components: Dict[str, List[Callable]] = {}
        self._active_panels: Dict[str, Any] = {}

    def register_component(self, component_type: str, update_callback: Callable) -> None:
        """Register component for data updates"""
        if component_type not in self._components:
            self._components[component_type] = []
        self._components[component_type].append(update_callback)

    def unregister_component(self, component_type: str, callback: Callable) -> None:
        """Unregister component from updates"""
        if component_type in self._components:
            self._components[component_type].remove(callback)

    def notify_components(self, component_type: str, data: Any) -> None:
        """Notify all registered components of data update"""
        if component_type in self._components:
            for callback in self._components[component_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Component update failed: {e}")

    def update_connections(self, connections: List[Dict]) -> None:
        """Route connection updates to registered components"""
        self.notify_components("connections", connections)

    def update_devices(self, devices: List[Dict]) -> None:
        """Route device updates to registered components"""
        self.notify_components("devices", devices)

    def update_events(self, events: List[Dict]) -> None:
        """Route event updates to registered components"""
        self.notify_components("events", events)


class BaseDashboard(App):
    """
    Unified Base Dashboard for CobaltGraph
    Implements comprehensive threat monitoring model for device and network modes

    Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │ Header                                                          │
    ├──────────────────────┬──────────────────────┬──────────────────┤
    │ Threat Posture (TL)  │ Temporal Trends      │ Geo + Alerts (TR)│
    │ Current, Baseline    │ 60-min history       │ Heatmap, Counts  │
    │ Active, Monitored    │ Volume, Anomalies    │ Alert Summary    │
    ├──────────────────────┼──────────────────────┼──────────────────┤
    │ Organization Intel   │ Connection Table     │ Threat Globe     │
    │ Risk Matrix          │ PRIMARY DATA FOCUS   │ ASCII Rendering  │
    │ Top Orgs by Risk     │ Full enrichment      │ Heatmap + Trails │
    │ Click to filter      │ Color-coded threats  │ Geo-spatial      │
    └──────────────────────┴──────────────────────┴──────────────────┘
    │ Status Bar | Keyboard Shortcuts                            │
    └─────────────────────────────────────────────────────────────────┘

    Features:
    - Unified layout for device and network modes
    - Real-time data updates via DataManager + VisualizationManager
    - Mode-aware component display (device focuses on personal, network on topology)
    - Comprehensive threat visualization with multiple dimensions
    - Interactive filtering and inspection
    """

    # CSS styling - Unified 6-cell grid layout
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

    #main_grid {
        height: 1fr;
        width: 100%;
        layout: vertical;
    }

    #top_row {
        height: 50%;
        width: 100%;
        layout: horizontal;
    }

    #bottom_row {
        height: 50%;
        width: 100%;
        layout: horizontal;
    }

    #top_left {
        width: 20%;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    #top_center {
        width: 50%;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    #top_right {
        width: 30%;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    #bottom_left {
        width: 20%;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    #bottom_center {
        width: 50%;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    #bottom_right {
        width: 30%;
        height: 100%;
        border: solid $primary;
        padding: 1;
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
        self.mode = mode
        self.pipeline = pipeline

        # Core managers
        self.data_manager = DataManager(db_path=db_path, cache_ttl=2.0)
        self.viz_manager = VisualizationManager()

        # Statistics (updated by data_manager)
        self.stats = {
            'total_connections': 0,
            'high_threat_count': 0,
            'unique_devices': 0,
            'unique_organizations': 0,
            'anomalies_detected': 0,
            'last_update': 0.0,
            'refresh_rate': 0.0,
        }

        # Live data buffers
        self.recent_connections: deque = deque(maxlen=100)
        self.recent_events: deque = deque(maxlen=50)
        self.recent_devices: Dict[str, Dict] = {}

    def compose(self) -> ComposeResult:
        """
        Unified grid layout implementing the comprehensive threat monitoring model
        6-cell grid (2 rows x 3 columns) with Header and Footer
        """
        from textual.widgets import Static

        yield Header()

        # Main content grid with 2 rows
        with Vertical(id="main_grid"):
            # Top row (50% height): Threat Context + Trends + Alerts
            with Horizontal(id="top_row"):
                yield Static(id="top_left")      # Threat Posture (20%)
                yield Static(id="top_center")    # Temporal Trends (50%)
                yield Static(id="top_right")     # Geographic + Alerts (30%)

            # Bottom row (50% height): Organization + Connections + Globe
            with Horizontal(id="bottom_row"):
                yield Static(id="bottom_left")   # Organization Intelligence (20%)
                yield Static(id="bottom_center") # Connection Table (50%)
                yield Static(id="bottom_right")  # Threat Globe (30%)

        yield Footer()

    def on_mount(self) -> None:
        """Initialize dashboard after mounting"""
        self.title = f"CobaltGraph - {self.mode.title()} Mode"
        self.is_connected = self.data_manager.connect()

        if self.pipeline:
            self.pipeline.subscribe(self._on_connection_event)
            logger.info(f"Dashboard subscribed to pipeline (mode: {self.mode})")

        # Set up refresh intervals
        self.set_interval(2.0, self._refresh_data)  # DB sync
        self.set_interval(1.0, self._update_ui)     # UI animation

        self._refresh_data()

    def on_unmount(self) -> None:
        """Clean up on exit"""
        self.data_manager.disconnect()

    def _refresh_data(self) -> None:
        """Refresh data from database (called every 2s)"""
        if not self.is_connected or not self.data_manager.is_cache_valid():
            return

        # Query connections
        conn_query = """
        SELECT timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
               threat_score, dst_org, dst_org_type, org_trust_score,
               dst_country, hop_count, os_fingerprint, dst_asn, device_vendor
        FROM connections
        ORDER BY timestamp DESC LIMIT 100
        """

        if self.mode == "device":
            conn_query = """
            SELECT timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
                   threat_score, dst_org, dst_org_type, org_trust_score,
                   dst_country, hop_count, os_fingerprint, dst_asn, device_vendor
            FROM connections
            WHERE src_ip IN (
                SELECT DISTINCT src_ip FROM connections
                WHERE src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.%' AND src_ip NOT LIKE '192.168.%'
                ORDER BY timestamp DESC LIMIT 1
            ) OR src_ip = '127.0.0.1'
            ORDER BY timestamp DESC LIMIT 100
            """

        rows = self.data_manager.execute_query(conn_query)
        connections = [dict(row) for row in rows]
        self.data_manager._connection_cache = connections
        self.viz_manager.update_connections(connections)

        # Load devices (network mode only)
        if self.mode == "network":
            device_query = """
            SELECT mac, vendor, ip_addresses, packet_count, connection_count,
                   threat_score, is_active, first_seen, last_seen
            FROM devices WHERE is_active = 1
            ORDER BY threat_score DESC, connection_count DESC LIMIT 50
            """
            rows = self.data_manager.execute_query(device_query)
            devices = [dict(row) for row in rows]
            self.data_manager._device_cache = devices
            self.viz_manager.update_devices(devices)

        # Update statistics
        self._update_statistics()
        self.stats = self.stats.copy()  # Trigger reactive update

    def _update_statistics(self) -> None:
        """Update statistics from database"""
        # Total connections
        total_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM connections"
        )
        self.stats['total_connections'] = total_result[0]['count'] if total_result else 0

        # High threat count
        threat_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM connections WHERE threat_score >= 0.7"
        )
        self.stats['high_threat_count'] = threat_result[0]['count'] if threat_result else 0

        # Unique devices (network mode)
        if self.mode == "network":
            device_result = self.data_manager.execute_query(
                "SELECT COUNT(DISTINCT mac) as count FROM devices WHERE is_active = 1"
            )
            self.stats['unique_devices'] = device_result[0]['count'] if device_result else 0
        else:
            self.stats['unique_devices'] = 1

        # Unique organizations
        org_result = self.data_manager.execute_query(
            "SELECT COUNT(DISTINCT dst_org) as count FROM connections WHERE dst_org IS NOT NULL"
        )
        self.stats['unique_organizations'] = org_result[0]['count'] if org_result else 0

        # Anomalies
        anomaly_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM events WHERE event_type = 'anomaly'"
        )
        self.stats['anomalies_detected'] = anomaly_result[0]['count'] if anomaly_result else 0
        self.stats['last_update'] = time.time()

    def _on_connection_event(self, event) -> None:
        """Callback from DataPipeline for real-time events"""
        try:
            # Convert event to dictionary
            conn_dict = event.to_dict() if hasattr(event, 'to_dict') else \
                       (dict(event) if isinstance(event, dict) else {})

            self.recent_connections.append(conn_dict)

            # Update stats in real-time
            if conn_dict.get('threat_score', 0) >= 0.7:
                self.stats['high_threat_count'] += 1
            self.stats['total_connections'] += 1
            self.stats['last_update'] = time.time()
            self.stats = self.stats.copy()

            # Notify visualization components
            self.viz_manager.update_connections(list(self.recent_connections))

            # Subclass-specific handler
            if hasattr(self, '_on_live_connection'):
                self._on_live_connection(conn_dict)

        except Exception as e:
            logger.error(f"Connection event error: {e}")

    def _update_ui(self) -> None:
        """Called every 1s for UI animations"""
        # Subclass panels update themselves via VisualizationManager callbacks
        # No need for explicit updates - components subscribe to data changes
        pass

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
