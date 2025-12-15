#!/usr/bin/env python3
"""
CobaltGraph Unified Dashboard Framework

Single consolidated base class for all dashboard implementations.
Provides 6-cell grid layout with automatic data management and reactive panels.

Architecture:
├─ UnifiedDashboard: Core base class with 6-cell grid + data management
├─ DataManager: Database queries with TTL caching
├─ VisualizationManager: Component event routing
└─ unified_components: 6 reusable panel components

Each mode (device/network) extends UnifiedDashboard with mode-specific components.
"""

import json
import logging
import sqlite3
import traceback
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Any
import time
from abc import ABC, abstractmethod

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer
from textual.reactive import reactive

# Import global heartbeat singleton
from src.utils.heartbeat import heartbeat

# Import connection intelligence modal and messages
from src.ui.connection_modal import ConnectionIntelligenceModal
from src.ui.unified_components import ConnectionSelected, ThreatAlert

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

    def get_connections(self, limit: int = 100) -> List[Dict]:
        """Get recent connections from database"""
        try:
            if not self.is_cache_valid():
                query = """
                    SELECT * FROM connections
                    ORDER BY timestamp DESC
                    LIMIT ?
                """
                results = self.execute_query(query, (limit,))
                self._connection_cache = [dict(row) for row in results]
                self._last_update = time.time()
                logger.debug(f"Loaded {len(self._connection_cache)} connections from database")
            return self._connection_cache
        except Exception as e:
            logger.error(f"Error fetching connections: {e}")
            return []

    def get_devices(self) -> List[Dict]:
        """Get device list from database"""
        query = "SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC LIMIT 100"
        try:
            results = self.execute_query(query)
            return [dict(row) for row in results]
        except Exception as e:
            logger.debug(f"Error fetching devices: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get overall statistics"""
        def safe_count(results) -> int:
            """Safely extract count from query results"""
            try:
                if results and results[0] is not None:
                    return dict(results[0]).get('count', 0) or 0
            except (IndexError, TypeError, KeyError):
                pass
            return 0

        try:
            # Total connections
            total_query = "SELECT COUNT(*) as count FROM connections"
            total_results = self.execute_query(total_query)
            total = safe_count(total_results)

            # High threat count
            threat_query = "SELECT COUNT(*) as count FROM connections WHERE threat_score >= 0.7"
            threat_results = self.execute_query(threat_query)
            high_threat = safe_count(threat_results)

            # Device count
            device_query = "SELECT COUNT(*) as count FROM devices WHERE is_active = 1"
            device_results = self.execute_query(device_query)
            devices = safe_count(device_results)

            return {
                'total': total,
                'high_threat': high_threat,
                'devices': devices,
            }
        except Exception as e:
            logger.debug(f"Error fetching stats: {e}")
            return {'total': 0, 'high_threat': 0, 'devices': 0}

    def get_events(self, event_type: str = None, limit: int = 20) -> List[Dict]:
        """
        Get recent events/anomalies from database.

        Args:
            event_type: Filter by type (anomaly, high_threat, consensus_uncertain, device_discovered)
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries with timestamp, type, severity, message, IPs, etc.
        """
        try:
            if event_type:
                query = """
                    SELECT * FROM events
                    WHERE event_type = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """
                params = (event_type, limit)
            else:
                query = """
                    SELECT * FROM events
                    ORDER BY timestamp DESC
                    LIMIT ?
                """
                params = (limit,)

            results = self.execute_query(query, params)
            return [dict(row) for row in results]
        except Exception as e:
            logger.debug(f"Error fetching events: {e}")
            return []

    def get_anomalies(self, limit: int = 10) -> List[Dict]:
        """
        Get recent anomaly detections.
        Convenience method that filters events by anomaly-related types.
        """
        try:
            query = """
                SELECT * FROM events
                WHERE event_type IN ('anomaly', 'high_threat', 'consensus_uncertain')
                ORDER BY timestamp DESC
                LIMIT ?
            """
            results = self.execute_query(query, (limit,))
            return [dict(row) for row in results]
        except Exception as e:
            logger.debug(f"Error fetching anomalies: {e}")
            return []


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


class UnifiedDashboard(App):
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
    - Mode-aware component display
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
        padding: 0 1 0 0;
    }

    #top_center {
        width: 50%;
        height: 100%;
        padding: 0 1 0 1;
    }

    #top_right {
        width: 30%;
        height: 100%;
        padding: 0 0 0 1;
    }

    #bottom_left {
        width: 20%;
        height: 100%;
        padding: 1 1 0 0;
    }

    #bottom_center {
        width: 50%;
        height: 100%;
        padding: 1 1 0 1;
    }

    #bottom_right {
        width: 30%;
        height: 100%;
        padding: 1 0 0 1;
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

    def __init__(self, db_path: str = "database/cobaltgraph.db", mode: str = "device", pipeline=None):
        """Initialize unified dashboard"""
        super().__init__()
        self.mode = mode
        self.pipeline = pipeline

        # Core managers
        self.data_manager = DataManager(db_path=db_path, cache_ttl=2.0)
        self.viz_manager = VisualizationManager()

        # Alert engine for toast notifications (Dashboard Evolution)
        self.alert_engine = None
        try:
            from src.analytics.alert_engine import create_alert_engine
            self.alert_engine = create_alert_engine()
            # Register callback for toast notifications
            self.alert_engine.register_alert_callback(self._on_alert_generated)
            logger.info("Alert engine integrated with dashboard")
        except ImportError as e:
            logger.warning(f"Alert engine not available: {e}")

        # Graph analytics engine for periodic computation (Dashboard Evolution)
        self.threat_analytics = None
        self.graph_analytics_cache: Dict[str, Any] = {}  # Cached graph results
        try:
            from src.analytics.threat_analytics import ThreatAnalytics
            self.threat_analytics = ThreatAnalytics()
            logger.info("Graph analytics engine initialized")
        except ImportError as e:
            logger.warning(f"Graph analytics not available: {e}")

        # Use global heartbeat singleton (already initialized by system_check)
        # Components are registered and marked online/offline during system checks

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

        # Unified dashboard panel references
        self.threat_posture_panel = None
        self.temporal_trends_panel = None
        self.geographic_alerts_panel = None
        self.organization_intel_panel = None
        self.connection_table_panel = None
        self.threat_globe_panel = None

    @property
    def _device_cache(self) -> List[Dict]:
        """Proxy to data_manager's device cache for backward compatibility"""
        return self.data_manager._device_cache

    def compose(self) -> ComposeResult:
        """
        Unified grid layout implementing the comprehensive threat monitoring model
        6-cell grid (2 rows x 3 columns) with Header and Footer
        Subclasses populate cells with specific implementations
        """
        from src.ui.unified_components import (
            ThreatPosturePanel,
            TemporalTrendsPanel,
            ConsensusBreakdownPanel,
            GeographicAlertsPanel,
            OrganizationIntelPanel,
            ConnectionTablePanel,
            ThreatGlobePanel,
        )

        yield Header()

        # Main content grid with 2 rows
        with Vertical(id="main_grid"):
            # Top row (50% height): Threat Context + Consensus + Alerts
            with Horizontal(id="top_row"):
                self.threat_posture_panel = ThreatPosturePanel(id="top_left")
                yield self.threat_posture_panel

                # Consensus Breakdown Panel (replaces Temporal Trends for scorer visibility)
                self.consensus_panel = ConsensusBreakdownPanel(id="top_center")
                yield self.consensus_panel

                self.geographic_alerts_panel = GeographicAlertsPanel(id="top_right")
                yield self.geographic_alerts_panel

            # Bottom row (50% height): Organization + Connections + Globe
            with Horizontal(id="bottom_row"):
                self.organization_intel_panel = OrganizationIntelPanel(id="bottom_left")
                yield self.organization_intel_panel

                self.connection_table_panel = ConnectionTablePanel(id="bottom_center")
                yield self.connection_table_panel

                self.threat_globe_panel = ThreatGlobePanel(id="bottom_right")
                yield self.threat_globe_panel

        yield Footer()

    def on_mount(self) -> None:
        """Initialize dashboard after mounting"""
        self.title = f"CobaltGraph - {self.mode.title()} Mode"
        self.sub_title = "Initializing..."
        self.is_connected = self.data_manager.connect()

        if self.pipeline:
            self.pipeline.subscribe(self._on_connection_event)
            logger.info(f"Dashboard subscribed to pipeline (mode: {self.mode})")

        # Set up refresh intervals
        self.set_interval(2.0, self._refresh_data)  # DB sync (forces cache invalidation)
        self.set_interval(0.5, self._update_heartbeat)  # Update heartbeat timestamp (0.5s)
        self.set_interval(1.0, self._update_ui)     # UI animation
        self.set_interval(30.0, self._refresh_graph_analytics)  # Graph analytics (30s)

        # Force initial data load
        self.data_manager.invalidate_cache()
        self._refresh_data()
        self._refresh_graph_analytics()  # Initial graph analytics computation

    def on_unmount(self) -> None:
        """Clean up on exit"""
        self.data_manager.disconnect()

    def _refresh_data(self) -> None:
        """Refresh data from database (called every 2s)"""
        if not self.is_connected:
            return

        # Send database heartbeat since we're connected
        heartbeat.beat("database", "DB connected")

        # Invalidate cache on every refresh to ensure fresh data
        self.data_manager.invalidate_cache()

        # Query connections with individual scorer data
        conn_query = """
        SELECT timestamp, src_ip, src_mac, dst_ip, dst_port, protocol,
               threat_score, dst_org, dst_org_type, org_trust_score,
               dst_country, dst_lat, dst_lon, hop_count, os_fingerprint, dst_asn, device_vendor,
               confidence, high_uncertainty, scoring_method,
               score_statistical, score_rule_based, score_ml_based, score_organization,
               anomaly_score, score_spread
        FROM connections
        ORDER BY timestamp DESC LIMIT 100
        """

        rows = self.data_manager.execute_query(conn_query)
        connections = [dict(row) for row in rows]
        self.data_manager._connection_cache = connections
        self.recent_connections = deque(connections, maxlen=100)
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
            self.recent_devices = {d.get('mac'): d for d in devices}
            self.viz_manager.update_devices(devices)
        else:
            devices = []

        # Load events
        event_query = """
        SELECT timestamp, event_type, severity, message, source_ip, dst_ip, threat_score
        FROM events
        ORDER BY timestamp DESC LIMIT 50
        """
        rows = self.data_manager.execute_query(event_query)
        events = [dict(row) for row in rows]
        self.recent_events = deque(events, maxlen=50)
        self.viz_manager.update_events(events)

        # Update statistics
        self._update_statistics()
        self._update_unified_panels(connections, devices, events)
        self.stats = self.stats.copy()  # Trigger reactive update

    def _update_statistics(self) -> None:
        """Update statistics from database"""
        # Helper to safely extract count from query result
        def safe_count(result) -> int:
            try:
                if result and result[0] is not None:
                    return result[0]['count'] or 0
            except (IndexError, TypeError, KeyError):
                pass
            return 0

        # Total connections
        total_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM connections"
        )
        self.stats['total_connections'] = safe_count(total_result)

        # High threat count
        threat_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM connections WHERE threat_score >= 0.7"
        )
        self.stats['high_threat_count'] = safe_count(threat_result)

        # Unique devices (network mode)
        if self.mode == "network":
            device_result = self.data_manager.execute_query(
                "SELECT COUNT(DISTINCT mac) as count FROM devices WHERE is_active = 1"
            )
            self.stats['unique_devices'] = safe_count(device_result)
        else:
            self.stats['unique_devices'] = 1

        # Unique organizations
        org_result = self.data_manager.execute_query(
            "SELECT COUNT(DISTINCT dst_org) as count FROM connections WHERE dst_org IS NOT NULL"
        )
        self.stats['unique_organizations'] = safe_count(org_result)

        # Anomalies
        anomaly_result = self.data_manager.execute_query(
            "SELECT COUNT(*) as count FROM events WHERE event_type = 'anomaly'"
        )
        self.stats['anomalies_detected'] = safe_count(anomaly_result)
        self.stats['last_update'] = time.time()

    def _update_unified_panels(self, connections: List[Dict], devices: List[Dict], events: List[Dict]) -> None:
        """Update unified 6-cell grid panels with calculated data"""
        if not connections:
            return

        # Check connection data for evidence of working components and send heartbeats
        for conn in connections[:10]:  # Sample first 10 connections
            # GeoIP heartbeat: if we have geo data, the service is working
            if conn.get('dst_lat') or conn.get('dst_lon') or conn.get('dst_country'):
                heartbeat.beat("geo_engine", "GeoIP data flowing")
                break

        for conn in connections[:10]:
            # ASN heartbeat: if we have ASN data, the service is working
            if conn.get('dst_asn') or conn.get('dst_org'):
                heartbeat.beat("asn_lookup", "ASN data flowing")
                break

        for conn in connections[:10]:
            # Consensus heartbeat: if we have threat scores, consensus is working
            if conn.get('threat_score') is not None:
                heartbeat.beat("consensus", "Threat scoring active")
                break

        # Check if capture is active based on recent timestamps
        if connections:
            latest_ts = connections[0].get('timestamp', 0)
            if latest_ts and (time.time() - latest_ts) < 60:  # Connection within last minute
                heartbeat.beat("capture", "Receiving connections")

        # Threat Posture Panel (Top-Left)
        if self.threat_posture_panel:
            threats = [c.get('threat_score', 0) or 0 for c in connections]
            current_threat = sum(threats) / len(threats) if threats else 0
            high_count = sum(1 for t in threats if t >= 0.7)

            # Get top 3 threat connections for radar graphs
            top_threats = sorted(
                connections,
                key=lambda c: float(c.get('threat_score', 0) or 0),
                reverse=True
            )[:3]

            self.threat_posture_panel.threat_data = {
                'current_threat': current_threat,
                'baseline_threat': sum(threats[:len(threats)//3]) / max(len(threats)//3, 1) if threats else 0,
                'active_threats': high_count,
                'monitored_ips': len(set(c.get('dst_ip') for c in connections)),
                'top_threats': top_threats,  # Add top 3 for radar graphs
            }

        # Consensus Breakdown Panel (Top-Center) - update with latest scorer data
        if hasattr(self, 'consensus_panel') and self.consensus_panel:
            # Find the most recent connection with scorer data
            for conn in connections:
                if conn.get('score_statistical') is not None or conn.get('score_spread') is not None:
                    self.consensus_panel.update_from_connection(conn)
                    break
            else:
                # No scorer data yet, use first connection for basic stats
                if connections:
                    self.consensus_panel.update_from_connection(connections[0])

        # Geographic Alerts Panel (Top-Right)
        if self.geographic_alerts_panel:
            critical_events = sum(1 for e in events if e.get('severity') == 'CRITICAL')
            warning_events = sum(1 for e in events if e.get('severity') == 'WARNING')
            info_events = sum(1 for e in events if e.get('severity') == 'INFO')

            self.geographic_alerts_panel.alert_data = {
                'critical_count': critical_events,
                'warning_count': warning_events,
                'info_count': info_events,
                'geo_map': {},
            }

        # Organization Intel Panel (Bottom-Left)
        if self.organization_intel_panel:
            org_stats = {}
            for conn in connections:
                org = conn.get('dst_org', 'Unknown')
                threat = conn.get('threat_score', 0) or 0
                if org not in org_stats:
                    org_stats[org] = {'threat': 0, 'count': 0}
                org_stats[org]['threat'] += threat
                org_stats[org]['count'] += 1

            top_orgs = sorted(
                [(k, v['threat']/v['count'], v['count']) for k, v in org_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]

            self.organization_intel_panel.org_data = {
                'top_orgs': top_orgs,
                'risk_matrix': {},
            }

        # Connection Table Panel (Bottom-Center)
        if self.connection_table_panel:
            self.connection_table_panel.connections = connections

        # Threat Globe Panel (Bottom-Right) - geo data
        if self.threat_globe_panel:
            self.threat_globe_panel.globe_data = {
                'connections': connections,
                'heatmap': {},
            }

    def _on_connection_event(self, event) -> None:
        """Callback from DataPipeline for real-time events"""
        try:
            # Send pipeline heartbeat since we're receiving events
            heartbeat.beat("pipeline", "Processing events")

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

            # Process through alert engine for toast notifications (Dashboard Evolution)
            if self.alert_engine:
                try:
                    self.alert_engine.process_connection(conn_dict)
                except Exception as alert_err:
                    logger.debug(
                        f"Alert processing error: {alert_err}\n"
                        f"  Connection: {conn_dict.get('dst_ip')}:{conn_dict.get('dst_port')}\n"
                        f"  Traceback: {traceback.format_exc()}"
                    )

            # Subclass-specific handler
            if hasattr(self, '_on_live_connection'):
                self._on_live_connection(conn_dict)

        except Exception as e:
            logger.error(
                f"Connection event error: {e}\n"
                f"  Traceback: {traceback.format_exc()}"
            )

    def _update_heartbeat(self) -> None:
        """Update heartbeat timestamp and system status gumballs (called every 0.5s)"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Mark dashboard as alive
        heartbeat.beat("dashboard", "UI active")

        # Update system status in ThreatPosturePanel
        if self.threat_posture_panel:
            self.threat_posture_panel.system_status = heartbeat.get_status()

        # Get summary from heartbeat
        online, total = heartbeat.get_online_count()

        self.sub_title = f"Last update: {timestamp} | Components: {online}/{total} online | DB: {'Connected' if self.is_connected else 'Offline'}"

    def _update_ui(self) -> None:
        """Called every 1s for UI animations"""
        # Subclass panels update themselves via VisualizationManager callbacks
        pass

    def _refresh_graph_analytics(self) -> None:
        """
        Periodic graph analytics computation (called every 30s).
        Computes PageRank centrality, threat clusters, attack paths, and ASN rankings.
        Results are cached for the connection intelligence modal.
        """
        if not self.threat_analytics:
            return

        try:
            # Feed recent connections to the analytics engine
            connections = list(self.recent_connections)
            for conn in connections[-50:]:  # Process last 50 connections
                try:
                    self.threat_analytics.process_connection(
                        src_ip=conn.get('src_ip', ''),
                        dst_ip=conn.get('dst_ip', ''),
                        threat_score=conn.get('threat_score', 0) or 0,
                        confidence=conn.get('confidence', 0.8) or 0.8,
                        dst_port=conn.get('dst_port', 443),
                        dst_org=conn.get('dst_org'),
                        dst_org_type=conn.get('dst_org_type'),
                        dst_asn=conn.get('dst_asn'),
                        hop_count=conn.get('hop_count'),
                        dst_country=conn.get('dst_country'),
                        org_trust_score=conn.get('org_trust_score'),
                    )
                except Exception as proc_err:
                    logger.debug(
                        f"Connection processing error: {proc_err}\n"
                        f"  Connection: src={conn.get('src_ip')} dst={conn.get('dst_ip')}:{conn.get('dst_port')}\n"
                        f"  Traceback: {traceback.format_exc()}"
                    )

            # Get comprehensive report and cache it
            report = self.threat_analytics.get_comprehensive_report()
            self.graph_analytics_cache = report

            # Send analytics heartbeat
            heartbeat.beat("analytics", "Graph analytics computed")
            logger.debug(f"Graph analytics refreshed: {report.get('summary', {})}")

        except Exception as e:
            logger.error(
                f"Graph analytics refresh failed: {e}\n"
                f"  Traceback: {traceback.format_exc()}"
            )

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
        self.data_manager.invalidate_cache()
        self._refresh_data()

    def action_export(self) -> None:
        """Export data to JSON/CSV (override in subclasses)"""
        self.sub_title = "Export: Not implemented in base class"

    def action_show_help(self) -> None:
        """Show available keybindings in subtitle"""
        self.sub_title = "Keys: Q=Quit | R=Refresh | ?=Help | Ctrl+P=Commands | Enter=Details"

    def _on_alert_generated(self, alert) -> None:
        """
        Callback for alert engine - converts Alert to ThreatAlert message.
        This bridges the alert_engine's callback mechanism with Textual's message system.

        Args:
            alert: Alert object from alert_engine with severity, title, message, etc.
        """
        try:
            # Map AlertSeverity enum to Textual notify severity strings
            severity_map = {
                "CRITICAL": ThreatAlert.SEVERITY_CRITICAL,  # "error"
                "WARNING": ThreatAlert.SEVERITY_WARNING,     # "warning"
                "INFO": ThreatAlert.SEVERITY_INFO,           # "information"
            }

            # Get severity string from alert
            alert_severity = getattr(alert.severity, 'value', str(alert.severity))
            severity = severity_map.get(alert_severity, ThreatAlert.SEVERITY_INFO)

            # Set timeout based on severity (critical stays longer)
            timeout = 10.0 if alert_severity == "CRITICAL" else (7.0 if alert_severity == "WARNING" else 5.0)

            # Post the ThreatAlert message to trigger on_threat_alert handler
            self.post_message(ThreatAlert(
                title=alert.title,
                message=alert.message,
                severity=severity,
                dst_ip=alert.dst_ip,
                rule_matched=getattr(alert, 'category', None),
                threat_score=alert.threat_score,
                timeout=timeout,
            ))

            logger.debug(f"Alert posted to dashboard: {alert.title}")

        except Exception as e:
            logger.error(f"Failed to post alert to dashboard: {e}")

    def on_connection_selected(self, message: ConnectionSelected) -> None:
        """
        Handle connection row selection from ConnectionTablePanel.
        Opens the Connection Intelligence Modal with full details.
        """
        connection_data = message.connection_data
        dst_ip = connection_data.get('dst_ip', 'Unknown')

        logger.info(f"Opening intelligence modal for {dst_ip}")
        self.sub_title = f"Opening details for {dst_ip}..."

        # Push the modal screen
        self.push_screen(ConnectionIntelligenceModal(connection_data))

    def on_threat_alert(self, message: ThreatAlert) -> None:
        """
        Handle threat alert messages by showing toast notifications.
        Uses Textual's built-in notify() for non-intrusive alerts.
        """
        # Build the notification message
        title = message.title
        body = message.message

        # Add extra context if available
        if message.dst_ip:
            body = f"{body}\nIP: {message.dst_ip}"
        if message.rule_matched:
            body = f"{body}\nRule: {message.rule_matched}"
        if message.threat_score is not None:
            body = f"{body}\nScore: {message.threat_score:.2f}"

        # Show the toast notification
        self.notify(
            body,
            title=title,
            severity=message.severity,
            timeout=message.timeout,
        )

        logger.info(f"Alert toast: {title} - {message.message}")

    def show_threat_alert(
        self,
        title: str,
        message: str,
        severity: str = "information",
        dst_ip: str = None,
        rule_matched: str = None,
        threat_score: float = None,
        timeout: float = 5.0,
    ) -> None:
        """
        Convenience method to show a threat alert toast directly.
        Can be called from anywhere with access to the app instance.
        """
        self.notify(
            message + (f"\nIP: {dst_ip}" if dst_ip else ""),
            title=title,
            severity=severity,
            timeout=timeout,
        )


# Convenience aliases for backward compatibility
class CobaltGraphDashboard(UnifiedDashboard):
    """
    Unified CobaltGraph Dashboard - base class for dashboard implementations

    Note: For the full-featured dashboard, use CobaltGraphDashboardEnhanced
    from dashboard_enhanced.py which provides working implementations of
    all features including globe visualization, anomaly panel, and detail modals.
    """

    BINDINGS = [
        ("q", "quit", "Quit Application"),
        ("r", "refresh", "Refresh Data"),
        ("?", "show_help", "Show Keybindings"),
        ("ctrl+p", "command_palette", "Command Palette"),
    ]

    def action_show_help(self) -> None:
        """Show available keybindings in subtitle"""
        self.sub_title = "Keys: Q=Quit | R=Refresh | ?=Help | Ctrl+P=Commands"


class DeviceDashboardBase(UnifiedDashboard):
    """
    Base class for device mode dashboards

    Note: Use CobaltGraphDashboardEnhanced with mode="device" for
    a full-featured implementation with all working actions.
    """

    def __init__(self, db_path: str = "database/cobaltgraph.db", pipeline=None):
        super().__init__(db_path=db_path, mode="device", pipeline=pipeline)

    BINDINGS = [
        ("q", "quit", "Quit Application"),
        ("r", "refresh", "Refresh Data"),
        ("?", "show_help", "Show Keybindings"),
        ("ctrl+p", "command_palette", "Command Palette"),
    ]


class NetworkDashboardBase(UnifiedDashboard):
    """
    Base class for network mode dashboards

    Note: Use CobaltGraphDashboardEnhanced with mode="network" for
    a full-featured implementation with all working actions.
    """

    def __init__(self, db_path: str = "database/cobaltgraph.db", pipeline=None):
        super().__init__(db_path=db_path, mode="network", pipeline=pipeline)

    BINDINGS = [
        ("q", "quit", "Quit Application"),
        ("r", "refresh", "Refresh Data"),
        ("?", "show_help", "Show Keybindings"),
        ("ctrl+p", "command_palette", "Command Palette"),
    ]


if __name__ == "__main__":
    dashboard = CobaltGraphDashboard()
    dashboard.run()
