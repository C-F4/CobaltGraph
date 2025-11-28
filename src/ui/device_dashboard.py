#!/usr/bin/env python3
"""
CobaltGraph Device Mode Dashboard
Personal security focused - "What am I connecting to?"

Layout:
┌─────────────────┬───────────────────────────────┬─────────────────┐
│ Threat Posture  │ Connection Intelligence Table │ Active Alerts   │
│ Panel (25%)     │ (50%)                         │ Panel (15%)     │
│                 │                               │                 │
│ Current: 0.32   │ Time | Dst IP | Port | Score  ├─────────────────┤
│ 24h Base: 0.28  │ Org | Type | Trust | Hops    │ Temporal Trends │
│ Trend: ↑ 14%    │                               │ Panel (10%)     │
│                 │ [F]ilter [I]nspect [E]xport   │                 │
│ Active Threats  │                               │ 60-min sparkline│
│ Monitored IPs   │ Shows full enrichment data    │ threat chart    │
│ Anomalies       │ Hides MAC/device columns      │                 │
│                 │ Focus on "What am I           │                 │
│ 60-min sparkline│ connecting to?"               │                 │
└─────────────────┴───────────────────────────────┴─────────────────┘

Features:
- Connection table dominates (50% width) - primary focus
- No MAC/vendor columns - not relevant in device mode
- Organization analysis prominent - understand destinations
- No globe - single device geographic patterns less meaningful
- Full enrichment data: ASN, org type, trust score, hops, OS fingerprint
"""

import logging
from collections import deque
from datetime import datetime
from typing import List, Dict

from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, DataTable, Static

try:
    from src.ui.base_dashboard import DeviceDashboardBase
except ImportError:
    from base_dashboard import DeviceDashboardBase

logger = logging.getLogger(__name__)


class ConnectionIntelligenceTableDevice(Static):
    """
    Enhanced connection table for device mode
    Shows outbound connections with full enrichment data
    Hides MAC/device columns (not relevant to single device)
    """

    DEFAULT_CSS = """
    ConnectionIntelligenceTableDevice {
        height: 1fr;
        border: solid $primary;
    }

    ConnectionIntelligenceTableDevice > DataTable {
        background: $surface;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections: List[Dict] = []

    def compose(self) -> ComposeResult:
        """Create data table"""
        self.table = DataTable(id="device_connections")

        # Add columns (no MAC/vendor columns)
        self.table.add_column("Time", key="time", width=10)
        self.table.add_column("Dst IP", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=6)
        self.table.add_column("Protocol", key="protocol", width=6)
        self.table.add_column("Threat", key="threat", width=8)
        self.table.add_column("Organization", key="org", width=20)
        self.table.add_column("Type", key="org_type", width=12)
        self.table.add_column("Trust", key="trust", width=6)
        self.table.add_column("Hops", key="hops", width=5)
        self.table.add_column("Country", key="country", width=12)
        self.table.add_column("OS", key="os", width=12)

        yield self.table

    def update_connections(self, connections: List[Dict]) -> None:
        """Update table with new connections"""
        self.connections = connections
        self.table.clear()

        for conn in connections:
            # Format timestamp
            timestamp = conn.get('timestamp', 0)
            if isinstance(timestamp, (int, float)):
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = str(timestamp)[:8]

            # Format threat score with color
            threat_score = conn.get('threat_score', 0) or 0
            threat_str = f"{threat_score:.2f}"

            # Format organization
            org = (conn.get('dst_org') or 'Unknown')[:20]
            org_type = (conn.get('dst_org_type') or '-')[:12]

            # Format trust score
            trust_score = conn.get('org_trust_score', 0) or 0
            trust_str = f"{trust_score:.1f}"

            # Format hops
            hops = conn.get('hop_count', 0) or 0
            hops_str = str(hops)

            # Format country
            country = (conn.get('dst_country') or '-')[:12]

            # Format OS fingerprint
            os_fp = (conn.get('os_fingerprint') or '-')[:12]

            # Determine row style based on threat level
            if threat_score >= 0.7:
                style = "bold red"
            elif threat_score >= 0.5:
                style = "bold yellow"
            elif threat_score >= 0.3:
                style = "yellow"
            else:
                style = "green"

            # Add row
            self.table.add_row(
                time_str,
                conn.get('dst_ip', 'Unknown'),
                str(conn.get('dst_port', '-')),
                conn.get('protocol', '-'),
                threat_str,
                org,
                org_type,
                trust_str,
                hops_str,
                country,
                os_fp,
                key=f"conn_{id(conn)}",
                label=Text(f"{conn.get('dst_ip', '-')}", style=style)
            )



class ThreatPosturePanel(Static):
    """Simple threat posture display"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {}

    def render(self):
        return Panel(
            "Threat Posture\n[Loading...]",
            title="[bold cyan]Threat Status[/bold cyan]",
            border_style="cyan"
        )


class SimpleAlertsPanel(Static):
    """Simple alerts display"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.alert_data = {}

    def render(self):
        return Panel(
            "Recent Alerts\n[No alerts]",
            title="[bold yellow]Alerts[/bold yellow]",
            border_style="yellow"
        )


class SimpleTrendsPanel(Static):
    """Simple trends display"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.trend_data = {}

    def render(self):
        return Panel(
            "Threat Trends\n[Loading...]",
            title="[bold green]60-Min Trends[/bold green]",
            border_style="green"
        )


class DeviceDashboard(DeviceDashboardBase):
    """
    Device Mode Dashboard
    Personal security focused - "What am I connecting to?"
    """

    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        dock: top;
        height: 1;
    }

    Footer {
        dock: bottom;
        height: 2;
    }

    #main_content {
        layout: horizontal;
        height: 1fr;
    }

    #left_panel {
        width: 25%;
        height: 1fr;
    }

    #center_panel {
        width: 50%;
        height: 1fr;
    }

    #right_panel {
        width: 25%;
        height: 1fr;
        layout: vertical;
    }

    #alerts_panel {
        height: 50%;
    }

    #trends_panel {
        height: 50%;
    }
    """

    def __init__(self, db_path: str = "data/cobaltgraph.db", pipeline=None, **kwargs):
        super().__init__(db_path=db_path, pipeline=pipeline)
        self.threat_posture_panel = None
        self.connection_table = None
        self.alerts_panel = None
        self.trends_panel = None
        self.threat_history = deque(maxlen=60)  # 60-minute trend

    def compose(self) -> ComposeResult:
        """Create layout"""
        yield Header()

        with Horizontal(id="main_content"):
            # Left panel: Threat Posture (25%)
            self.threat_posture_panel = ThreatPosturePanel(id="left_panel")
            yield self.threat_posture_panel

            # Center panel: Connection Table (50%)
            self.connection_table = ConnectionIntelligenceTableDevice(id="center_panel")
            yield self.connection_table

            # Right panel: Alerts + Trends (25%)
            with Vertical(id="right_panel"):
                self.alerts_panel = SimpleAlertsPanel(id="alerts_panel")
                yield self.alerts_panel

                self.trends_panel = SimpleTrendsPanel(id="trends_panel")
                yield self.trends_panel

        yield Footer()

    def on_mount(self) -> None:
        """Initialize after mount"""
        super().on_mount()
        self.title = "CobaltGraph - Device Mode (Personal Security)"

        # Set initial data
        self._update_panels()

    def _on_live_connection(self, conn_dict: Dict) -> None:
        """Handle live connection events from pipeline"""
        # Track threat history for trends
        threat = conn_dict.get('threat_score', 0) or 0
        self.threat_history.append(threat)

        # Update panels with live data
        self._update_panels()

    def _refresh_data(self) -> None:
        """Refresh data from database"""
        super()._refresh_data()
        self._update_panels()

    def _update_panels(self) -> None:
        """Update all dashboard panels"""
        if not self.is_connected or not self._connection_cache:
            return

        # Update connection table
        if self.connection_table:
            self.connection_table.update_connections(self._connection_cache)

        # Calculate threat posture data
        threat_data = self._calculate_threat_posture()

        # Update threat posture panel
        if self.threat_posture_panel:
            self.threat_posture_panel.threat_data = threat_data

        # Update alerts (high threat connections)
        alerts = self._generate_alerts()
        if self.alerts_panel:
            self.alerts_panel.alert_data = {'alerts': alerts}

        # Update temporal trends
        trends_data = self._calculate_temporal_trends()
        if self.trends_panel:
            self.trends_panel.trend_data = trends_data

    def _calculate_threat_posture(self) -> Dict:
        """Calculate current threat posture metrics"""
        if not self._connection_cache:
            return {
                'current_threat': 0.0,
                'baseline_threat': 0.0,
                'active_threats': 0,
                'monitored_ips': 0,
                'anomaly_count': 0,
            }

        # Current threat = average of last 10 connections
        recent_threats = [
            float(conn.get('threat_score', 0) or 0)
            for conn in self._connection_cache[:10]
        ]
        current_threat = sum(recent_threats) / len(recent_threats) if recent_threats else 0

        # Baseline threat = average of all recent connections
        all_threats = [
            float(conn.get('threat_score', 0) or 0)
            for conn in self._connection_cache
        ]
        baseline_threat = sum(all_threats) / len(all_threats) if all_threats else 0

        # Active threats = high score connections
        active_threats = sum(1 for conn in self._connection_cache if float(conn.get('threat_score', 0) or 0) >= 0.7)

        # Monitored IPs = unique destination IPs
        monitored_ips = len(set(conn.get('dst_ip') for conn in self._connection_cache))

        return {
            'current_threat': current_threat,
            'baseline_threat': baseline_threat,
            'active_threats': active_threats,
            'monitored_ips': monitored_ips,
            'anomaly_count': self.stats.get('anomalies_detected', 0),
        }

    def _generate_alerts(self) -> List[Dict]:
        """Generate alerts from high-threat connections"""
        alerts = []

        for conn in self._connection_cache[:20]:  # Check recent connections
            threat_score = float(conn.get('threat_score', 0) or 0)

            if threat_score >= 0.7:
                severity = 'CRITICAL' if threat_score >= 0.9 else 'HIGH'
                alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': severity,
                    'message': f"High-threat connection: {conn.get('dst_ip')} ({conn.get('dst_org', 'Unknown')})",
                    'threat_score': threat_score,
                })

        return alerts

    def _calculate_temporal_trends(self) -> Dict:
        """Calculate temporal trends for sparkline"""
        # Group connections by time windows (simplified)
        threat_values = [
            float(conn.get('threat_score', 0) or 0)
            for conn in self._connection_cache
        ]

        # Simulate 60-minute trend with available data
        if threat_values:
            # Fill to 60 points if needed
            while len(threat_values) < 60:
                threat_values.append(threat_values[-1] if threat_values else 0)
            threat_values = threat_values[-60:]  # Last 60 points
        else:
            threat_values = [0] * 60

        return {
            'threat_trend': threat_values,
            'title': 'Threat Level (60-min)',
            'current': threat_values[-1] if threat_values else 0,
        }

    def action_inspect(self) -> None:
        """Inspect selected connection (placeholder)"""
        logger.info("Inspect action triggered")

    def action_filter(self) -> None:
        """Open filter dialog (placeholder)"""
        logger.info("Filter action triggered")

    def action_organization(self) -> None:
        """Show organization intelligence (placeholder)"""
        logger.info("Organization action triggered")

    def action_alerts(self) -> None:
        """Show alerts panel (already visible)"""
        logger.info("Alerts panel focused")

    def action_export(self) -> None:
        """Export connections to JSON/CSV (placeholder)"""
        logger.info("Export action triggered")
