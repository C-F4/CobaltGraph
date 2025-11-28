#!/usr/bin/env python3
"""
CobaltGraph Device Mode Dashboard
Personal device security focused - "What am I connecting to?"

Uses unified DataManager and VisualizationManager from BaseDashboard.
Components register with viz_manager for automatic data updates.

Layout:
├─ Header
├─ Main Content
│  ├─ Top (30%): ThreatGlobePanel + ThreatPosturePanel
│  └─ Bottom (70%): SmartConnectionTable + (AlertsPanel + TrendsPanel)
└─ Footer
"""

import logging
from collections import deque
from datetime import datetime
from typing import List, Dict

from rich.text import Text
from rich.panel import Panel

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, DataTable, Static

try:
    from src.ui.base_dashboard import DeviceDashboardBase
except ImportError:
    from base_dashboard import DeviceDashboardBase

try:
    from src.ui.viz_engine import ThreatGlobe
except ImportError:
    ThreatGlobe = None

logger = logging.getLogger(__name__)


class SmartConnectionTable(Static):
    """
    Enhanced connection table for device mode
    Adaptive column sizing to prevent truncation
    Shows outbound connections with essential enrichment data
    """

    DEFAULT_CSS = """
    SmartConnectionTable {
        height: 1fr;
        width: 1fr;
        border: solid $primary;
    }

    SmartConnectionTable > DataTable {
        background: $surface;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections: List[Dict] = []
        self.filtered_connections: List[Dict] = []
        self.filter_state = "all"  # all, high, medium, low, unknown
        self.table = None

    def compose(self) -> ComposeResult:
        """Create data table with smart column sizing"""
        self.table = DataTable(id="device_connections")

        # Add columns with optimized widths for device mode
        # Total width ~110 chars: essential data only
        self.table.add_column("Time", key="time", width=10)
        self.table.add_column("IP", key="dst_ip", width=16)
        self.table.add_column("Port", key="port", width=6)
        self.table.add_column("Proto", key="protocol", width=6)
        self.table.add_column("Risk", key="threat", width=5)
        self.table.add_column("Organization", key="org", width=25)
        self.table.add_column("Type", key="org_type", width=10)
        self.table.add_column("Trust", key="trust", width=5)
        self.table.add_column("Hops", key="hops", width=5)

        yield self.table

    def update_connections(self, connections: List[Dict]) -> None:
        """Update table with new connections and apply filters"""
        self.connections = connections
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Apply current filter to connections"""
        if self.filter_state == "all":
            self.filtered_connections = self.connections
        elif self.filter_state == "high":
            self.filtered_connections = [c for c in self.connections if (c.get('threat_score', 0) or 0) >= 0.7]
        elif self.filter_state == "medium":
            self.filtered_connections = [c for c in self.connections if 0.3 <= (c.get('threat_score', 0) or 0) < 0.7]
        elif self.filter_state == "low":
            self.filtered_connections = [c for c in self.connections if (c.get('threat_score', 0) or 0) < 0.3]
        else:
            self.filtered_connections = self.connections

        self._render_table()

    def _render_table(self) -> None:
        """Render filtered connections in table"""
        if not self.table:
            return

        self.table.clear()

        for conn in self.filtered_connections[:100]:  # Limit display
            timestamp = conn.get('timestamp', 0)
            if isinstance(timestamp, (int, float)):
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = str(timestamp)[:8]

            threat_score = conn.get('threat_score', 0) or 0
            if threat_score >= 0.7:
                threat_style = "red bold"
                risk_label = "HIGH"
            elif threat_score >= 0.3:
                threat_style = "yellow bold"
                risk_label = "MED"
            else:
                threat_style = "green"
                risk_label = "LOW"

            dst_ip = conn.get('dst_ip', '-')
            port = str(conn.get('dst_port', '-'))
            protocol = conn.get('protocol', '-').upper()
            org = conn.get('dst_org', 'Unknown')[:25]
            org_type = conn.get('dst_org_type', 'unknown')[:10]
            trust = f"{(conn.get('org_trust_score', 0) or 0) * 100:.0f}%"
            hops = str(conn.get('hop_count', '-'))

            self.table.add_row(
                time_str,
                Text(dst_ip, style="cyan"),
                port,
                protocol,
                Text(risk_label, style=threat_style),
                org,
                org_type,
                trust,
                hops,
                key=f"conn_{id(conn)}"
            )

    def set_filter(self, filter_type: str) -> None:
        """Set filter type and refresh display"""
        self.filter_state = filter_type
        self._apply_filter()


class ThreatGlobePanel(Static):
    """
    Threat Globe Visualization Widget
    Shows real-time geographic threat mapping with spinning animation
    """

    DEFAULT_CSS = """
    ThreatGlobePanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
        padding: 0;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.globe = None

    def render(self):
        """Render threat globe visualization"""
        if ThreatGlobe is None:
            return Panel(
                "[yellow]ThreatGlobe requires viz_engine module[/yellow]",
                title="[bold cyan]Threat Globe[/bold cyan]",
                border_style="cyan"
            )

        try:
            if self.globe is None:
                self.globe = ThreatGlobe(width=60, height=15)
            return self.globe.render()
        except Exception as e:
            logger.debug(f"Globe render error: {e}")
            return Panel(
                f"[red]Globe initialization: {str(e)[:50]}[/red]",
                title="[bold cyan]Threat Globe[/bold cyan]",
                border_style="cyan"
            )

    def update_with_connections(self, connections: List[Dict]) -> None:
        """Update globe with new connection data"""
        if self.globe and connections:
            try:
                for conn in connections[:20]:  # Limit updates
                    lat = conn.get('dst_lat', 0) or 0
                    lon = conn.get('dst_lon', 0) or 0
                    threat = conn.get('threat_score', 0) or 0
                    self.globe.add_connection(lat, lon, threat)
            except Exception as e:
                logger.debug(f"Globe update error: {e}")


class ThreatPosturePanel(Static):
    """
    Threat Posture Status Panel
    Shows current threat assessment and trend analysis
    """

    DEFAULT_CSS = """
    ThreatPosturePanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
        padding: 1;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {}

    def render(self):
        """Render threat posture information"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        trend = self.threat_data.get('trend_direction', '→')
        high_threat_count = self.threat_data.get('high_threat_count', 0)
        total_connections = self.threat_data.get('total_connections', 0)

        # Color based on threat level
        if current >= 0.7:
            current_style = "[bold red]"
        elif current >= 0.3:
            current_style = "[bold yellow]"
        else:
            current_style = "[green]"

        content = f"""{current_style}Current Threat[/]
{current:.2f} ({(current*100):.0f}%)

[cyan]24h Baseline[/]
{baseline:.2f}

[yellow]{trend} Trend[/]

[red]High Risk[/]
{high_threat_count}/{total_connections}

[dim]Filtering:[/]
[cyan]F=All[/] [yellow]H=High[/] [green]L=Low[/]
"""

        return Panel(
            content,
            title="[bold cyan]Threat Status[/bold cyan]",
            border_style="cyan"
        )


class AlertsPanel(Static):
    """
    Recent Alerts Display
    Shows high-threat connections and anomalies
    """

    DEFAULT_CSS = """
    AlertsPanel {
        height: 100%;
        width: 100%;
        border: solid $accent;
        padding: 1;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.alerts = []

    def render(self):
        """Render recent alerts"""
        if not self.alerts:
            return Panel(
                "[dim]No recent alerts[/dim]",
                title="[bold yellow]Recent Alerts[/bold yellow]",
                border_style="yellow"
            )

        alert_lines = []
        for alert in self.alerts[:5]:  # Show last 5 alerts
            alert_lines.append(f"• {alert.get('message', 'Unknown')}")

        return Panel(
            "\n".join(alert_lines),
            title="[bold yellow]Recent Alerts[/bold yellow]",
            border_style="yellow"
        )

    def add_alert(self, message: str, threat_level: str = "medium") -> None:
        """Add a new alert"""
        self.alerts.insert(0, {
            'message': message,
            'threat_level': threat_level,
            'timestamp': datetime.now()
        })
        # Keep only last 10 alerts
        self.alerts = self.alerts[:10]


class TrendsPanel(Static):
    """
    Threat Trends Visualization
    Shows 60-minute threat score history with sparkline
    """

    DEFAULT_CSS = """
    TrendsPanel {
        height: 100%;
        width: 100%;
        border: solid $accent;
        padding: 1;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.history = deque(maxlen=60)

    def render(self):
        """Render threat trends"""
        if not self.history:
            return Panel(
                "[dim]Loading trends...[/dim]",
                title="[bold green]60-Min Trends[/bold green]",
                border_style="green"
            )

        # Create sparkline-style visualization
        max_val = max(self.history) if self.history else 1.0
        sparkline_chars = "▁▂▃▄▅▆▇█"

        sparkline = ""
        for val in self.history:
            idx = int((val / max(max_val, 0.01)) * (len(sparkline_chars) - 1))
            sparkline += sparkline_chars[min(idx, len(sparkline_chars) - 1)]

        avg_threat = sum(self.history) / len(self.history) if self.history else 0
        peak = max(self.history) if self.history else 0

        trend_text = f"""[dim]Avg: {avg_threat:.2f} | Peak: {peak:.2f}[/dim]

{sparkline}

[cyan]Last 60 minutes[/cyan]
"""

        return Panel(
            trend_text,
            title="[bold green]60-Min Trends[/bold green]",
            border_style="green"
        )

    def update_history(self, threat_score: float) -> None:
        """Add new threat score to history"""
        self.history.append(threat_score)


class DeviceDashboard(DeviceDashboardBase):
    """
    Device Mode Dashboard - Complete Implementation
    Personal security focused with geographic threat visualization
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
        layout: vertical;
        height: 1fr;
    }

    #top_section {
        layout: horizontal;
        height: 30%;
        width: 1fr;
    }

    #globe_container {
        width: 65%;
        height: 100%;
    }

    #top_right {
        width: 35%;
        height: 100%;
        layout: vertical;
    }

    #bottom_section {
        layout: horizontal;
        height: 70%;
        width: 1fr;
    }

    #table_container {
        width: 65%;
        height: 100%;
    }

    #bottom_right {
        width: 35%;
        height: 100%;
        layout: vertical;
    }

    #alerts_container {
        height: 50%;
        width: 100%;
    }

    #trends_container {
        height: 50%;
        width: 100%;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("f", "filter_all", "All Connections"),
        ("h", "filter_high", "High Risk"),
        ("l", "filter_low", "Low Risk"),
        ("i", "inspect", "Inspect"),
        ("e", "export", "Export"),
        ("a", "alerts", "Alerts"),
        ("o", "organization", "Organization"),
        ("?", "show_help", "Help"),
    ]

    def __init__(self, db_path: str = "data/cobaltgraph.db", pipeline=None, **kwargs):
        super().__init__(db_path=db_path, pipeline=pipeline)
        self.connection_table = None
        self.threat_globe = None
        self.threat_posture_panel = None
        self.alerts_panel = None
        self.trends_panel = None
        self.threat_history = deque(maxlen=60)

        # Register components with visualization manager
        self.viz_manager.register_component("connections", self._on_connections_update)

    def compose(self) -> ComposeResult:
        """Create optimized layout with globe visualization"""
        yield Header()

        with Container(id="main_content"):
            # Top section: Globe + Threat Posture
            with Horizontal(id="top_section"):
                self.threat_globe = ThreatGlobePanel(id="globe_container")
                yield self.threat_globe

                self.threat_posture_panel = ThreatPosturePanel(id="top_right")
                yield self.threat_posture_panel

            # Bottom section: Connection Table + Alerts/Trends
            with Horizontal(id="bottom_section"):
                self.connection_table = SmartConnectionTable(id="table_container")
                yield self.connection_table

                with Vertical(id="bottom_right"):
                    self.alerts_panel = AlertsPanel(id="alerts_container")
                    yield self.alerts_panel

                    self.trends_panel = TrendsPanel(id="trends_container")
                    yield self.trends_panel

        yield Footer()

    def on_mount(self) -> None:
        """Initialize after mount"""
        super().on_mount()
        self.title = "CobaltGraph - Device Mode"

    def _on_connections_update(self, connections: List[Dict]) -> None:
        """Called by viz_manager when connections update"""
        if not connections:
            return

        # Update connection table
        if self.connection_table:
            self.connection_table.update_connections(connections)

        # Update threat globe
        if self.threat_globe:
            self.threat_globe.update_with_connections(connections)

        # Update threats and posture
        threats = [c.get('threat_score', 0) or 0 for c in connections]
        if threats:
            current_threat = sum(threats) / len(threats)
            self.threat_history.append(current_threat)

        # Generate alerts for high-threat connections
        for conn in connections:
            threat = conn.get('threat_score', 0) or 0
            if threat >= 0.7 and self.alerts_panel:
                ip = conn.get('dst_ip', 'Unknown')
                org = conn.get('dst_org', 'Unknown')
                self.alerts_panel.add_alert(f"[red]{ip}[/red] → {org}", "high")

        # Update panels
        threat_data = self._calculate_threat_posture(connections)
        if self.threat_posture_panel:
            self.threat_posture_panel.threat_data = threat_data

        if self.trends_panel and self.threat_history:
            for threat in list(self.threat_history)[-1:]:
                self.trends_panel.update_history(threat)

    def _on_live_connection(self, conn_dict: Dict) -> None:
        """Handle live connection from pipeline"""
        # Delegated to _on_connections_update via viz_manager
        pass

    def _calculate_threat_posture(self, connections: List[Dict]) -> Dict:
        """Calculate threat posture metrics from connections"""
        if not connections:
            return {
                'current_threat': 0.0,
                'baseline_threat': 0.0,
                'trend_direction': '→',
                'high_threat_count': 0,
                'total_connections': 0,
            }

        threats = [c.get('threat_score', 0) or 0 for c in connections]
        current = sum(threats) / len(threats) if threats else 0
        high_count = sum(1 for t in threats if t >= 0.7)

        # Calculate trend from history
        if len(self.threat_history) >= 2:
            recent = list(self.threat_history)[-10:]
            old = list(self.threat_history)[:10]
            recent_avg = sum(recent) / len(recent) if recent else 0
            old_avg = sum(old) / len(old) if old else 0
            trend = '↑' if recent_avg > old_avg else ('↓' if recent_avg < old_avg else '→')
        else:
            trend = '→'

        return {
            'current_threat': current,
            'baseline_threat': sum(list(self.threat_history)[:10]) / min(10, len(self.threat_history)) if self.threat_history else 0,
            'trend_direction': trend,
            'high_threat_count': high_count,
            'total_connections': len(threats),
        }

    def action_filter_all(self) -> None:
        """Show all connections"""
        if self.connection_table:
            self.connection_table.set_filter("all")

    def action_filter_high(self) -> None:
        """Show only high-risk connections"""
        if self.connection_table:
            self.connection_table.set_filter("high")

    def action_filter_low(self) -> None:
        """Show only low-risk connections"""
        if self.connection_table:
            self.connection_table.set_filter("low")

    def action_inspect(self) -> None:
        """Inspect selected connection (placeholder)"""
        pass

    def action_export(self) -> None:
        """Export data (placeholder)"""
        pass

    def action_alerts(self) -> None:
        """Show alerts view (placeholder)"""
        pass

    def action_organization(self) -> None:
        """Show organization analysis (placeholder)"""
        pass

    def action_show_help(self) -> None:
        """Show help information"""
        pass
