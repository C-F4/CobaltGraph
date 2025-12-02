#!/usr/bin/env python3
"""
CobaltGraph Unified Dashboard Components
Provides 6 reusable panel components for the unified dashboard grid layout.

Components:
- ThreatPosturePanel: Current threat level with radar graphs for top 3 threats
- TemporalTrendsPanel: 60-minute threat history trends
- GeographicAlertsPanel: Geo heatmap with alert counts
- OrganizationIntelPanel: Risk matrix by organization type
- ConnectionTablePanel: Primary connection data table
- ThreatGlobePanel: ASCII globe with threat visualization
"""

import logging
import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Any

from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text

from textual.widgets import Static, DataTable
from textual.reactive import reactive
from textual.app import ComposeResult

logger = logging.getLogger(__name__)


class ThreatRadarGraph:
    """
    ASCII-based radar/spider chart renderer for threat visualization.
    Displays multi-dimensional threat scores in a compact visual format.
    """

    # Radar chart dimensions (axes)
    AXES = [
        ('THR', 'Threat'),      # Threat score
        ('CNF', 'Confidence'),  # Confidence level
        ('RIS', 'Risk'),        # Org risk (1 - trust)
        ('HOP', 'Distance'),    # Hop distance normalized
        ('GEO', 'Geo Risk'),    # Geographic risk
    ]

    @staticmethod
    def render_mini_radar(values: dict, width: int = 15, height: int = 7,
                          label: str = "", color: str = "cyan") -> list:
        """
        Render a compact ASCII radar chart for a single connection.

        Args:
            values: Dict with keys 'threat', 'confidence', 'org_risk', 'hop_dist', 'geo_risk'
                   Each value should be 0.0-1.0
            width: Chart width in characters
            height: Chart height in lines
            label: Label for the chart (e.g., IP or connection ID)
            color: Rich color for the chart

        Returns:
            List of strings representing the radar chart lines
        """
        # Normalize and extract values (default to 0.5 if missing)
        threat = float(values.get('threat', 0) or 0)
        confidence = float(values.get('confidence', 0.5) or 0.5)
        org_risk = 1.0 - float(values.get('org_trust', 0.5) or 0.5)  # Invert trust to risk
        hop_dist = min(float(values.get('hop_count', 0) or 0) / 30.0, 1.0)  # Normalize to 30 hops max
        geo_risk = float(values.get('geo_risk', 0.3) or 0.3)

        # All values as list in order: THR, CNF, RIS, HOP, GEO
        vals = [threat, confidence, org_risk, hop_dist, geo_risk]

        # Calculate average for overall indicator
        avg_val = sum(vals) / len(vals)

        # Determine threat color based on average
        if avg_val >= 0.7:
            bar_color = "bold red"
            level = "CRIT"
        elif avg_val >= 0.5:
            bar_color = "bold yellow"
            level = "HIGH"
        elif avg_val >= 0.3:
            bar_color = "yellow"
            level = "MED"
        else:
            bar_color = "green"
            level = "LOW"

        lines = []

        # Header with label and threat level
        header = f"[{color}]┌{'─' * (width - 2)}┐[/{color}]"
        lines.append(header)

        # Label line
        label_text = label[:width - 4] if len(label) > width - 4 else label
        label_line = f"[{color}]│[/{color}][{bar_color}]{label_text:^{width - 2}}[/{bar_color}][{color}]│[/{color}]"
        lines.append(label_line)

        # Render each axis as a horizontal bar
        axis_labels = ['THR', 'CNF', 'RIS', 'HOP', 'GEO']
        for i, (ax_label, val) in enumerate(zip(axis_labels, vals)):
            # Calculate bar width
            bar_width = width - 7  # Leave room for label and brackets
            filled = int(val * bar_width)
            empty = bar_width - filled

            # Determine bar character and color based on value
            if val >= 0.7:
                fill_char = '█'
                val_color = "red"
            elif val >= 0.5:
                fill_char = '▓'
                val_color = "yellow"
            elif val >= 0.3:
                fill_char = '▒'
                val_color = "bright_yellow"
            else:
                fill_char = '░'
                val_color = "green"

            bar = f"[{val_color}]{fill_char * filled}[/{val_color}][dim]{'·' * empty}[/dim]"
            line = f"[{color}]│[/{color}]{ax_label}[dim]:[/dim]{bar}[{color}]│[/{color}]"
            lines.append(line)

        # Bottom with overall score
        score_text = f"{avg_val:.2f} {level}"
        bottom_line = f"[{color}]│[/{color}][{bar_color}]{score_text:^{width - 2}}[/{bar_color}][{color}]│[/{color}]"
        lines.append(bottom_line)

        footer = f"[{color}]└{'─' * (width - 2)}┘[/{color}]"
        lines.append(footer)

        return lines

    @staticmethod
    def render_comparison_radar(connections: list, width: int = 40, height: int = 12) -> str:
        """
        Render side-by-side comparison of top 3 threat connections.

        Args:
            connections: List of connection dicts with scoring variables
            width: Total width for all three charts
            height: Height of the visualization

        Returns:
            Formatted string with all three radar charts
        """
        if not connections:
            return "[dim]No threat connections to display[/dim]"

        # Get top 3 highest threats
        sorted_conns = sorted(
            connections,
            key=lambda c: float(c.get('threat_score', 0) or 0),
            reverse=True
        )[:3]

        if not sorted_conns:
            return "[dim]No high-threat connections[/dim]"

        # Render each connection's radar
        chart_width = max(15, (width - 2) // max(len(sorted_conns), 1))
        all_charts = []
        colors = ['cyan', 'magenta', 'yellow']

        for idx, conn in enumerate(sorted_conns):
            # Extract scoring variables
            values = {
                'threat': conn.get('threat_score', 0),
                'confidence': conn.get('confidence', 0.5),
                'org_trust': conn.get('org_trust_score', 0.5),
                'hop_count': conn.get('hop_count', 0),
                'geo_risk': ThreatRadarGraph._calculate_geo_risk(conn),
            }

            # Create label from IP (last octet) or org
            ip = conn.get('dst_ip', 'Unknown')
            org = (conn.get('dst_org') or 'Unknown')[:8]
            label = f"{ip.split('.')[-1] if '.' in ip else ip[:4]}:{org}"

            chart_lines = ThreatRadarGraph.render_mini_radar(
                values,
                width=chart_width,
                height=8,
                label=label,
                color=colors[idx % len(colors)]
            )
            all_charts.append(chart_lines)

        # Combine charts side-by-side
        result_lines = []
        max_lines = max(len(c) for c in all_charts)

        for line_idx in range(max_lines):
            combined = ""
            for chart in all_charts:
                if line_idx < len(chart):
                    combined += chart[line_idx] + " "
                else:
                    combined += " " * (chart_width + 1)
            result_lines.append(combined)

        return "\n".join(result_lines)

    @staticmethod
    def _calculate_geo_risk(conn: dict) -> float:
        """Calculate geographic risk factor from connection data."""
        # Base geo risk on country and org type
        org_type = (conn.get('dst_org_type') or 'unknown').lower()

        # High risk org types
        high_risk_types = {'tor', 'vpn', 'proxy', 'hosting', 'bulletproof'}
        medium_risk_types = {'isp', 'unknown'}

        if org_type in high_risk_types:
            return 0.8
        elif org_type in medium_risk_types:
            return 0.5
        else:
            return 0.2


class ThreatPosturePanel(Static):
    """
    Top-left panel: Threat posture assessment with radar graphs
    Shows current threat level, baseline, active threats, and radar graphs for top 3 threats
    """

    DEFAULT_CSS = """
    ThreatPosturePanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow-y: auto;
    }
    """

    threat_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {
            'current_threat': 0.0,
            'baseline_threat': 0.0,
            'active_threats': 0,
            'monitored_ips': 0,
            'top_threats': [],  # Top 3 threat connections for radar graphs
        }

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self.refresh()

    def render(self):
        """Render threat posture with radar graphs for top 3 threats"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active = self.threat_data.get('active_threats', 0)
        ips = self.threat_data.get('monitored_ips', 0)
        top_threats = self.threat_data.get('top_threats', [])

        # Color code threat level
        if current >= 0.7:
            threat_color = "[bold red]"
            threat_level = "CRITICAL"
        elif current >= 0.5:
            threat_color = "[bold yellow]"
            threat_level = "HIGH"
        elif current >= 0.3:
            threat_color = "[yellow]"
            threat_level = "MEDIUM"
        else:
            threat_color = "[green]"
            threat_level = "LOW"

        # Build content with threat posture info
        content_lines = []
        content_lines.append(f"{threat_color}Current Threat[/]")
        content_lines.append(f"{current:.2f} [{threat_level}]")
        content_lines.append("")
        content_lines.append(f"[dim]Baseline:[/dim] {baseline:.2f}")
        content_lines.append(f"[red]High Threats:[/red] {active}")
        content_lines.append(f"[cyan]Monitored:[/cyan] {ips} IPs")

        # Add separator before radar graphs
        content_lines.append("")
        content_lines.append("[bold cyan]─── TOP THREAT RADAR ───[/bold cyan]")
        content_lines.append("")

        # Add radar graphs for top 3 threats
        if top_threats:
            radar_output = ThreatRadarGraph.render_comparison_radar(
                top_threats,
                width=50,
                height=10
            )
            content_lines.append(radar_output)

            # Add legend
            content_lines.append("")
            content_lines.append("[dim]THR=Threat CNF=Confidence[/dim]")
            content_lines.append("[dim]RIS=OrgRisk HOP=Distance GEO=GeoRisk[/dim]")
        else:
            content_lines.append("[dim]Scanning for threats...[/dim]")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Threat Posture[/bold cyan]",
            border_style="cyan"
        )


class TemporalTrendsPanel(Static):
    """
    Top-center panel: Temporal threat trends
    Shows 60-minute threat history with volume and anomaly counts
    """

    DEFAULT_CSS = """
    TemporalTrendsPanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    trend_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.trend_data = {
            'threat_history': deque(maxlen=60),  # 60 minutes
            'volume_history': deque(maxlen=60),
            'anomaly_count': 0,
        }

    def watch_trend_data(self, new_data: dict) -> None:
        """Trigger re-render when trend data changes"""
        self.refresh()

    def render(self):
        """Render temporal trends with ASCII sparkline"""
        threat_history = list(self.trend_data.get('threat_history', []))
        volume_history = list(self.trend_data.get('volume_history', []))
        anomaly_count = self.trend_data.get('anomaly_count', 0)

        content_lines = []

        # Threat trend sparkline
        if threat_history:
            avg_threat = sum(threat_history) / len(threat_history)
            max_threat = max(threat_history)
            min_threat = min(threat_history)

            # Build sparkline
            sparkline = ThreatRadarGraph._build_sparkline(threat_history, width=40)
            content_lines.append("[bold]Threat Trend (60m)[/bold]")
            content_lines.append(sparkline)
            content_lines.append(f"[dim]avg:{avg_threat:.2f} max:{max_threat:.2f}[/dim]")
        else:
            content_lines.append("[dim]Collecting threat data...[/dim]")

        content_lines.append("")

        # Volume trend
        if volume_history:
            total_vol = sum(volume_history)
            avg_vol = total_vol / len(volume_history)
            sparkline = ThreatRadarGraph._build_sparkline(volume_history, width=40)
            content_lines.append("[bold]Volume Trend[/bold]")
            content_lines.append(sparkline)
            content_lines.append(f"[dim]total:{total_vol} avg:{avg_vol:.0f}[/dim]")
        else:
            content_lines.append("[dim]Collecting volume data...[/dim]")

        content_lines.append("")
        content_lines.append(f"[yellow]Anomalies:[/yellow] {anomaly_count}")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Temporal Trends[/bold cyan]",
            border_style="cyan"
        )

    @staticmethod
    def _build_sparkline(values: list, width: int = 40) -> str:
        """Build ASCII sparkline from values"""
        if not values:
            return "[dim]─" * width + "[/dim]"

        # Normalize values to 0-7 range for block characters
        min_val = min(values)
        max_val = max(values)
        range_val = max_val - min_val if max_val > min_val else 1

        blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']

        # Sample values if too many
        if len(values) > width:
            step = len(values) / width
            sampled = [values[int(i * step)] for i in range(width)]
        else:
            sampled = values

        # Build sparkline
        line = ""
        for val in sampled:
            idx = int((val - min_val) / range_val * 7)
            idx = max(0, min(7, idx))

            # Color based on value
            if val >= 0.7:
                line += f"[red]{blocks[idx]}[/red]"
            elif val >= 0.5:
                line += f"[yellow]{blocks[idx]}[/yellow]"
            else:
                line += f"[green]{blocks[idx]}[/green]"

        return line


# Add the sparkline helper to ThreatRadarGraph
ThreatRadarGraph._build_sparkline = TemporalTrendsPanel._build_sparkline


class GeographicAlertsPanel(Static):
    """
    Top-right panel: Geographic alerts and heatmap
    Shows alert counts by severity and geographic distribution
    """

    DEFAULT_CSS = """
    GeographicAlertsPanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    alert_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.alert_data = {
            'critical_count': 0,
            'warning_count': 0,
            'info_count': 0,
            'geo_map': {},
        }

    def watch_alert_data(self, new_data: dict) -> None:
        """Trigger re-render when alert data changes"""
        self.refresh()

    def render(self):
        """Render geographic alerts"""
        critical = self.alert_data.get('critical_count', 0)
        warning = self.alert_data.get('warning_count', 0)
        info = self.alert_data.get('info_count', 0)
        geo_map = self.alert_data.get('geo_map', {})

        content_lines = []
        content_lines.append("[bold]Alert Summary[/bold]")
        content_lines.append(f"[bold red]CRITICAL:[/bold red] {critical}")
        content_lines.append(f"[bold yellow]WARNING:[/bold yellow] {warning}")
        content_lines.append(f"[cyan]INFO:[/cyan] {info}")
        content_lines.append("")

        # Geographic distribution
        if geo_map:
            content_lines.append("[bold]Geo Distribution[/bold]")
            sorted_geo = sorted(geo_map.items(), key=lambda x: x[1], reverse=True)[:5]
            for country, count in sorted_geo:
                bar_len = min(count, 10)
                bar = '█' * bar_len
                content_lines.append(f"{country:3s} [{bar:10s}] {count}")
        else:
            content_lines.append("[dim]Scanning regions...[/dim]")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Geo Alerts[/bold cyan]",
            border_style="cyan"
        )


class OrganizationIntelPanel(Static):
    """
    Bottom-left panel: Organization intelligence
    Shows risk matrix by organization and top orgs by threat
    """

    DEFAULT_CSS = """
    OrganizationIntelPanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    org_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.org_data = {
            'top_orgs': [],  # List of (org_name, avg_threat, count)
            'risk_matrix': {},
        }

    def watch_org_data(self, new_data: dict) -> None:
        """Trigger re-render when org data changes"""
        self.refresh()

    def render(self):
        """Render organization intelligence"""
        top_orgs = self.org_data.get('top_orgs', [])
        risk_matrix = self.org_data.get('risk_matrix', {})

        content_lines = []
        content_lines.append("[bold]Top Risk Organizations[/bold]")
        content_lines.append("")

        if top_orgs:
            for org, threat, count in top_orgs[:5]:
                # Truncate org name
                org_name = org[:15] if len(org) > 15 else org

                # Color based on threat
                if threat >= 0.7:
                    color = "bold red"
                elif threat >= 0.5:
                    color = "bold yellow"
                elif threat >= 0.3:
                    color = "yellow"
                else:
                    color = "green"

                # Build bar
                bar_width = 8
                filled = int(threat * bar_width)
                bar = '█' * filled + '░' * (bar_width - filled)

                content_lines.append(f"[{color}]{org_name:15s}[/{color}]")
                content_lines.append(f" [{color}]{bar}[/{color}] {threat:.2f} ({count})")
        else:
            content_lines.append("[dim]Analyzing organizations...[/dim]")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Org Intel[/bold cyan]",
            border_style="cyan"
        )


class ConnectionTablePanel(Static):
    """
    Bottom-center panel: Primary connection table
    Shows all connections with full enrichment data
    """

    DEFAULT_CSS = """
    ConnectionTablePanel {
        height: 100%;
        width: 100%;
        overflow: auto;
    }

    ConnectionTablePanel DataTable {
        background: $surface;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.table = None
        self.connections = []

    def compose(self) -> ComposeResult:
        """Create data table"""
        self.table = DataTable(id="connection_table")

        # Add columns
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("Dst IP", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=5)
        self.table.add_column("Org", key="org", width=12)
        self.table.add_column("Type", key="org_type", width=8)
        self.table.add_column("Threat", key="threat", width=6)

        yield self.table

    def watch_connections(self, new_connections: list) -> None:
        """Update table when connections change"""
        if self.table is None:
            return

        self.connections = new_connections
        self.table.clear()

        for conn in self.connections[:50]:
            try:
                time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M:%S")
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()

                # Color based on threat
                if threat >= 0.7:
                    threat_color = "bold red"
                elif threat >= 0.5:
                    threat_color = "bold yellow"
                else:
                    threat_color = "green"

                self.table.add_row(
                    f"[dim]{time_str}[/]",
                    f"[cyan]{conn.get('dst_ip', 'Unknown')[:15]}[/]",
                    f"[magenta]{conn.get('dst_port', '-')}[/]",
                    f"[white]{(conn.get('dst_org') or 'Unknown')[:12]}[/]",
                    f"[dim]{org_type:>8}[/]",
                    f"[{threat_color}]{threat:.2f}[/{threat_color}]",
                )
            except Exception as e:
                logger.debug(f"Failed to add row: {e}")


class ThreatGlobePanel(Static):
    """
    Bottom-right panel: ASCII threat globe
    Shows geographic threat distribution on a globe visualization
    """

    DEFAULT_CSS = """
    ThreatGlobePanel {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    globe_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.globe_data = {
            'connections': [],
            'heatmap': {},
        }
        self.world_map = None

        # Try to initialize flat world map
        try:
            from src.ui.globe_flat import FlatWorldMap
            self.world_map = FlatWorldMap(width=60, height=15)
        except ImportError:
            try:
                from globe_flat import FlatWorldMap
                self.world_map = FlatWorldMap(width=60, height=15)
            except ImportError:
                self.world_map = None

    def watch_globe_data(self, new_data: dict) -> None:
        """Update globe when data changes"""
        if self.world_map is None:
            self.refresh()
            return

        connections = new_data.get('connections', [])

        # Clear and add threats
        self.world_map.clear_threats()
        for conn in connections[-30:]:
            try:
                lat = float(conn.get('dst_lat', 0) or 0)
                lon = float(conn.get('dst_lon', 0) or 0)
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()
                ip = conn.get('dst_ip', 'Unknown')

                self.world_map.add_threat(lat, lon, ip, threat, org_type)
            except Exception as e:
                logger.debug(f"Failed to add threat to globe: {e}")

        self.refresh()

    def render(self):
        """Render threat globe"""
        if self.world_map:
            try:
                self.world_map.update(0.05)
                return self.world_map.render()
            except Exception as e:
                logger.debug(f"Globe render failed: {e}")

        # Fallback: Simple text display
        connections = self.globe_data.get('connections', [])
        content_lines = []
        content_lines.append("[bold cyan]Globe View[/bold cyan]")
        content_lines.append("[dim]Initializing visualization...[/dim]")

        if connections:
            # Show top countries
            countries = {}
            for conn in connections:
                country = (conn.get('dst_country') or 'XX')[:2]
                threat = float(conn.get('threat_score', 0) or 0)
                if country not in countries:
                    countries[country] = []
                countries[country].append(threat)

            sorted_countries = sorted(
                [(c, sum(t)/len(t), len(t)) for c, t in countries.items()],
                key=lambda x: x[1] * x[2],
                reverse=True
            )[:5]

            content_lines.append("")
            content_lines.append("[bold]Top Threat Regions[/bold]")
            for country, avg_threat, count in sorted_countries:
                if avg_threat >= 0.7:
                    color = "red"
                elif avg_threat >= 0.5:
                    color = "yellow"
                else:
                    color = "green"

                bar = '█' * int(avg_threat * 10)
                content_lines.append(f"{country} [{color}]{bar:10s}[/{color}] {avg_threat:.2f}")

        content = "\n".join(content_lines)
        return Panel(content, title="[bold cyan]Threat Globe[/bold cyan]", border_style="cyan")
