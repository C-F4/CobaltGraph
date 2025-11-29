#!/usr/bin/env python3
"""
CobaltGraph Unified Dashboard Components
Implements the 6-cell grid components following the cobalt0.001.jpg model

Components:
1. ThreatPosturePanel - Current threat assessment with baseline comparison
2. TemporalTrendsPanel - 60-minute history with volume and anomalies
3. GeographicAlertsPanel - Heatmap display with active alert summary
4. OrganizationIntelPanel - Risk matrix and top organizations
5. ConnectionTablePanel - Primary data focus with full enrichment
6. ThreatGlobePanel - ASCII globe with heatmap and connection trails
"""

import logging
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional

from rich.panel import Panel
from rich.text import Text
from rich.table import Table as RichTable

from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class ThreatPosturePanel(Static):
    """
    Top-left (20%): Current threat assessment
    Shows real-time threat posture with baseline comparison
    """

    DEFAULT_CSS = """
    ThreatPosturePanel {
        height: 100%;
        width: 100%;
        padding: 1;
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
        }

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self.refresh()

    def render(self):
        """Render threat posture with color coding"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active = self.threat_data.get('active_threats', 0)
        ips = self.threat_data.get('monitored_ips', 0)

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

        content = f"""{threat_color}Current Threat[/]
{current:.2f} [{threat_level}]

[dim]24h Baseline:[/dim]
{baseline:.2f}

[cyan]Active Threats:[/cyan]
{active}

[cyan]Monitored IPs:[/cyan]
{ips}
"""

        return Panel(
            content,
            title="[bold cyan]Threat Posture[/bold cyan]",
            border_style="cyan"
        )


class TemporalTrendsPanel(Static):
    """
    Top-center (50%): Live Activity Monitor (Dynamic)
    Shows real-time connection metrics and threat distribution
    """

    DEFAULT_CSS = """
    TemporalTrendsPanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    trend_data = reactive(dict)
    frame_count = 0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.trend_data = {
            'threat_history': deque(maxlen=60),
            'volume_history': deque(maxlen=60),
            'anomaly_count': 0,
        }
        self.frame_count = 0

    def watch_trend_data(self, new_data: dict) -> None:
        """Trigger re-render when trend data changes"""
        self.frame_count = (self.frame_count + 1) % 4
        self.refresh()

    def render(self):
        """Render live activity monitor with dynamic indicators"""
        threats = list(self.trend_data.get('threat_history', []))
        volumes = list(self.trend_data.get('volume_history', []))
        anomalies = self.trend_data.get('anomaly_count', 0)

        # Dynamic spinner
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner = spinners[self.frame_count % len(spinners)]

        # Calculate stats
        avg_threat = (sum(threats) / len(threats)) if threats else 0
        peak_volume = max(volumes) if volumes else 0
        total_volume = sum(volumes) if volumes else 0

        # Threat level indicator
        if avg_threat >= 0.7:
            threat_bar = "[bold red]████████[/bold red]"
            level = "CRITICAL"
        elif avg_threat >= 0.5:
            threat_bar = "[bold yellow]██████░░[/bold yellow]"
            level = "HIGH"
        elif avg_threat >= 0.3:
            threat_bar = "[yellow]████░░░░[/yellow]"
            level = "MEDIUM"
        else:
            threat_bar = "[green]██░░░░░░[/green]"
            level = "LOW"

        content = f"""{spinner} [cyan]Live Activity[/cyan]

[cyan]Threat Level:[/cyan] {threat_bar}
[cyan]Level:[/cyan] {level} ({avg_threat:.2f})

[cyan]Volume:[/cyan] Peak: {peak_volume} | Total: {total_volume}
[cyan]Anomalies:[/cyan] {anomalies}
"""

        return Panel(content, title="[bold cyan]Monitor[/bold cyan]")


class GeographicAlertsPanel(Static):
    """
    Top-right (30%): Alert summary (compact)
    Shows critical alerts only, minimal display
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
            'geo_map': {},
            'critical_count': 0,
            'warning_count': 0,
            'info_count': 0,
        }

    def watch_alert_data(self, new_data: dict) -> None:
        """Trigger re-render when alert data changes"""
        self.refresh()

    def render(self):
        """Render compact alert summary"""
        critical = self.alert_data.get('critical_count', 0)
        warning = self.alert_data.get('warning_count', 0)
        info = self.alert_data.get('info_count', 0)

        content = f"""[bold red]CRITICAL:[/bold red] {critical}
[bold yellow]WARNING:[/bold yellow] {warning}
[cyan]INFO:[/cyan] {info}
"""

        return Panel(
            content,
            title="[bold cyan]Alerts[/bold cyan]"
        )


class OrganizationIntelPanel(Static):
    """
    Bottom-left (20%): Organization intelligence
    Shows risk matrix and top organizations by threat
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
            'top_orgs': [],
            'risk_matrix': {},
        }

    def watch_org_data(self, new_data: dict) -> None:
        """Trigger re-render when org data changes"""
        self.refresh()

    def render(self):
        """Render organization risk matrix and top organizations"""
        top_orgs = self.org_data.get('top_orgs', [])[:5]

        content = "[bold yellow]Top Organizations (Last Hour)[/bold yellow]\n"
        if top_orgs:
            for org_name, threat, count in top_orgs:
                # Handle None organization names
                org_display = (org_name or 'Unknown')[:15]
                content += f"[cyan]{org_display:<15}[/cyan] "
                content += f"[red]{threat:.2f}[/red] [{count}]\n"
        else:
            content += "[dim]No organization data available[/dim]\n"

        content += "\n[bold cyan]Risk Matrix[/bold cyan]\n"
        content += "[dim](Threat vs Trust) Click to filter[/dim]"

        return Panel(
            content,
            title="[bold yellow]Organization Intel[/bold yellow]",
            border_style="yellow"
        )


class ConnectionTablePanel(Static):
    """
    Bottom-center (50%): Connection intelligence table (INTERACTIVE)
    Primary data focus with full scrolling (vertical + horizontal)
    """

    DEFAULT_CSS = """
    ConnectionTablePanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }

    ConnectionTablePanel:focus {
        background: $boost;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections = []
        self.filter_level = "all"  # all, critical, high, medium, low
        self.scroll_index = 0
        self.sort_column = "timestamp"  # Can be sorted by any column

    def watch_connections(self, new_connections: list) -> None:
        """Trigger re-render when connections change"""
        self.refresh()

    def render(self):
        """Render scrollable connection table with all visible columns"""
        if not self.connections:
            return Panel(
                "[dim]Loading connections...[/dim]",
                title="[bold cyan]Connections[/bold cyan]"
            )

        # Use compact column widths to fit all data
        table = RichTable(title="[bold cyan]Connections[/bold cyan]", show_footer=False)
        table.add_column("Time", style="cyan", width=8, no_wrap=True)
        table.add_column("IP", style="cyan", width=12, no_wrap=True)
        table.add_column("Port", width=4, no_wrap=True)
        table.add_column("Org", width=12, no_wrap=True)
        table.add_column("Risk", width=4, no_wrap=True)
        table.add_column("Hops", width=3, no_wrap=True)

        # Show all connections (scrollable)
        for conn in self.connections[:50]:  # Limit to 50 for performance
            time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M")
            ip = (conn.get('dst_ip') or '-')[:12]
            port = str(conn.get('dst_port', '-'))[:4]
            org = (conn.get('dst_org') or 'U')[:12]
            threat = float(conn.get('threat_score', 0) or 0)
            hops = str(conn.get('hop_count', '-'))[:3]

            # Color code threat with symbols
            if threat >= 0.7:
                threat_label = f"[bold red]●●[/bold red]"
            elif threat >= 0.5:
                threat_label = f"[bold yellow]●○[/bold yellow]"
            elif threat >= 0.3:
                threat_label = f"[yellow]◐○[/yellow]"
            else:
                threat_label = f"[green]○○[/green]"

            table.add_row(time_str, ip, port, org, threat_label, hops)

        return Panel(table)


class ThreatGlobePanel(Static):
    """
    Bottom-right (30%): Real geographic threat globe
    Shows actual lat/lon connections on world map
    Interactive visualization of threat distribution
    """

    DEFAULT_CSS = """
    ThreatGlobePanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    globe_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.animation_frame = 0
        self.globe_data = {
            'connections': [],
            'heatmap': {},
        }

    def watch_globe_data(self, new_data: dict) -> None:
        """Trigger re-render when globe data changes"""
        if hasattr(self, 'animation_frame'):
            self.animation_frame = (self.animation_frame + 1) % 4
        self.refresh()

    def render(self):
        """Render geographic threat globe with real lat/lon data"""
        connections = self.globe_data.get('connections', [])

        # Extract geographic data
        geo_threats = {}  # country -> threat_list
        for conn in connections:
            country = (conn.get('dst_country') or 'Unknown')[:3].upper()
            threat = float(conn.get('threat_score', 0) or 0)
            if country not in geo_threats:
                geo_threats[country] = []
            geo_threats[country].append(threat)

        # Calculate top threat regions
        top_regions = sorted(
            [(c, sum(t)/len(t), len(t)) for c, t in geo_threats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Build geographic globe display
        content = "[bold cyan]Global Threat Map[/bold cyan]\n"

        if top_regions:
            for country, avg_threat, count in top_regions:
                # Color code by threat level
                if avg_threat >= 0.7:
                    color = "[bold red]"
                    bar = "█████"
                elif avg_threat >= 0.5:
                    color = "[bold yellow]"
                    bar = "████░"
                elif avg_threat >= 0.3:
                    color = "[yellow]"
                    bar = "███░░"
                else:
                    color = "[green]"
                    bar = "██░░░"

                content += f"{color}{country}[/] {bar} {avg_threat:.2f} ({count})\n"
        else:
            content += "[dim]Loading geographic data...[/dim]\n"

        # Show connection heat
        total_threat = sum(c.get('threat_score', 0) or 0 for c in connections)
        avg_threat = (total_threat / len(connections)) if connections else 0

        content += f"\n[cyan]Global Risk:[/cyan] {avg_threat:.2f}"

        return Panel(content, title="[bold cyan]Threat Map[/bold cyan]")
