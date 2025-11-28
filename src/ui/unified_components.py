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
        border: solid $primary;
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
    Top-center (50%): 60-minute threat history
    Shows threat trends, connection volume, and anomalies
    """

    DEFAULT_CSS = """
    TemporalTrendsPanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
        padding: 1;
    }
    """

    trend_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.trend_data = {
            'threat_history': deque(maxlen=60),
            'volume_history': deque(maxlen=60),
            'anomaly_count': 0,
        }

    def render(self):
        """Render temporal trends with sparklines"""
        threats = list(self.trend_data.get('threat_history', []))
        volumes = list(self.trend_data.get('volume_history', []))
        anomalies = self.trend_data.get('anomaly_count', 0)

        # Sparkline characters
        sparkline_chars = "▁▂▃▄▅▆▇█"

        def make_sparkline(data, max_val=None):
            if not data:
                return "─ no data ─"
            if max_val is None:
                max_val = max(data) if data else 1.0
            max_val = max(max_val, 0.01)
            line = ""
            for val in data:
                idx = int((val / max_val) * (len(sparkline_chars) - 1))
                line += sparkline_chars[min(idx, len(sparkline_chars) - 1)]
            return line

        threat_sparkline = make_sparkline(threats, 1.0)
        volume_sparkline = make_sparkline(volumes)

        content = f"""[cyan]Threat Level:[/cyan]
{threat_sparkline}
{f"Avg: {sum(threats)/len(threats):.2f}" if threats else "Collecting..."}

[cyan]Connection Volume:[/cyan]
{volume_sparkline}
{f"Peak: {max(volumes) if volumes else 0}" if volumes else "Collecting..."}

[bold red]Recent Anomalies:[/bold red]
{anomalies} detected
"""

        return Panel(
            content,
            title="[bold cyan]60-Minute Trends[/bold cyan]",
            border_style="cyan"
        )


class GeographicAlertsPanel(Static):
    """
    Top-right (30%): Geographic heatmap + active alerts
    Shows geographic threat distribution and active alert summary
    """

    DEFAULT_CSS = """
    GeographicAlertsPanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
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

    def render(self):
        """Render geographic heatmap and alert summary"""
        critical = self.alert_data.get('critical_count', 0)
        warning = self.alert_data.get('warning_count', 0)
        info = self.alert_data.get('info_count', 0)

        content = f"""[bold cyan]Geographic Heatmap[/bold cyan]
[dim]No geographic data available[/dim]
[dim]Click to filter by country[/dim]

[bold yellow]Active Alerts[/bold yellow]
[bold red]CRITICAL:[/bold red] {critical}
[bold yellow]WARNING:[/bold yellow] {warning}
[cyan]INFO:[/cyan] {info}

[Actions: [cyan]I[/cyan]nvestigate | [red]B[/red]lock | [yellow]D[/yellow]ismiss]
auto-scroll ON
"""

        return Panel(
            content,
            title="[bold cyan]Alerts & Geo[/bold cyan]",
            border_style="cyan"
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
        border: solid $primary;
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

    def render(self):
        """Render organization risk matrix and top organizations"""
        top_orgs = self.org_data.get('top_orgs', [])[:5]

        content = "[bold yellow]Top Organizations (Last Hour)[/bold yellow]\n"
        if top_orgs:
            for org_name, threat, count in top_orgs:
                content += f"[cyan]{org_name[:15]:<15}[/cyan] "
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
    Bottom-center (50%): Connection intelligence table
    Primary data focus showing full connection enrichment
    """

    DEFAULT_CSS = """
    ConnectionTablePanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
        padding: 1;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections = []
        self.filter_level = "all"  # all, critical, high, medium, low

    def render(self):
        """Render connection table with color-coded threats"""
        if not self.connections:
            return Panel(
                "[dim]Waiting for connections...[/dim]",
                title="[bold cyan]Connections[/bold cyan]",
                border_style="cyan"
            )

        table = RichTable(title="[bold cyan]Connections Intelligence[/bold cyan]")
        table.add_column("Time", style="cyan", width=8)
        table.add_column("IP", style="cyan", width=15)
        table.add_column("Port", width=5)
        table.add_column("Org", width=20)
        table.add_column("Risk", width=5)
        table.add_column("Hops", width=4)

        for conn in self.connections[:10]:  # Show top 10
            time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M:%S")
            ip = conn.get('dst_ip', '-')
            port = str(conn.get('dst_port', '-'))
            org = conn.get('dst_org', 'Unknown')[:15]
            threat = float(conn.get('threat_score', 0) or 0)
            hops = str(conn.get('hop_count', '-'))

            if threat >= 0.7:
                risk_style = "bold red"
                risk_label = "CRIT"
            elif threat >= 0.5:
                risk_style = "bold yellow"
                risk_label = "HIGH"
            elif threat >= 0.3:
                risk_style = "yellow"
                risk_label = "MED"
            else:
                risk_style = "green"
                risk_label = "LOW"

            table.add_row(time_str, ip, port, org, Text(risk_label, style=risk_style), hops)

        return Panel(table, border_style="cyan")


class ThreatGlobePanel(Static):
    """
    Bottom-right (30%): Threat globe visualization
    ASCII globe with heatmap and animated connection trails
    """

    DEFAULT_CSS = """
    ThreatGlobePanel {
        height: 100%;
        width: 100%;
        border: solid $primary;
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

    def render(self):
        """Render ASCII globe with threat visualization"""
        content = """
    oooooooooooo.....
  ooo                ooo
 oo                    oo
o                        o
o                        o
o         GLOBE          o
o                        o
o                        o
 oo                    oo
  ooo                ooo
    oooooooooooo.....

    [dim]heatmap + trails[/dim]
"""

        return Panel(
            content,
            title="[bold cyan]Threat Globe[/bold cyan]",
            border_style="cyan"
        )
