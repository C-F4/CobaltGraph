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
from textual.message import Message

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
    Top-left panel: Threat posture assessment with radar graphs and system status gumballs
    Shows current threat level, baseline, active threats, radar graphs for top 3 threats,
    and real-time component health indicators.
    """

    DEFAULT_CSS = """
    ThreatPosturePanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow-y: auto;
    }
    """

    # Component definitions for system status gumballs
    # These must match the keys in heartbeat.COBALTGRAPH_COMPONENTS
    SYSTEM_COMPONENTS = [
        ("database", "Database"),
        ("capture", "Capture"),
        ("pipeline", "Pipeline"),
        ("consensus", "Consensus"),
        ("geo_engine", "GeoIP"),
        ("asn_lookup", "ASN"),
        ("reputation", "Reputation"),
        ("dashboard", "Dashboard"),
    ]

    threat_data = reactive(dict)
    system_status = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {
            'current_threat': 0.0,
            'baseline_threat': 0.0,
            'active_threats': 0,
            'monitored_ips': 0,
            'top_threats': [],  # Top 3 threat connections for radar graphs
        }
        # Initialize with empty status - will be populated by heartbeat
        self.system_status = {}

    def _get_gumball(self, status: str) -> str:
        """Return colored gumball indicator based on status"""
        if status == "ACTIVE":
            return "[bold bright_green]●[/bold bright_green]"
        elif status == "DEGRADED":
            return "[bold yellow]●[/bold yellow]"
        else:  # DEAD
            return "[bold red]●[/bold red]"

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self.refresh()

    def watch_system_status(self, new_data: dict) -> None:
        """Trigger re-render when system status changes"""
        self.refresh()

    def render(self):
        """Render threat posture with system status gumballs and radar graphs"""
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

        # Build content with system status gumballs first
        content_lines = []
        content_lines.append("[bold cyan]─── SYSTEM STATUS ───[/bold cyan]")

        # Render system status gumballs in a compact 2-column layout
        for i in range(0, len(self.SYSTEM_COMPONENTS), 2):
            left_comp = self.SYSTEM_COMPONENTS[i]
            left_info = self.system_status.get(left_comp[0], {})
            left_status = left_info.get("status", "DEAD")
            left_gumball = self._get_gumball(left_status)
            left_text = f"{left_gumball} {left_comp[1]:<9}"

            if i + 1 < len(self.SYSTEM_COMPONENTS):
                right_comp = self.SYSTEM_COMPONENTS[i + 1]
                right_info = self.system_status.get(right_comp[0], {})
                right_status = right_info.get("status", "DEAD")
                right_gumball = self._get_gumball(right_status)
                right_text = f"{right_gumball} {right_comp[1]}"
            else:
                right_text = ""

            content_lines.append(f"{left_text} {right_text}")

        # Calculate overall system health from actual status data
        online_count = 0
        total_health = 0
        component_count = len(self.system_status) if self.system_status else len(self.SYSTEM_COMPONENTS)

        for comp_id, comp_info in self.system_status.items():
            if comp_info.get("status") == "ACTIVE":
                online_count += 1
            total_health += comp_info.get("health_percentage", 0)

        avg_health = total_health / component_count if component_count > 0 else 0
        content_lines.append(f"[dim]{online_count}/{component_count} online | {avg_health:.0f}% health[/dim]")

        # Add separator and threat posture info
        content_lines.append("")
        content_lines.append("[bold cyan]─── THREAT POSTURE ───[/bold cyan]")
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


class ConsensusBreakdownPanel(Static):
    """
    Dashboard panel showing compact 4-scorer consensus breakdown.
    Shows individual scorer bars at-a-glance with agreement indicator.

    Replaces TemporalTrendsPanel in the top-center position for
    enhanced consensus visibility.
    """

    DEFAULT_CSS = """
    ConsensusBreakdownPanel {
        height: 100%;
        width: 100%;
    }
    """

    consensus_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.consensus_data = {
            'last_consensus': None,
            'scorer_history': {
                'statistical': [],
                'rule_based': [],
                'ml_based': [],
                'organization': [],
            },
            'agreement_rate': 1.0,
            'total_assessments': 0,
        }

    def watch_consensus_data(self, new_data: dict) -> None:
        """Trigger re-render when consensus data changes"""
        self.refresh()

    def update_from_connection(self, conn: Dict) -> None:
        """Update consensus display from a connection record"""
        score_statistical = conn.get('score_statistical')
        score_rule_based = conn.get('score_rule_based')
        score_ml_based = conn.get('score_ml_based')
        score_organization = conn.get('score_organization')
        score_spread = conn.get('score_spread')
        high_uncertainty = conn.get('high_uncertainty', False)

        self.consensus_data = {
            'last_consensus': {
                'statistical': score_statistical,
                'rule_based': score_rule_based,
                'ml_based': score_ml_based,
                'organization': score_organization,
                'spread': score_spread,
                'high_uncertainty': high_uncertainty,
                'final_score': conn.get('threat_score', 0),
                'confidence': conn.get('confidence', 0),
            },
            'scorer_history': self.consensus_data.get('scorer_history', {}),
            'agreement_rate': 1.0 - (score_spread or 0),
            'total_assessments': self.consensus_data.get('total_assessments', 0) + 1,
        }

    def render(self):
        """Render compact 4-scorer breakdown with bars"""
        last = self.consensus_data.get('last_consensus')
        agreement_rate = self.consensus_data.get('agreement_rate', 1.0)
        total = self.consensus_data.get('total_assessments', 0)

        content_lines = []
        content_lines.append("[bold cyan]─── SCORER CONSENSUS ───[/bold cyan]")
        content_lines.append("")

        # Agreement indicator
        if last:
            spread = last.get('spread') or 0
            high_uncertainty = last.get('high_uncertainty', False)

            if high_uncertainty:
                agreement_indicator = "[bold yellow]⚠ DISAGREEMENT[/bold yellow]"
            elif spread < 0.15:
                agreement_indicator = "[bold green]✓ STRONG AGREEMENT[/bold green]"
            elif spread < 0.25:
                agreement_indicator = "[green]◐ MODERATE[/green]"
            else:
                agreement_indicator = "[yellow]◐ WEAK[/yellow]"

            content_lines.append(f"Status: {agreement_indicator}")
            content_lines.append("")

            # Final score summary
            final = last.get('final_score', 0)
            confidence = last.get('confidence', 0)

            if final >= 0.7:
                final_color = "red"
            elif final >= 0.5:
                final_color = "yellow"
            else:
                final_color = "green"

            content_lines.append(f"Final: [{final_color}]{final:.2f}[/{final_color}] | Conf: {confidence:.2f}")
            content_lines.append("")

            # 4 Scorer compact bars
            content_lines.append("[bold]Scorer Breakdown[/bold]")

            scorers = [
                ("STAT", last.get('statistical'), "cyan"),
                ("RULE", last.get('rule_based'), "magenta"),
                ("ML  ", last.get('ml_based'), "blue"),
                ("ORG ", last.get('organization'), "yellow"),
            ]

            bar_width = 15
            for name, score, base_color in scorers:
                if score is None:
                    content_lines.append(f"{name} [dim]{'─' * bar_width}[/dim] N/A")
                    continue

                score = float(score)
                filled = int(score * bar_width)

                # Color based on score level
                if score >= 0.7:
                    color = "red"
                elif score >= 0.5:
                    color = "yellow"
                else:
                    color = "green"

                bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (bar_width - filled)}[/dim]"
                content_lines.append(f"{name} {bar} [{color}]{score:.2f}[/{color}]")

            content_lines.append("")

            # Spread indicator
            if spread is not None:
                spread_bar_width = 20
                spread_filled = int(spread * spread_bar_width * 2)  # Scale for visibility
                spread_filled = min(spread_bar_width, spread_filled)

                spread_color = "green" if spread < 0.15 else "yellow" if spread < 0.25 else "red"
                spread_bar = f"[{spread_color}]{'█' * spread_filled}[/{spread_color}][dim]{'░' * (spread_bar_width - spread_filled)}[/dim]"
                content_lines.append(f"[dim]Spread:[/dim] {spread_bar} [{spread_color}]{spread:.3f}[/{spread_color}]")

        else:
            content_lines.append("[dim]Awaiting consensus data...[/dim]")
            content_lines.append("")
            content_lines.append("[dim]Scorers:[/dim]")
            content_lines.append("  STAT  Rule-based statistical")
            content_lines.append("  RULE  Pattern matching")
            content_lines.append("  ML    Machine learning")
            content_lines.append("  ORG   Organization trust")

        content_lines.append("")
        content_lines.append(f"[dim]Assessments: {total}[/dim]")

        content = "\n".join(content_lines)

        return Panel(
            content,
            title="[bold cyan]Consensus[/bold cyan]",
            border_style="cyan"
        )


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
    Shows all connections with full enrichment data.

    Click any row to open the Connection Intelligence Modal
    with full details about that connection.
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

    ConnectionTablePanel DataTable > .datatable--cursor {
        background: $primary 30%;
    }

    ConnectionTablePanel DataTable > .datatable--hover {
        background: $primary 20%;
    }
    """

    connections = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.table = None
        self.connections = []
        self._row_to_connection: Dict[Any, Dict] = {}  # Map row keys to connection data

    def compose(self) -> ComposeResult:
        """Create data table with cursor enabled for selection"""
        self.table = DataTable(id="connection_table", cursor_type="row")

        # Add columns - include confidence indicator
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("Dst IP", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=5)
        self.table.add_column("Org", key="org", width=12)
        self.table.add_column("Type", key="org_type", width=8)
        self.table.add_column("Threat", key="threat", width=6)
        self.table.add_column("", key="indicator", width=3)  # Status indicator

        yield self.table

    def watch_connections(self, new_connections: list) -> None:
        """Update table when connections change"""
        if self.table is None:
            return

        self.connections = new_connections
        self.table.clear()
        self._row_to_connection.clear()

        for idx, conn in enumerate(self.connections[:50]):
            try:
                time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M:%S")
                threat = float(conn.get('threat_score', 0) or 0)
                confidence = float(conn.get('confidence', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()
                high_uncertainty = conn.get('high_uncertainty', False)

                # Color based on threat
                if threat >= 0.7:
                    threat_color = "bold red"
                elif threat >= 0.5:
                    threat_color = "bold yellow"
                else:
                    threat_color = "green"

                # Status indicator
                if high_uncertainty:
                    indicator = "[yellow]⚠[/yellow]"  # Uncertainty warning
                elif threat >= 0.7:
                    indicator = "[red]●[/red]"  # Critical
                elif threat >= 0.5:
                    indicator = "[yellow]●[/yellow]"  # Warning
                elif confidence >= 0.8:
                    indicator = "[green]●[/green]"  # High confidence clean
                else:
                    indicator = "[dim]○[/dim]"  # Normal

                # Add row and store the connection data mapping
                row_key = self.table.add_row(
                    f"[dim]{time_str}[/]",
                    f"[cyan]{conn.get('dst_ip', 'Unknown')[:15]}[/]",
                    f"[magenta]{conn.get('dst_port', '-')}[/]",
                    f"[white]{(conn.get('dst_org') or 'Unknown')[:12]}[/]",
                    f"[dim]{org_type:>8}[/]",
                    f"[{threat_color}]{threat:.2f}[/{threat_color}]",
                    indicator,
                )
                self._row_to_connection[row_key] = conn

            except Exception as e:
                logger.debug(f"Failed to add row: {e}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """
        Handle row selection - post message to parent to open modal.
        The parent dashboard will handle opening the ConnectionIntelligenceModal.
        """
        row_key = event.row_key
        connection_data = self._row_to_connection.get(row_key)

        if connection_data:
            # Post a custom message to the app to open the modal
            self.post_message(ConnectionSelected(connection_data))
            logger.debug(f"Row selected: {connection_data.get('dst_ip')}")


class ConnectionSelected(Message):
    """Message posted when a connection row is selected in the table."""

    def __init__(self, connection_data: Dict[str, Any]):
        super().__init__()
        self.connection_data = connection_data


class ThreatAlert(Message):
    """
    Message posted when a threat alert should be shown as a toast notification.
    Used by the alert engine to surface critical events to the user.
    """

    # Severity levels matching Textual's notify severity
    SEVERITY_CRITICAL = "error"      # Red toast
    SEVERITY_WARNING = "warning"     # Yellow toast
    SEVERITY_INFO = "information"    # Blue toast

    def __init__(
        self,
        title: str,
        message: str,
        severity: str = "information",
        dst_ip: Optional[str] = None,
        rule_matched: Optional[str] = None,
        threat_score: Optional[float] = None,
        timeout: float = 5.0,
    ):
        super().__init__()
        self.title = title
        self.message = message
        self.severity = severity
        self.dst_ip = dst_ip
        self.rule_matched = rule_matched
        self.threat_score = threat_score
        self.timeout = timeout


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


class SystemStatusPanel(Static):
    """
    System status panel with real-time heartbeat gumballs for each CobaltGraph component.
    Shows ONLINE/DEGRADED/OFFLINE status via colored indicators.

    Components monitored:
    - Database: SQLite connection health
    - Capture: Network packet capture (requires root)
    - Pipeline: Data processing pipeline
    - Consensus: BFT threat scoring engine
    - GeoIP: Geolocation service
    - ASN: ASN lookup service
    - Reputation: IP reputation (VirusTotal/AbuseIPDB)
    """

    DEFAULT_CSS = """
    SystemStatusPanel {
        height: auto;
        width: 100%;
        padding: 0 1;
    }
    """

    # Component definitions with display names and descriptions
    COMPONENTS = [
        ("database", "Database", "SQLite WAL"),
        ("capture", "Capture", "Packet capture"),
        ("pipeline", "Pipeline", "Data processing"),
        ("consensus", "Consensus", "BFT scoring"),
        ("geo_engine", "GeoIP", "Geolocation"),
        ("asn_lookup", "ASN", "ASN lookup"),
        ("reputation", "Reputation", "IP reputation"),
    ]

    status_data = reactive(dict)

    def __init__(self, heartbeat_monitor=None, **kwargs):
        super().__init__(**kwargs)
        self.heartbeat_monitor = heartbeat_monitor
        self.status_data = {
            comp_id: {"status": "DEAD", "health": 0, "age": 999}
            for comp_id, _, _ in self.COMPONENTS
        }

    def update_from_heartbeat(self, heartbeat_monitor) -> None:
        """Update status from heartbeat monitor instance"""
        self.heartbeat_monitor = heartbeat_monitor
        if heartbeat_monitor:
            self.status_data = heartbeat_monitor.get_status()
            self.refresh()

    def watch_status_data(self, new_data: dict) -> None:
        """Trigger re-render when status data changes"""
        self.refresh()

    def _get_gumball(self, status: str) -> str:
        """Return colored gumball indicator based on status"""
        if status == "ACTIVE":
            return "[bold bright_green]●[/bold bright_green]"
        elif status == "DEGRADED":
            return "[bold yellow]●[/bold yellow]"
        else:  # DEAD
            return "[bold red]●[/bold red]"

    def _get_status_text(self, status: str) -> str:
        """Return colored status text"""
        if status == "ACTIVE":
            return "[green]ONLINE[/green]"
        elif status == "DEGRADED":
            return "[yellow]DEGRADED[/yellow]"
        else:
            return "[red]OFFLINE[/red]"

    def render(self):
        """Render system status with gumball indicators"""
        content_lines = []
        content_lines.append("[bold cyan]─── SYSTEM STATUS ───[/bold cyan]")
        content_lines.append("")

        for comp_id, display_name, description in self.COMPONENTS:
            comp_status = self.status_data.get(comp_id, {})
            status = comp_status.get("status", "DEAD")
            health = comp_status.get("health_percentage", 0)
            age = comp_status.get("last_beat_age", 999)

            gumball = self._get_gumball(status)
            status_text = self._get_status_text(status)

            # Format: ● Database    ONLINE  (100%)
            line = f"{gumball} {display_name:<10} {status_text}"
            content_lines.append(line)

        # Add overall health bar
        content_lines.append("")
        total_health = sum(
            self.status_data.get(c[0], {}).get("health_percentage", 0)
            for c in self.COMPONENTS
        )
        avg_health = total_health / len(self.COMPONENTS) if self.COMPONENTS else 0

        # Health bar visualization
        bar_width = 20
        filled = int(avg_health / 100 * bar_width)
        if avg_health >= 80:
            bar_color = "green"
        elif avg_health >= 50:
            bar_color = "yellow"
        else:
            bar_color = "red"

        health_bar = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (bar_width - filled)}[/dim]"
        content_lines.append(f"[dim]Health:[/dim] {health_bar} {avg_health:.0f}%")

        content = "\n".join(content_lines)
        return Panel(
            content,
            title="[bold cyan]System[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
