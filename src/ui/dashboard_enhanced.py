#!/usr/bin/env python3
"""
CobaltGraph Enhanced Unified Dashboard
Comprehensive threat monitoring with mode-aware layout (device/network)

Features:
- 6-cell grid layout matching cobalt_base_maybe.png reference design
- Mode-specific rendering (device vs network)
- Integrated ASCII globe with threat heatmaps and connection trails
- Real-time threat scoring and organization intelligence
- Geographic threat visualization with hop topology
- High-density connection table with full enrichment data

Architecture:
- Inherits from unified_dashboard.UnifiedDashboard for base framework
- Extends with enhanced components and mode-specific panels
- Integrated ascii_globe.py for superior globe rendering
- DataManager + VisualizationManager for real-time updates
"""

import logging
import sqlite3
import time
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.panel import Panel
from rich.table import Table as RichTable
from rich.text import Text

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, Static, DataTable
from textual.reactive import reactive

logger = logging.getLogger(__name__)

try:
    from src.ui.unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager
except ImportError:
    from unified_dashboard import UnifiedDashboard, DataManager, VisualizationManager

try:
    from src.ui.ascii_globe import ASCIIGlobe, ConnectionPing
except ImportError:
    ASCIIGlobe = None
    ConnectionPing = None


class ThreatPostureQuickPanel(Static):
    """
    Top-left (50%): Quick threat posture assessment
    Current threat level, baseline, active threats, monitored IPs
    """

    DEFAULT_CSS = """
    ThreatPostureQuickPanel {
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
            'high_threat_count': 0,
        }

    def watch_threat_data(self, new_data: dict) -> None:
        """Trigger re-render when threat data changes"""
        self.refresh()

    def render(self):
        """Render threat posture"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active = self.threat_data.get('active_threats', 0)
        ips = self.threat_data.get('monitored_ips', 0)
        high_threat = self.threat_data.get('high_threat_count', 0)

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

[dim]Baseline:[/dim] {baseline:.2f}
[red]High Threats:[/red] {high_threat}
[cyan]Active:[/cyan] {active}
[cyan]Monitored:[/cyan] {ips} IPs
"""

        return Panel(
            content,
            title="[bold cyan]Threat Posture[/bold cyan]",
            border_style="cyan"
        )


class EnhancedThreatGlobePanel(Static):
    """
    Top-Right (50%): Interactive Threat Visualization
    Provides real-time threat heat mapping and animated connection visualization

    Features:
    - Dynamic threat heatmap by region
    - Animated connection indicators
    - Real-time threat scores
    - Color-coded threat levels
    """

    DEFAULT_CSS = """
    EnhancedThreatGlobePanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: hidden;
    }
    """

    globe_data = reactive(dict)
    animation_frame = reactive(int)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.globe = None
        self.globe_data = {
            'connections': [],
            'heatmap': {},
            'stats': {},
        }
        self.animation_frame = 0
        self.threat_regions = {}
        self.region_pings = []

        # Initialize ASCII globe if available
        if ASCIIGlobe:
            try:
                # Calculate dimensions from terminal (will be refined on mount)
                self.globe = ASCIIGlobe(width=40, height=20)
                self.globe.state.rotation_x = 23.5  # Earth's axial tilt
                self.globe.auto_rotate = True
                self.globe.rotation_speed = 15.0  # degrees per second
            except Exception as e:
                logger.warning(f"Failed to initialize ASCIIGlobe: {e}")
                self.globe = None

    def watch_globe_data(self, new_data: dict) -> None:
        """Update globe when data changes"""
        if self.globe is None:
            return

        try:
            # Extract threat regions from connections
            connections = new_data.get('connections', [])

            # Build threat region map
            self.threat_regions = {}
            for conn in connections[-20:]:  # Last 20 connections
                try:
                    country = (conn.get('dst_country') or 'Unknown')[:2].upper()
                    threat = float(conn.get('threat_score', 0) or 0)

                    if country not in self.threat_regions:
                        self.threat_regions[country] = {'count': 0, 'avg_threat': 0.0, 'ips': []}

                    self.threat_regions[country]['count'] += 1
                    self.threat_regions[country]['avg_threat'] = threat
                    self.threat_regions[country]['ips'].append(conn.get('dst_ip', 'Unknown'))

                    # Add to globe
                    src_lat, src_lon = 39.8283, -98.5795  # US center
                    dst_lat = float(conn.get('dst_lat', 0) or 0)
                    dst_lon = float(conn.get('dst_lon', 0) or 0)

                    self.globe.add_connection(
                        src_lat, src_lon,
                        dst_lat, dst_lon,
                        threat,
                        metadata={
                            'ip': conn.get('dst_ip'),
                            'org': conn.get('dst_org'),
                            'country': country,
                            'port': conn.get('dst_port'),
                            'threat': threat,
                        }
                    )
                except Exception as e:
                    logger.debug(f"Failed to process connection: {e}")

            # Trigger animation update
            self.animation_frame += 1
        except Exception as e:
            logger.warning(f"Globe data watch failed: {e}")

    def watch_animation_frame(self, frame: int) -> None:
        """Animation frame update trigger"""
        self.refresh()

    def render(self):
        """Sophisticated threat visualization with globe, heatmap, and analytics"""
        connections = self.globe_data.get('connections', [])

        # Try to render full globe if available
        if self.globe:
            try:
                # Get globe rendering
                globe_output = self.globe.render_with_overlay()
                return globe_output
            except Exception as e:
                logger.debug(f"Globe render failed: {e}")

        # Sophisticated fallback: Enhanced threat heatmap with multiple metrics
        lines = []
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        lines.append("[bold cyan]🌐 GLOBAL THREAT INTELLIGENCE MAP[/bold cyan]")
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")

        # Geographic threat analysis
        geo_data = {}
        org_types = {}
        threat_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for conn in connections:
            country = (conn.get('dst_country') or 'XX')[:2].upper()
            threat = float(conn.get('threat_score', 0) or 0)
            org_type = (conn.get('dst_org_type') or 'unknown').lower()

            if country not in geo_data:
                geo_data[country] = {'threats': [], 'count': 0, 'types': {}}

            geo_data[country]['threats'].append(threat)
            geo_data[country]['count'] += 1
            geo_data[country]['types'][org_type] = geo_data[country]['types'].get(org_type, 0) + 1

            # Track threat distribution
            if threat >= 0.7:
                threat_stats['critical'] += 1
            elif threat >= 0.5:
                threat_stats['high'] += 1
            elif threat >= 0.3:
                threat_stats['medium'] += 1
            else:
                threat_stats['low'] += 1

        # Top threat regions
        top_regions = sorted(
            [(c, sum(d['threats'])/len(d['threats']), d['count']) for c, d in geo_data.items()],
            key=lambda x: x[1] * x[2],  # Sort by threat * count
            reverse=True
        )[:6]

        lines.append("")
        lines.append("[bold]🔴 CRITICAL THREAT ZONES:[/bold]")
        for country, avg_threat, count in top_regions:
            if avg_threat >= 0.7:
                threat_bar = "[bold red]▓▓▓▓▓▓▓▓▓▓[/bold red]"
                indicator = "[bold red]⚠ CRITICAL[/bold red]"
            elif avg_threat >= 0.5:
                threat_bar = "[bold yellow]▓▓▓▓▓▓░░░░[/bold yellow]"
                indicator = "[bold yellow]⚠ HIGH[/bold yellow]"
            elif avg_threat >= 0.3:
                threat_bar = "[yellow]▓▓▓▓░░░░░░[/yellow]"
                indicator = "[yellow]⚠ MEDIUM[/yellow]"
            else:
                threat_bar = "[green]▓▓░░░░░░░░[/green]"
                indicator = "[green]✓ LOW[/green]"

            lines.append(f"  {country:2s} {threat_bar} {avg_threat:5.2f} (n={count:2d}) {indicator}")

        lines.append("")
        lines.append("[bold]🏢 ORGANIZATION TYPE DISTRIBUTION:[/bold]")

        # Organization type breakdown
        org_summary = {}
        for country, data in geo_data.items():
            for org_type, count in data['types'].items():
                if org_type not in org_summary:
                    org_summary[org_type] = 0
                org_summary[org_type] += count

        type_colors = {
            'cloud': 'bold cyan',
            'cdn': 'cyan',
            'hosting': 'blue',
            'isp': 'magenta',
            'vpn': 'bold magenta',
            'tor': 'bold red',
            'enterprise': 'bold green',
            'government': 'bold blue',
        }

        for org_type, count in sorted(org_summary.items(), key=lambda x: x[1], reverse=True)[:5]:
            color = type_colors.get(org_type, 'white')
            lines.append(f"  [{color}]{org_type:12s}[/{color}] ▰▰▰ {count:3d} connections")

        lines.append("")
        lines.append("[bold]📊 THREAT DISTRIBUTION:[/bold]")
        total = sum(threat_stats.values())
        if total > 0:
            crit_pct = (threat_stats['critical'] / total) * 100
            high_pct = (threat_stats['high'] / total) * 100
            med_pct = (threat_stats['medium'] / total) * 100
            low_pct = (threat_stats['low'] / total) * 100

            lines.append(f"  [bold red]CRITICAL[/bold red]: {threat_stats['critical']:3d} ({crit_pct:5.1f}%) [bold red]{'█' * int(crit_pct/5)}[/bold red]")
            lines.append(f"  [bold yellow]HIGH[/bold yellow]:     {threat_stats['high']:3d} ({high_pct:5.1f}%) [bold yellow]{'█' * int(high_pct/5)}[/bold yellow]")
            lines.append(f"  [yellow]MEDIUM[/yellow]:   {threat_stats['medium']:3d} ({med_pct:5.1f}%) [yellow]{'█' * int(med_pct/5)}[/yellow]")
            lines.append(f"  [green]LOW[/green]:      {threat_stats['low']:3d} ({low_pct:5.1f}%) [green]{'█' * int(low_pct/5)}[/green]")

        lines.append("")
        lines.append(f"[dim]Total Connections: {len(connections)} | Active Regions: {len(geo_data)}[/dim]")
        lines.append("[bold cyan]═══════════════════════════════════════[/bold cyan]")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]🌐 THREAT INTELLIGENCE DASHBOARD[/bold cyan]", border_style="cyan")


class SmartConnectionTable(Static):
    """
    Enhanced connection table for both device and network modes
    Adaptive columns, threat coloring, and enrichment data
    """

    DEFAULT_CSS = """
    SmartConnectionTable {
        height: 100%;
        width: 100%;
        overflow: auto;
    }

    SmartConnectionTable DataTable {
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

        # Columns for comprehensive view
        self.table.add_column("Time", key="time", width=8)
        self.table.add_column("IP", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=5)
        self.table.add_column("Org", key="org", width=18)
        self.table.add_column("Type", key="org_type", width=8)
        self.table.add_column("Risk", key="threat", width=6)
        self.table.add_column("Score", key="score", width=5)
        self.table.add_column("Hops", key="hops", width=4)

        yield self.table

    def watch_connections(self, new_connections: list) -> None:
        """Update table when connections change - text color coded by threat and type"""
        if self.table is None:
            return

        self.connections = new_connections
        self.table.clear()

        # Add rows with text color coding by threat and type
        for conn in self.connections[:50]:  # Limit to 50 for performance
            try:
                time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M:%S")
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()

                # Threat color mapping (text only)
                if threat >= 0.7:
                    threat_color = "bold red"
                    threat_indicator = "●●●"
                elif threat >= 0.5:
                    threat_color = "bold yellow"
                    threat_indicator = "●●○"
                elif threat >= 0.3:
                    threat_color = "yellow"
                    threat_indicator = "●○○"
                else:
                    threat_color = "green"
                    threat_indicator = "○○○"

                # Type color mapping (text only) - based on organization type
                type_colors = {
                    'cloud': 'bold cyan',
                    'cdn': 'cyan',
                    'hosting': 'blue',
                    'isp': 'magenta',
                    'vpn': 'bold magenta',
                    'tor': 'bold red',
                    'enterprise': 'bold green',
                    'government': 'bold blue',
                    'education': 'green',
                    'unknown': 'dim white',
                }
                type_color = type_colors.get(org_type, 'dim white')

                ip = (conn.get('dst_ip') or 'Unknown')[:15]
                port = str(conn.get('dst_port', '-'))
                org = (conn.get('dst_org') or 'Unknown')[:18]
                hops = str(conn.get('hop_count', '-'))

                # Format row with text color coding only (no backgrounds)
                self.table.add_row(
                    f"[dim]{time_str}[/]",
                    f"[cyan]{ip}[/]",
                    f"[magenta]{port}[/]",
                    f"[white]{org}[/]",
                    f"[{type_color}]{org_type:>8}[/]",
                    f"[{threat_color}]{threat_indicator}[/]",
                    f"[{threat_color}]{threat:.2f}[/]",
                    f"[cyan]{hops}[/]",
                    key=str(conn.get('id', ''))
                )
            except Exception as e:
                logger.debug(f"Failed to add row: {e}")


class NetworkTopologyPanel(Static):
    """
    Network mode specific: Device → Destination topology
    Shows which devices are communicating with what destinations
    """

    DEFAULT_CSS = """
    NetworkTopologyPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    topology_data = reactive(dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.flows = {}
        self.topology_data = {}

    def watch_topology_data(self, new_data: dict) -> None:
        """Update topology when data changes"""
        self.flows = new_data
        self.refresh()

    def render(self):
        """Render device→destination topology with ASCII graph"""
        if not self.flows:
            return Panel(
                "[dim]Scanning network topology...[/dim]",
                title="[bold cyan]🌐 NETWORK TOPOLOGY[/bold cyan]",
                border_style="cyan"
            )

        lines = []
        lines.append("[bold cyan]┌─────────────────────────────────────┐[/bold cyan]")
        lines.append("[bold cyan]│ PASSIVELY DISCOVERED DEVICES        │[/bold cyan]")
        lines.append("[bold cyan]└─────────────────────────────────────┘[/bold cyan]")
        lines.append("")

        device_count = len(self.flows)
        lines.append(f"[dim]Total Devices: {device_count}[/dim]")
        lines.append("")

        # Create a topology graph
        lines.append("[bold]LOCAL NETWORK TOPOLOGY:[/bold]")
        lines.append("")
        lines.append("[cyan]┌─ HOME NETWORK (Local)[/cyan]")

        device_list = list(self.flows.items())[:8]  # Top 8 devices

        for idx, (src_mac, flow_data) in enumerate(device_list):
            vendor = (flow_data.get('device_vendor', 'Unknown'))[:16]
            dest_count = len(flow_data.get('destinations', {}))
            threat_score = flow_data.get('threat_avg', 0)

            is_last = idx == len(device_list) - 1

            # Device node
            prefix = "[cyan]└─[/cyan]" if is_last else "[cyan]├─[/cyan]"

            if threat_score >= 0.7:
                threat_icon = "[bold red]⚠[/bold red]"
                threat_color = "bold red"
            elif threat_score >= 0.5:
                threat_icon = "[bold yellow]⚡[/bold yellow]"
                threat_color = "bold yellow"
            elif threat_score >= 0.3:
                threat_icon = "[yellow]△[/yellow]"
                threat_color = "yellow"
            else:
                threat_icon = "[green]✓[/green]"
                threat_color = "green"

            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:16s}[/{threat_color}] → {dest_count} flows")

            # Show connection flows
            destinations = sorted(
                flow_data.get('destinations', {}).items(),
                key=lambda x: float(x[1].get('threat', 0) or 0),
                reverse=True
            )[:2]  # Top 2 destinations per device

            for dest_idx, (dest, data) in enumerate(destinations):
                threat = float(data.get('threat', 0) or 0)
                count = data.get('count', 0)

                is_dest_last = dest_idx == len(destinations) - 1
                flow_prefix = "[cyan]│  └──[/cyan]" if is_dest_last else "[cyan]│  ├──[/cyan]"

                if threat >= 0.7:
                    dest_color = "bold red"
                    dest_icon = "🔴"
                elif threat >= 0.5:
                    dest_color = "bold yellow"
                    dest_icon = "🟡"
                else:
                    dest_color = "green"
                    dest_icon = "🟢"

                # Truncate IP if too long
                dest_str = dest[:18] if len(dest) > 18 else dest

                lines.append(f"{flow_prefix} {dest_icon} [{dest_color}]{dest_str:18s}[/{dest_color}] x{count}")

        lines.append("")
        lines.append("[bold cyan]═════════════════════════════════════[/bold cyan]")

        # Add statistics
        total_flows = sum(len(f.get('destinations', {})) for f in self.flows.values())
        lines.append(f"[dim]Total Flows: {total_flows} | Active Devices: {device_count}[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🌐 NETWORK TOPOLOGY[/bold cyan]",
            border_style="cyan"
        )


class DeviceDiscoveryPanel(Static):
    """
    Device mode specific: Discovered devices on network
    Shows MAC addresses, vendors, and activity summary
    """

    DEFAULT_CSS = """
    DeviceDiscoveryPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    devices = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.devices = []

    def watch_devices(self, new_devices: list) -> None:
        """Update devices when data changes"""
        self.devices = new_devices
        self.refresh()

    def render(self):
        """Render discovered devices with network topology"""
        if not self.devices:
            return Panel(
                "[dim]Scanning for connected devices...[/dim]",
                title="[bold cyan]🔍 DEVICE DISCOVERY[/bold cyan]",
                border_style="cyan"
            )

        lines = []
        lines.append("[bold cyan]┌─────────────────────────────────────┐[/bold cyan]")
        lines.append("[bold cyan]│ PASSIVELY DISCOVERED DEVICES        │[/bold cyan]")
        lines.append("[bold cyan]└─────────────────────────────────────┘[/bold cyan]")
        lines.append("")

        # Sort by threat score
        sorted_devices = sorted(
            self.devices,
            key=lambda d: float(d.get('threat_score', 0) or 0),
            reverse=True
        )[:12]  # Show top 12

        # Add summary
        lines.append(f"[dim]Discovered: {len(self.devices)} device(s)[/dim]")
        lines.append("")
        lines.append("[bold]DEVICE INVENTORY:[/bold]")
        lines.append("")

        # Build network tree
        lines.append("[cyan]┌─ LOCAL NETWORK[/cyan]")

        for idx, device in enumerate(sorted_devices):
            mac = device.get('mac', 'Unknown')[:17]
            vendor = (device.get('vendor') or 'Unknown')[:16]
            threat = float(device.get('threat_score', 0) or 0)
            conn_count = device.get('connection_count', 0)

            is_last = idx == len(sorted_devices) - 1
            prefix = "[cyan]└─[/cyan]" if is_last else "[cyan]├─[/cyan]"

            # Threat indicator with color
            if threat >= 0.7:
                threat_icon = "[bold red]⚠[/bold red]"
                threat_color = "bold red"
                threat_label = "CRITICAL"
            elif threat >= 0.5:
                threat_icon = "[bold yellow]⚡[/bold yellow]"
                threat_color = "bold yellow"
                threat_label = "HIGH"
            elif threat >= 0.3:
                threat_icon = "[yellow]△[/yellow]"
                threat_color = "yellow"
                threat_label = "MEDIUM"
            else:
                threat_icon = "[green]✓[/green]"
                threat_color = "green"
                threat_label = "LOW"

            lines.append(f"{prefix} {threat_icon} [{threat_color}]{vendor:16s}[/{threat_color}] [{threat_label:8s}] {conn_count} flows")
            lines.append(f"[dim]   └─ MAC: {mac}[/dim]")

        lines.append("")
        lines.append("[bold cyan]═════════════════════════════════════[/bold cyan]")

        # Statistics
        total_connections = sum(d.get('connection_count', 0) for d in self.devices)
        high_threat_devices = len([d for d in self.devices if float(d.get('threat_score', 0) or 0) >= 0.5])

        lines.append("")
        lines.append("[bold]NETWORK STATISTICS:[/bold]")
        lines.append(f"  [cyan]Devices:[/cyan] {len(self.devices)}")
        lines.append(f"  [cyan]Total Flows:[/cyan] {total_connections}")
        lines.append(f"  [bold yellow]High Risk:[/bold yellow] {high_threat_devices}")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🔍 DEVICE DISCOVERY[/bold cyan]",
            border_style="cyan"
        )


class CobaltGraphDashboardEnhanced(UnifiedDashboard):
    """
    Enhanced unified dashboard with mode support (device/network)
    4-cell grid layout (2x2) combining best components

    Grid Layout:
    ┌──────────────────────────────────┬──────────────────────────────────┐
    │ Top-Left (50%):                  │ Top-Right (50%):                 │
    │ Threat Posture + Stats           │ Threat Globe (ASCII)             │
    │                                  │ Heatmaps + Connection Trails     │
    ├──────────────────────────────────┼──────────────────────────────────┤
    │ Bottom-Left (50%):               │ Bottom-Right (50%):              │
    │ Connection Table (PRIMARY)       │ Mode-Specific Panel              │
    │ Full enrichment data             │ Device Discovery / Network Topo  │
    └──────────────────────────────────┴──────────────────────────────────┘

    Modes:
    - device: Personal device security focus
    - network: Network-wide topology and threat monitoring
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("?", "help", "Help"),
    ]

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
        height: 1;
    }

    #main_grid {
        height: 1fr;
        layout: vertical;
    }

    #top_row {
        height: 50%;
        layout: horizontal;
    }

    #bottom_row {
        height: 50%;
        layout: horizontal;
    }

    #top_left {
        width: 50%;
        padding: 0 1 0 0;
    }

    #top_right {
        width: 50%;
        padding: 0 0 0 1;
    }

    #bottom_left {
        width: 50%;
        padding: 1 1 0 0;
    }

    #bottom_right {
        width: 50%;
        padding: 1 0 0 1;
    }
    """

    def __init__(self, db_path: str = "data/cobaltgraph.db", mode: str = "device"):
        """Initialize enhanced dashboard with mode"""
        super().__init__(db_path=db_path, mode=mode)
        self.title = f"CobaltGraph - {mode.upper()} Mode"
        self.sub_title = "Loading..."

        # Panels
        self.threat_posture_panel = None
        self.globe_panel = None
        self.connection_table = None
        self.mode_specific_panel = None

    def compose(self) -> ComposeResult:
        """4-cell grid layout with mode-aware content"""
        yield Header()

        with Vertical(id="main_grid"):
            # Top row: Threat Posture (left) + Globe (right)
            with Horizontal(id="top_row"):
                self.threat_posture_panel = ThreatPostureQuickPanel(id="top_left")
                yield self.threat_posture_panel

                self.globe_panel = EnhancedThreatGlobePanel(id="top_right")
                yield self.globe_panel

            # Bottom row: Connection Table (left) + Mode-specific (right)
            with Horizontal(id="bottom_row"):
                self.connection_table = SmartConnectionTable(id="bottom_left")
                yield self.connection_table

                # Mode-specific panel
                if self.mode == "network":
                    self.mode_specific_panel = NetworkTopologyPanel(id="bottom_right")
                else:
                    self.mode_specific_panel = DeviceDiscoveryPanel(id="bottom_right")

                yield self.mode_specific_panel

        yield Footer()

    def action_refresh(self) -> None:
        """Manual refresh action"""
        self._refresh_data()

    def on_mount(self) -> None:
        """Initialize dashboard on mount"""
        self.title = f"CobaltGraph Enhanced - {self.mode.upper()} Mode"

        if self.data_manager.connect():
            self.is_connected = True
            self.set_interval(2.0, self._refresh_data)
            self.set_interval(0.1, self._update_display)  # 100ms for smooth animations
            self._refresh_data()
        else:
            self.sub_title = "Database connection failed"

    def _refresh_data(self) -> None:
        """Refresh data from database"""
        try:
            if not self.data_manager.is_connected:
                return

            # Get connections
            connections = self.data_manager.get_connections(limit=100)
            self.recent_connections = deque(connections, maxlen=100)

            # Calculate threat statistics
            threat_scores = [float(c.get('threat_score', 0) or 0) for c in connections]
            current_threat = (sum(threat_scores) / len(threat_scores)) if threat_scores else 0
            high_threat_count = sum(1 for t in threat_scores if t >= 0.7)

            # Update threat posture panel
            if self.threat_posture_panel:
                self.threat_posture_panel.threat_data = {
                    'current_threat': current_threat,
                    'baseline_threat': 0.2,  # Default baseline
                    'active_threats': high_threat_count,
                    'monitored_ips': len(set(c.get('dst_ip') for c in connections)),
                    'high_threat_count': high_threat_count,
                }

            # Update connection table
            if self.connection_table:
                self.connection_table.connections = connections

            # Update globe with new connections
            if self.globe_panel:
                self.globe_panel.globe_data = {
                    'connections': connections,
                    'heatmap': self._calculate_heatmap(connections),
                }

            # Mode-specific updates
            if self.mode == "network":
                devices = self.data_manager.get_devices() if hasattr(self.data_manager, 'get_devices') else []
                if self.mode_specific_panel and isinstance(self.mode_specific_panel, NetworkTopologyPanel):
                    self.mode_specific_panel.topology_data = self._build_topology(connections, devices)
            else:
                devices = self.data_manager.get_devices() if hasattr(self.data_manager, 'get_devices') else []
                if self.mode_specific_panel and isinstance(self.mode_specific_panel, DeviceDiscoveryPanel):
                    self.mode_specific_panel.devices = devices

            # Update stats
            stats = self.data_manager.get_stats()
            self.sub_title = f"Updated: {datetime.now().strftime('%H:%M:%S')} | Connections: {stats.get('total', 0)} | Risk: {current_threat:.2f}"

        except Exception as e:
            logger.error(f"Refresh failed: {e}")
            self.sub_title = f"Error: {str(e)[:30]}"

    def _update_display(self) -> None:
        """Quick display updates (animations, etc)"""
        # Update globe animation
        if self.globe_panel:
            try:
                if self.globe_panel.globe:
                    self.globe_panel.globe.update(0.05)  # Update every 50ms
                    self.globe_panel.refresh()  # Force re-render
            except Exception as e:
                logger.debug(f"Globe update failed: {e}")

    def _calculate_heatmap(self, connections: List[Dict]) -> Dict:
        """Calculate geographic heatmap from connections"""
        heatmap = defaultdict(float)
        for conn in connections:
            lat = conn.get('dst_lat')
            lon = conn.get('dst_lon')
            threat = float(conn.get('threat_score', 0) or 0)

            if lat and lon:
                key = (round(lat, 0), round(lon, 0))
                heatmap[key] += threat

        return dict(heatmap)

    def _build_topology(self, connections: List[Dict], devices: List[Dict]) -> Dict:
        """Build device→destination topology"""
        topology = defaultdict(lambda: {
            'device_vendor': 'Unknown',
            'destinations': defaultdict(lambda: {
                'count': 0,
                'threat': 0.0,
                'org': 'Unknown'
            })
        })

        device_map = {d.get('mac', ''): d for d in devices}

        for conn in connections:
            src_mac = conn.get('src_mac', 'Unknown')
            dst_ip = conn.get('dst_ip', 'Unknown')
            dst_port = conn.get('dst_port', '-')
            threat = float(conn.get('threat_score', 0) or 0)
            org = (conn.get('dst_org') or 'Unknown')[:15]

            if src_mac in device_map:
                topology[src_mac]['device_vendor'] = device_map[src_mac].get('vendor', 'Unknown')

            key = f"{dst_ip}:{dst_port}"
            topology[src_mac]['destinations'][key]['count'] += 1
            topology[src_mac]['destinations'][key]['threat'] = max(
                topology[src_mac]['destinations'][key]['threat'], threat
            )
            topology[src_mac]['destinations'][key]['org'] = org

        return dict(topology)

    def action_refresh(self) -> None:
        """Manual refresh action"""
        self._refresh_data()

    def action_quit(self) -> None:
        """Quit application"""
        self.exit()

    def action_help(self) -> None:
        """Show help (could implement as modal)"""
        self.sub_title = "Press Q to quit, R to refresh, D for devices, T for topology"

    def action_toggle_devices(self) -> None:
        """Toggle devices panel visibility"""
        if self.devices_panel:
            self.devices_panel.visible = not self.devices_panel.visible

    def action_toggle_topology(self) -> None:
        """Toggle topology panel visibility"""
        if self.topology_panel:
            self.topology_panel.visible = not self.topology_panel.visible


if __name__ == '__main__':
    import sys

    mode = "device"
    db_path = "data/cobaltgraph.db"

    if len(sys.argv) > 1:
        mode = sys.argv[1]

    dashboard = CobaltGraphDashboardEnhanced(db_path=db_path, mode=mode)
    dashboard.run()
