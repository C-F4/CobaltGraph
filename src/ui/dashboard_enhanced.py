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
    Bottom-right (30%): ASCII Globe with advanced rendering
    Integrates ascii_globe.py for superior visualization

    Features:
    - Braille-character rendering for high resolution
    - Threat heatmaps by geographic region
    - Animated connection ping trails
    - Real-time metadata overlay (rotation, stats, threats)
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

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.globe = None
        self.globe_data = {
            'connections': [],
            'heatmap': {},
            'stats': {},
        }

        # Initialize ASCII globe if available
        if ASCIIGlobe:
            try:
                # Calculate dimensions from terminal (will be refined on mount)
                self.globe = ASCIIGlobe(width=40, height=20)
                self.globe.state.rotation_x = 23.5  # Earth's axial tilt
            except Exception as e:
                logger.warning(f"Failed to initialize ASCIIGlobe: {e}")
                self.globe = None

    def watch_globe_data(self, new_data: dict) -> None:
        """Update globe when data changes"""
        if self.globe is None:
            return

        try:
            # Add connections to globe
            connections = new_data.get('connections', [])
            for conn in connections[-10:]:  # Last 10 connections only
                try:
                    src_lat, src_lon = 39.8283, -98.5795  # US center
                    dst_lat = float(conn.get('dst_lat', 0) or 0)
                    dst_lon = float(conn.get('dst_lon', 0) or 0)
                    threat = float(conn.get('threat_score', 0) or 0)

                    self.globe.add_connection(
                        src_lat, src_lon,
                        dst_lat, dst_lon,
                        threat,
                        metadata={
                            'ip': conn.get('dst_ip'),
                            'org': conn.get('dst_org'),
                            'country': conn.get('dst_country'),
                            'port': conn.get('dst_port'),
                        }
                    )
                except Exception as e:
                    logger.debug(f"Failed to add connection to globe: {e}")

            self.refresh()
        except Exception as e:
            logger.warning(f"Globe data watch failed: {e}")

    def render(self):
        """Render the globe with overlay"""
        if self.globe is None:
            # Fallback to simple heatmap if globe unavailable
            connections = self.globe_data.get('connections', [])

            # Extract geographic data
            geo_threats = {}
            for conn in connections:
                country = (conn.get('dst_country') or 'XX')[:2].upper()
                threat = float(conn.get('threat_score', 0) or 0)
                if country not in geo_threats:
                    geo_threats[country] = []
                geo_threats[country].append(threat)

            # Top regions
            top_regions = sorted(
                [(c, sum(t)/len(t), len(t)) for c, t in geo_threats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:8]

            content = "[bold cyan]◐ World Threat Map[/bold cyan]\n\n"

            for country, avg_threat, count in top_regions:
                if avg_threat >= 0.7:
                    bar = "[bold red]████████[/bold red]"
                elif avg_threat >= 0.5:
                    bar = "[bold yellow]██████░░[/bold yellow]"
                elif avg_threat >= 0.3:
                    bar = "[yellow]████░░░░[/yellow]"
                else:
                    bar = "[green]██░░░░░░[/green]"

                content += f"{country} {bar} {avg_threat:.2f}\n"

            if not top_regions:
                content += "[dim]Loading geographic data...[/dim]\n"

            content += f"\n[cyan]Total:[/cyan] {len(connections)}"
            return Panel(content, title="[bold cyan]Threat Map[/bold cyan]")

        # Use full globe rendering
        try:
            return self.globe.render_with_overlay()
        except Exception as e:
            logger.error(f"Globe render failed: {e}")
            return Panel(f"[red]Globe Error: {e}[/red]", title="[bold cyan]Threat Map[/bold cyan]")


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
        self.table.add_column("Risk", key="threat", width=4)
        self.table.add_column("Hops", key="hops", width=4)

        yield self.table

    def watch_connections(self, new_connections: list) -> None:
        """Update table when connections change"""
        if self.table is None:
            return

        self.connections = new_connections
        self.table.clear()

        if len(self.connections) > 0:
            logger.debug(f"Updating connection table with {len(self.connections)} connections")
            sample = self.connections[0]
            logger.debug(f"Sample connection keys: {list(sample.keys()) if isinstance(sample, dict) else 'not a dict'}")
            logger.debug(f"Sample threat_score: {sample.get('threat_score', 'N/A') if isinstance(sample, dict) else 'N/A'}")

        # Add rows with color coding
        for conn in self.connections[:50]:  # Limit to 50 for performance
            try:
                time_str = datetime.fromtimestamp(conn.get('timestamp', 0)).strftime("%H:%M:%S")
                ip = (conn.get('dst_ip') or 'Unknown')[:15]
                port = str(conn.get('dst_port', '-'))
                org = (conn.get('dst_org') or 'Unknown')[:18]
                org_type = (conn.get('dst_org_type') or 'unknown')[:8]
                threat = float(conn.get('threat_score', 0) or 0)
                hops = str(conn.get('hop_count', '-'))

                # Color coding by threat level
                if threat >= 0.7:
                    threat_style = "bold red"
                    threat_label = "●●●"
                elif threat >= 0.5:
                    threat_style = "bold yellow"
                    threat_label = "●●○"
                elif threat >= 0.3:
                    threat_style = "yellow"
                    threat_label = "●○○"
                else:
                    threat_style = "green"
                    threat_label = "○○○"

                self.table.add_row(
                    time_str,
                    ip,
                    port,
                    org,
                    org_type,
                    threat_label,
                    hops,
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
        """Render device→destination topology"""
        if not self.flows:
            return Panel(
                "[dim]No topology data available[/dim]",
                title="[bold cyan]Network Topology[/bold cyan]"
            )

        content = ""
        device_count = len(self.flows)

        for src_mac, flow_data in list(self.flows.items())[:10]:  # Limit to 10 devices
            vendor = flow_data.get('device_vendor', 'Unknown')
            dest_count = len(flow_data.get('destinations', {}))

            if dest_count == 0:
                continue

            content += f"[cyan]{vendor}[/cyan] → {dest_count} destinations\n"

            # Show top destinations
            destinations = sorted(
                flow_data.get('destinations', {}).items(),
                key=lambda x: x[1].get('threat', 0),
                reverse=True
            )[:3]

            for dest, data in destinations:
                threat = data.get('threat', 0)
                count = data.get('count', 0)

                if threat >= 0.7:
                    threat_style = "[bold red]"
                elif threat >= 0.5:
                    threat_style = "[bold yellow]"
                else:
                    threat_style = "[green]"

                content += f"  └─ {threat_style}{dest}[/] ({count})\n"

        return Panel(
            content,
            title="[bold cyan]Network Topology[/bold cyan]",
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
        """Render discovered devices"""
        if not self.devices:
            return Panel(
                "[dim]No devices discovered[/dim]",
                title="[bold cyan]Discovered Devices[/bold cyan]"
            )

        content = ""

        # Sort by threat score
        sorted_devices = sorted(
            self.devices,
            key=lambda d: float(d.get('threat_score', 0) or 0),
            reverse=True
        )[:15]  # Show top 15

        for device in sorted_devices:
            mac = device.get('mac', 'Unknown')[:17]
            vendor = (device.get('vendor') or 'Unknown')[:20]
            threat = float(device.get('threat_score', 0) or 0)
            conn_count = device.get('connection_count', 0)

            if threat >= 0.7:
                indicator = "[bold red]●[/bold red]"
            elif threat >= 0.5:
                indicator = "[bold yellow]●[/bold yellow]"
            elif threat >= 0.3:
                indicator = "[yellow]●[/yellow]"
            else:
                indicator = "[green]●[/green]"

            content += f"{indicator} {mac} [{vendor[:12]}] {conn_count} conns\n"

        return Panel(
            content,
            title="[bold cyan]Discovered Devices[/bold cyan]",
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
            self.set_interval(0.5, self._update_display)
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
        if self.globe_panel and self.globe_panel.globe:
            try:
                self.globe_panel.globe.update(0.1)
            except Exception:
                pass

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
