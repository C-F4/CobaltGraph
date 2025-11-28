#!/usr/bin/env python3
"""
CobaltGraph Network Mode Dashboard
Network topology focused - "What's happening on my network?"

Layout:
┌─────────────────────────┬─────────────────────┬──────────────────┐
│ Network Topology Panel  │ Connection Table    │ Lightweight Globe│
│ (Device→Dest Flow)      │ (30%)               │ (ASCII Textures) │
│ (20%)                   │                     │ (20%)            │
│                         │ Time|SrcMAC|Vendor  ├──────────────────┤
│ [Device] → [Dest IPs]   │ DstIP|Port|Score    │ Device Discovery │
│ AA:BB:CC (Apple)        │ Org|Hops|OS         │ Panel (15%)      │
│   ├─► 142.250.80.46:443 │                     │                  │
│   ├─► 8.8.8.8:53        │ Aggregated view:    │ MAC | Vendor     │
│   └─► 1.1.1.1:443       │ Group by dest IP    │ IP  | Threats    │
│                         │ Show device+count   │ Count| Score     │
├─────────────────────────┤                     │                  │
│ Threat Posture Panel    │ [D]evices [T]opo    │ [G]lobe toggle   │
│ (Network-wide) (20%)    │ [F]ilter [E]xport   ├──────────────────┤
│                         │                     │ Org Intelligence │
│ Network Threat: 0.45    │ Shows passive       │ Panel (15%)      │
│ 24h Baseline: 0.38      │ fingerprinting:     │                  │
│ Devices: 12             │ - MAC vendor        │ Risk matrix      │
│ High-Threat: 3          │ - OS detection      │ (Threat vs Trust)│
│                         │ - Hop count         │                  │
└─────────────────────────┴─────────────────────┴──────────────────┘

Features:
- Network topology panel shows device→destination flows
- Device discovery panel shows MAC vendor and OS fingerprinting
- Lightweight globe with ASCII textures
- Full passive fingerprinting display
"""

import logging
import json
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict

from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, DataTable, Static

try:
    from src.ui.base_dashboard import NetworkDashboardBase
except ImportError:
    from base_dashboard import NetworkDashboardBase

try:
    from src.ui.viz_engine import ThreatGlobe
except ImportError:
    ThreatGlobe = None

logger = logging.getLogger(__name__)


class NetworkTopologyPanel(Static):
    """
    Device→Destination flow visualization
    Shows which devices are talking to what destinations
    """

    DEFAULT_CSS = """
    NetworkTopologyPanel {
        border: solid $primary;
        height: 1fr;
        width: 20%;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.flows: Dict = {}

    def update_flows(self, connections: List[Dict], devices: List[Dict]) -> None:
        """Update topology from connections and devices"""
        self.flows = defaultdict(lambda: {
            'device_vendor': 'Unknown',
            'destinations': defaultdict(lambda: {
                'count': 0,
                'threat': 0.0,
                'org': 'Unknown'
            })
        })

        # Build device map
        device_map = {}
        for device in devices:
            mac = device.get('mac', '')
            device_map[mac] = {
                'vendor': device.get('vendor', 'Unknown'),
                'threat': float(device.get('threat_score', 0) or 0),
            }

        # Build flows from connections
        for conn in connections:
            src_mac = (conn.get('src_mac') or 'Unknown')
            dst_ip = (conn.get('dst_ip') or 'Unknown')
            dst_port = conn.get('dst_port', '-')
            threat = float(conn.get('threat_score', 0) or 0)
            org = (conn.get('dst_org') or 'Unknown')[:15]

            if src_mac in device_map:
                self.flows[src_mac]['device_vendor'] = device_map[src_mac]['vendor']

            key = f"{dst_ip}:{dst_port}"
            self.flows[src_mac]['destinations'][key]['count'] += 1
            self.flows[src_mac]['destinations'][key]['threat'] = max(
                self.flows[src_mac]['destinations'][key]['threat'], threat
            )
            self.flows[src_mac]['destinations'][key]['org'] = org

    def render(self) -> Panel:
        """Render topology visualization"""
        lines = []

        if not self.flows:
            return Panel("No network topology data", title="Network Topology")

        for mac, flow in list(self.flows.items())[:5]:  # Limit to top 5 devices
            vendor = flow.get('device_vendor', 'Unknown')
            lines.append(f"[bold cyan]{mac[:8]}[/bold cyan] ({vendor})")

            destinations = flow.get('destinations', {})
            for dest_key, dest_info in list(destinations.items())[:3]:  # Top 3 destinations per device
                count = dest_info['count']
                threat = dest_info['threat']
                org = dest_info['org'][:12]

                # Color code by threat
                if threat >= 0.7:
                    color = "bold red"
                elif threat >= 0.5:
                    color = "bold yellow"
                else:
                    color = "green"

                threat_str = f"{threat:.2f}"
                lines.append(f"  ├─► [dim]{dest_key}[/dim] ({org}) [{count}] [{color}]{threat_str}[/{color}]")

            lines.append("")

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Network Topology[/bold cyan]", border_style="cyan")


class DeviceDiscoveryPanel(Static):
    """
    Active device registry with passive fingerprinting
    Shows MAC, vendor, IP, connection count, threat score, OS
    """

    DEFAULT_CSS = """
    DeviceDiscoveryPanel {
        border: solid $primary;
        height: 1fr;
        width: 15%;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.devices: List[Dict] = []

    def update_devices(self, devices: List[Dict]) -> None:
        """Update device list"""
        self.devices = devices

    def render(self) -> Panel:
        """Render device discovery panel"""
        lines = []

        if not self.devices:
            return Panel("No devices discovered", title="Device Discovery")

        # Header
        lines.append("[bold]MAC Address       Vendor        IPs     Conns  Threat[/bold]")
        lines.append("─" * 50)

        for device in self.devices[:10]:  # Show top 10 devices
            mac = device.get('mac', 'Unknown')[:17]
            vendor = device.get('vendor', 'Unknown')[:13]
            ips_raw = device.get('ip_addresses', '[]')

            # Parse IP addresses
            try:
                if isinstance(ips_raw, str):
                    ips = json.loads(ips_raw)
                else:
                    ips = ips_raw if isinstance(ips_raw, list) else []
            except:
                ips = []

            ip_str = ','.join(ips[:1]) if ips else '-'
            conns = device.get('connection_count', 0) or 0
            threat = float(device.get('threat_score', 0) or 0)

            # Color code threat
            if threat >= 0.7:
                color = "bold red"
            elif threat >= 0.5:
                color = "bold yellow"
            else:
                color = "green"

            threat_str = f"{threat:.2f}"
            lines.append(
                f"{mac} {vendor} {ip_str:15} {conns:5d}  "
                f"[{color}]{threat_str}[/{color}]"
            )

        content = "\n".join(lines)
        return Panel(content, title="[bold cyan]Device Discovery[/bold cyan]", border_style="cyan")


class ConnectionTableNetwork(Static):
    """
    Connection table for network mode
    Aggregated view showing connections with source device
    """

    DEFAULT_CSS = """
    ConnectionTableNetwork {
        border: solid $primary;
        height: 1fr;
        width: 30%;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.table = DataTable(id="network_connections")

    def compose(self) -> ComposeResult:
        """Create data table"""
        # Add columns
        self.table.add_column("Time", key="time", width=10)
        self.table.add_column("SrcMAC", key="src_mac", width=12)
        self.table.add_column("Vendor", key="vendor", width=10)
        self.table.add_column("Dst IP", key="dst_ip", width=15)
        self.table.add_column("Port", key="port", width=6)
        self.table.add_column("Threat", key="threat", width=8)
        self.table.add_column("Org", key="org", width=15)
        self.table.add_column("Hops", key="hops", width=5)
        self.table.add_column("OS", key="os", width=12)

        yield self.table

    def update_connections(self, connections: List[Dict]) -> None:
        """Update connection table"""
        self.table.clear()

        for conn in connections[:50]:  # Show recent 50
            # Format timestamp
            timestamp = conn.get('timestamp', 0)
            if isinstance(timestamp, (int, float)):
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = str(timestamp)[:8]

            src_mac = (conn.get('src_mac') or 'Unknown')[:12]
            vendor = (conn.get('device_vendor') or '-')[:10]
            dst_ip = (conn.get('dst_ip') or 'Unknown')
            port = str(conn.get('dst_port', '-'))

            threat_score = float(conn.get('threat_score', 0) or 0)
            threat_str = f"{threat_score:.2f}"

            org = (conn.get('dst_org') or 'Unknown')[:15]
            hops = str(conn.get('hop_count', '-'))
            os_fp = (conn.get('os_fingerprint') or '-')[:12]

            # Determine row style
            if threat_score >= 0.7:
                style = "bold red"
            elif threat_score >= 0.5:
                style = "bold yellow"
            else:
                style = "green"

            self.table.add_row(
                time_str,
                src_mac,
                vendor,
                dst_ip,
                port,
                threat_str,
                org,
                hops,
                os_fp,
                key=f"conn_{id(conn)}",
                label=Text(f"{dst_ip}", style=style)
            )



class NetworkThreatGlobePanel(Static):
    """
    Threat Globe Visualization for Network Mode
    Shows real-time geographic threat mapping with spinning animation
    """

    DEFAULT_CSS = """
    NetworkThreatGlobePanel {
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
                title="[bold cyan]Network Threat Globe[/bold cyan]",
                border_style="cyan"
            )

        try:
            if self.globe is None:
                self.globe = ThreatGlobe(width=50, height=12)
            return self.globe.render()
        except Exception as e:
            logger.debug(f"Globe render error: {e}")
            return Panel(
                f"[red]Globe initialization: {str(e)[:50]}[/red]",
                title="[bold cyan]Network Threat Globe[/bold cyan]",
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


class NetworkThreatPosturePanel(Static):
    """
    Network-Wide Threat Posture Status Panel
    Shows aggregate threat assessment across all devices
    """

    DEFAULT_CSS = """
    NetworkThreatPosturePanel {
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
        """Render network threat posture information"""
        current = self.threat_data.get('current_threat', 0)
        baseline = self.threat_data.get('baseline_threat', 0)
        active_threats = self.threat_data.get('active_threats', 0)
        monitored_ips = self.threat_data.get('monitored_ips', 0)
        anomaly_count = self.threat_data.get('anomaly_count', 0)

        # Color based on threat level
        if current >= 0.7:
            current_style = "[bold red]"
        elif current >= 0.3:
            current_style = "[bold yellow]"
        else:
            current_style = "[green]"

        content = f"""{current_style}Network Threat[/]
{current:.2f} ({(current*100):.0f}%)

[cyan]24h Baseline[/]
{baseline:.2f}

[red]Active Threats[/]
{active_threats}

[magenta]Monitored IPs[/]
{monitored_ips}

[yellow]Anomalies[/]
{anomaly_count}
"""

        return Panel(
            content,
            title="[bold cyan]Network Status[/bold cyan]",
            border_style="cyan"
        )


class NetworkTrendsPanel(Static):
    """
    Network Threat Trends Visualization
    Shows 60-minute threat score history across network
    """

    DEFAULT_CSS = """
    NetworkTrendsPanel {
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
            title="[bold green]60-Min Network Trends[/bold green]",
            border_style="green"
        )

    def update_history(self, threat_score: float) -> None:
        """Add new threat score to history"""
        self.history.append(threat_score)


class SimpleOrgPanel(Static):
    """Organization intelligence with top organizations"""

    DEFAULT_CSS = """
    SimpleOrgPanel {
        height: 100%;
        width: 100%;
        border: solid $accent;
        padding: 1;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.org_data = {}

    def render(self):
        """Render organization intelligence"""
        org_dict = self.org_data.get('organizations', {})

        if not org_dict:
            return Panel(
                "[dim]No organization data[/dim]",
                title="[bold magenta]Organization Intel[/bold magenta]",
                border_style="magenta"
            )

        lines = []
        # Sort by connection count
        sorted_orgs = sorted(
            org_dict.items(),
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )

        for org_name, org_info in sorted_orgs[:5]:  # Top 5 orgs
            count = org_info.get('count', 0)
            threat_avg = org_info.get('threat_sum', 0) / max(count, 1)
            trust = org_info.get('trust_sum', 0) / max(count, 1)

            # Color by threat
            if threat_avg >= 0.7:
                color = "bold red"
            elif threat_avg >= 0.3:
                color = "bold yellow"
            else:
                color = "green"

            org_short = org_name[:20] if org_name else "Unknown"
            lines.append(f"[{color}]{org_short}[/{color}] ({count}x) {threat_avg:.2f}")

        content = "\n".join(lines) if lines else "[dim]No organizations[/dim]"
        return Panel(
            content,
            title="[bold magenta]Top Organizations[/bold magenta]",
            border_style="magenta"
        )


class NetworkDashboard(NetworkDashboardBase):
    """
    Network Mode Dashboard
    Network topology focused - "What's happening on my network?"
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
        height: 35%;
        width: 1fr;
    }

    #globe_container {
        width: 60%;
        height: 100%;
    }

    #top_right {
        width: 40%;
        height: 100%;
        layout: vertical;
    }

    #threat_container {
        height: 50%;
        width: 100%;
    }

    #trends_container {
        height: 50%;
        width: 100%;
    }

    #bottom_section {
        layout: horizontal;
        height: 65%;
        width: 1fr;
    }

    #left_panels {
        width: 25%;
        height: 100%;
        layout: vertical;
    }

    #topology_panel {
        height: 50%;
        width: 100%;
    }

    #org_panel {
        height: 50%;
        width: 100%;
    }

    #center_panel {
        width: 35%;
        height: 100%;
    }

    #right_panels {
        width: 40%;
        height: 100%;
        layout: vertical;
    }

    #devices_section {
        height: 100%;
        width: 100%;
    }
    """

    def __init__(self, db_path: str = "data/cobaltgraph.db", pipeline=None, **kwargs):
        super().__init__(db_path=db_path, pipeline=pipeline)
        self.threat_globe = None
        self.threat_posture_panel = None
        self.trends_panel = None
        self.topology_panel = None
        self.connection_table = None
        self.devices_panel = None
        self.org_panel = None
        self.threat_history = deque(maxlen=60)  # 60-minute trend

    def compose(self) -> ComposeResult:
        """Create optimized network mode layout with globe and threat visualization"""
        yield Header()

        with Container(id="main_content"):
            # Top section: ThreatGlobe (60%) + Threat Status (40%)
            with Horizontal(id="top_section"):
                self.threat_globe = NetworkThreatGlobePanel(id="globe_container")
                yield self.threat_globe

                with Vertical(id="top_right"):
                    self.threat_posture_panel = NetworkThreatPosturePanel(id="threat_container")
                    yield self.threat_posture_panel

                    self.trends_panel = NetworkTrendsPanel(id="trends_container")
                    yield self.trends_panel

            # Bottom section: Topology + Connections + Devices
            with Horizontal(id="bottom_section"):
                # Left: Topology + Organization (25%)
                with Vertical(id="left_panels"):
                    self.topology_panel = NetworkTopologyPanel(id="topology_panel")
                    yield self.topology_panel

                    self.org_panel = SimpleOrgPanel(id="org_panel")
                    yield self.org_panel

                # Center: Connection Table (35%)
                self.connection_table = ConnectionTableNetwork(id="center_panel")
                yield self.connection_table

                # Right: Device Discovery (40%)
                with Vertical(id="right_panels"):
                    self.devices_panel = DeviceDiscoveryPanel(id="devices_section")
                    yield self.devices_panel

        yield Footer()

    def on_mount(self) -> None:
        """Initialize after mount"""
        super().on_mount()
        self.title = "CobaltGraph - Network Mode (Network Topology)"

        # Set initial data
        self._update_panels()

    def _refresh_data(self) -> None:
        """Refresh data from database"""
        super()._refresh_data()
        self._update_panels()

    def _update_panels(self) -> None:
        """Update all dashboard panels"""
        if not self.is_connected:
            return

        # Update connection table
        if self.connection_table and self._connection_cache:
            self.connection_table.update_connections(self._connection_cache)

        # Update threat globe with connection data
        if self.threat_globe and self._connection_cache:
            self.threat_globe.update_with_connections(self._connection_cache)

        # Update network topology
        if self.topology_panel:
            self.topology_panel.update_flows(
                self._connection_cache,
                self._device_cache
            )

        # Update device discovery
        if self.devices_panel and self._device_cache:
            self.devices_panel.update_devices(self._device_cache)

        # Calculate threat posture data
        threat_data = self._calculate_threat_posture()

        # Update threat posture panel
        if self.threat_posture_panel:
            self.threat_posture_panel.threat_data = threat_data

        # Update trends panel
        if self.trends_panel and self.threat_history:
            for threat in list(self.threat_history)[-1:]:
                self.trends_panel.update_history(threat)

        # Update organization intelligence
        org_data = self._calculate_organization_data()
        if self.org_panel:
            self.org_panel.org_data = org_data

    def _calculate_threat_posture(self) -> Dict:
        """Calculate network-wide threat posture"""
        if not self._connection_cache:
            return {
                'current_threat': 0.0,
                'baseline_threat': 0.0,
                'active_threats': 0,
                'monitored_ips': 0,
                'anomaly_count': 0,
            }

        # Current threat = average of recent connections
        recent_threats = [
            float(conn.get('threat_score', 0) or 0)
            for conn in self._connection_cache[:20]
        ]
        current_threat = sum(recent_threats) / len(recent_threats) if recent_threats else 0

        # Baseline threat = average of all connections
        all_threats = [
            float(conn.get('threat_score', 0) or 0)
            for conn in self._connection_cache
        ]
        baseline_threat = sum(all_threats) / len(all_threats) if all_threats else 0

        # Active threats
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

    def _calculate_organization_data(self) -> Dict:
        """Calculate organization intelligence"""
        org_stats = defaultdict(lambda: {
            'count': 0,
            'threat_sum': 0.0,
            'threat_max': 0.0,
            'trust_sum': 0.0,
        })

        for conn in self._connection_cache:
            org = conn.get('dst_org', 'Unknown')
            org_stats[org]['count'] += 1
            threat = float(conn.get('threat_score', 0) or 0)
            trust = float(conn.get('org_trust_score', 0) or 0.5)

            org_stats[org]['threat_sum'] += threat
            org_stats[org]['threat_max'] = max(org_stats[org]['threat_max'], threat)
            org_stats[org]['trust_sum'] += trust

        return {
            'organizations': dict(org_stats),
            'total_orgs': len(org_stats),
        }

    def action_devices(self) -> None:
        """Toggle device panel visibility"""
        logger.info("Devices action triggered")

    def action_topology(self) -> None:
        """Toggle topology panel visibility"""
        logger.info("Topology action triggered")

    def action_globe(self) -> None:
        """Toggle globe visibility"""
        logger.info("Globe action triggered")

    def action_filter(self) -> None:
        """Open filter dialog"""
        logger.info("Filter action triggered")

    def action_fingerprinting(self) -> None:
        """Show fingerprinting stats"""
        logger.info("Fingerprinting action triggered")

    def _on_live_connection(self, conn_dict: Dict) -> None:
        """Handle live connection events from pipeline"""
        # Track threat history for trends
        threat = conn_dict.get('threat_score', 0) or 0
        self.threat_history.append(threat)

        # Update panels with live data
        self._update_panels()

    def action_export(self) -> None:
        """Export data"""
        logger.info("Export action triggered")
