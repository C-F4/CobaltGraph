#!/usr/bin/env python3
"""
Network Topology Visualization Panels

Device→Destination flow visualization and interactive topology:
- NetworkTopologyPanel: Basic flow diagram
- InteractiveTopologyPanel: Expandable device tree with drill-down
- TopologyMatrix: Heatmap showing device↔destination relationships
"""

import logging
from collections import defaultdict
from typing import List, Dict, Optional

from rich.panel import Panel as RichPanel
from rich.text import Text
from textual.widgets import Static, DataTable

from src.ui.reconnaissance.device_state import DeviceReconRecord, DeviceReconnaissanceEngine

logger = logging.getLogger(__name__)


class NetworkTopologyPanel(Static):
    """
    Device→Destination flow visualization

    Shows:
    - Which devices are talking to what destinations
    - Top 5 devices and their top 3 destinations
    - Threat level color coding
    - Connection counts and organization info
    """

    DEFAULT_CSS = """
    NetworkTopologyPanel {
        border: solid $primary;
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: hidden;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.flows: Dict = {}

    def update_flows(self, connections: List[Dict], devices: Optional[List[DeviceReconRecord]] = None) -> None:
        """
        Update topology from connections and devices

        Args:
            connections: List of connection dictionaries
            devices: List of DeviceReconRecord objects
        """
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
        if devices:
            for device in devices:
                mac = device.mac_address or device.primary_ip
                device_map[mac] = {
                    'vendor': device.vendor or 'Unknown',
                    'threat': device.threat_score,
                }

        # Build flows from connections
        for conn in connections:
            src_mac = conn.get('src_mac') or conn.get('src_ip', 'Unknown')
            dst_ip = conn.get('dst_ip', 'Unknown')
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

    def render(self) -> RichPanel:
        """Render topology visualization"""
        lines = []

        if not self.flows:
            return RichPanel("No network topology data", title="Network Topology")

        for mac, flow in list(self.flows.items())[:5]:  # Limit to top 5 devices
            vendor = flow.get('device_vendor', 'Unknown')
            lines.append(f"[bold cyan]{mac[:16]}[/bold cyan] ({vendor})")

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
        return RichPanel(content, title="[bold cyan]Network Topology[/bold cyan]", border_style="cyan")


class InteractiveTopologyPanel(Static):
    """
    Interactive network topology with expandable device tree

    Features:
    - Tree view of devices and destinations
    - Click to expand/collapse device branches
    - Threat level highlighting
    - Real-time activity indicators
    """

    DEFAULT_CSS = """
    InteractiveTopologyPanel {
        border: solid $secondary;
        height: 100%;
        width: 100%;
        overflow: hidden;
    }

    InteractiveTopologyPanel DataTable {
        height: 100%;
    }
    """

    def __init__(self, engine: DeviceReconnaissanceEngine, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine
        self.table: Optional[DataTable] = None
        self.expanded_devices: set = set()
        self.max_destinations_shown = 5

    def compose(self):
        """Create topology table"""
        table = DataTable(show_cursor=True, show_header=True)
        table.add_columns(
            "Device",
            "Role",
            "Threat",
            "Destinations",
            "Activity",
        )
        self.table = table
        yield table

    def update_topology(self) -> None:
        """Update topology visualization from engine"""
        if not self.table:
            return

        self.table.clear()

        devices = self.engine.get_devices(sort_by="threat", limit=10)

        for device in devices:
            # Device row
            device_id = device.mac_address or device.primary_ip
            vendor = f" ({device.vendor})" if device.vendor else ""

            threat_color = "green" if device.threat_score < 0.3 else (
                "yellow" if device.threat_score < 0.6 else (
                    "bold yellow" if device.threat_score < 0.8 else "bold red"
                )
            )

            threat_text = Text(f"{device.threat_score:.2f}", style=threat_color)

            activity = "🔴 Active" if device.state.value == "active" else "🟡 Idle"

            self.table.add_row(
                f"[bold]{device_id}{vendor}[/bold]",
                device.inferred_role.value.replace("_", " "),
                threat_text,
                f"{device.metrics.unique_destinations}",
                activity,
            )

    def toggle_device_expansion(self, device_id: str) -> None:
        """Toggle expansion of device destinations"""
        if device_id in self.expanded_devices:
            self.expanded_devices.remove(device_id)
        else:
            self.expanded_devices.add(device_id)
        self.update_topology()


class TopologyHeatmapPanel(Static):
    """
    Device↔Destination relationship heatmap

    Shows:
    - Matrix view of which devices talk to which destinations
    - Color intensity = threat level
    - Size/opacity = connection count
    """

    DEFAULT_CSS = """
    TopologyHeatmapPanel {
        border: solid $info;
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: hidden;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.device_dest_matrix: Dict[str, Dict[str, int]] = {}

    def render(self) -> RichPanel:
        """Render heatmap"""
        if not self.device_dest_matrix:
            return RichPanel("No topology data", title="Topology Heatmap")

        lines = []
        lines.append("Device ↔ Destination Activity Heatmap")
        lines.append("")

        # Simplified text representation
        for device, dests in list(self.device_dest_matrix.items())[:5]:
            dest_str = ", ".join(f"{d[:12]}" for d in list(dests.keys())[:5])
            lines.append(f"  {device[:16]:16} → {dest_str}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Topology Heatmap[/bold cyan]", border_style="cyan")

    def update_matrix(self, connections: List[Dict]) -> None:
        """Update device-destination matrix from connections"""
        self.device_dest_matrix = defaultdict(lambda: defaultdict(int))

        for conn in connections:
            src = conn.get('src_mac') or conn.get('src_ip', 'unknown')
            dst = conn.get('dst_ip', 'unknown')
            self.device_dest_matrix[src][dst] += 1
