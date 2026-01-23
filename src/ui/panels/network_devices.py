"""
Network Devices Panel
=====================

Bottom-right panel displaying discovered network devices.
Shows device information with flow data and threat indicators.

In network mode: Shows destination flows per device (MAC-based)
In device mode: Shows device inventory with connection counts
"""

import json
import logging
from typing import List, Dict, Any, Optional

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class NetworkDevicesPanel(Static):
    """
    Displays discovered network devices with their traffic flows.

    Two display modes based on available data:
        - Flow mode: Shows device → destination flows (when topology data available)
        - Inventory mode: Shows device list with stats (fallback)

    Attributes:
        topology_data: Dict mapping MAC → flow data
        devices: List of device dicts
        mode: Operating mode ('network' or 'device')
    """

    DEFAULT_CSS = """
    NetworkDevicesPanel {
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: auto;
    }
    """

    topology_data = reactive(dict)
    devices = reactive(list)
    network_info = reactive(dict)

    def __init__(self, mode: str = "device", **kwargs):
        super().__init__(**kwargs)
        self.mode = mode
        self.topology_data = {}
        self.devices = []
        self.network_info = {'ip_range': 'detecting...'}

    def watch_topology_data(self, new_data: dict) -> None:
        """Update when topology data changes."""
        self._update_network_range_from_topology()
        self.refresh()

    def watch_devices(self, new_devices: list) -> None:
        """Update when device list changes."""
        self._update_network_range_from_devices()
        self.refresh()

    def _update_network_range_from_topology(self) -> None:
        """Detect network range from flow data."""
        if not self.topology_data:
            return

        src_ips = set()
        for mac, flow_data in self.topology_data.items():
            if 'src_ip' in flow_data:
                src_ips.add(flow_data['src_ip'])

        self._detect_network_range(src_ips)

    def _update_network_range_from_devices(self) -> None:
        """Detect network range from device IPs."""
        if not self.devices:
            return

        src_ips = set()
        for device in self.devices:
            ip_addresses = device.get('ip_addresses', [])

            # Handle JSON string that wasn't parsed
            if isinstance(ip_addresses, str):
                try:
                    ip_addresses = json.loads(ip_addresses)
                except (json.JSONDecodeError, TypeError):
                    ip_addresses = []

            for ip in ip_addresses:
                if isinstance(ip, str):
                    src_ips.add(ip)

        self._detect_network_range(src_ips)

    def _detect_network_range(self, src_ips: set) -> None:
        """Determine network range from IP set."""
        for ip in src_ips:
            if not isinstance(ip, str):
                continue

            if ip.startswith('192.168.'):
                parts = ip.split('.')
                if len(parts) >= 3:
                    self.network_info['ip_range'] = f"192.168.{parts[2]}.0/24"
                    return
            elif ip.startswith('10.'):
                parts = ip.split('.')
                if len(parts) >= 3:
                    self.network_info['ip_range'] = f"10.{parts[1]}.{parts[2]}.0/24"
                    return
            elif ip.startswith('172.'):
                parts = ip.split('.')
                if len(parts) >= 2:
                    try:
                        second = int(parts[1])
                        if 16 <= second <= 31:
                            self.network_info['ip_range'] = f"172.{parts[1]}.{parts[2]}.0/24"
                            return
                    except ValueError:
                        pass

    def render(self) -> Panel:
        """Render the network devices panel."""
        has_flow_data = bool(self.topology_data)
        has_device_data = bool(self.devices)

        if not has_flow_data and not has_device_data:
            return Panel(
                "[dim]Scanning network...[/dim]\n\n"
                "[cyan]Waiting for network traffic...[/cyan]\n"
                "[dim]Devices will appear with:\n"
                "- MAC address\n"
                "- IP address\n"
                "- Connection flows[/dim]",
                title="[bold cyan]Network Devices[/bold cyan]",
                border_style="cyan"
            )

        content = Text()

        # Header
        content.append("┌─────────────────────────────────────────┐\n", style="bold cyan")
        content.append("│           NETWORK DEVICES               │\n", style="bold cyan")
        content.append("└─────────────────────────────────────────┘\n", style="bold cyan")

        # Network range
        ip_range = self.network_info.get('ip_range', 'detecting...')
        content.append("Network: ", style="bold")
        content.append(f"{ip_range}\n\n", style="cyan")

        # Render based on available data
        if has_flow_data:
            self._render_flows(content)
        elif has_device_data:
            self._render_devices(content)

        return Panel(
            content,
            title="[bold cyan]Network Devices[/bold cyan]",
            border_style="cyan"
        )

    def _render_flows(self, content: Text) -> None:
        """Render devices with destination flows."""
        device_count = len(self.topology_data)
        total_flows = sum(len(f.get('destinations', {})) for f in self.topology_data.values())

        content.append(f"Devices: {device_count} | Flows: {total_flows}\n\n", style="dim")

        # Sort by threat and take top 5
        sorted_devices = sorted(
            self.topology_data.items(),
            key=lambda x: float(x[1].get('threat_avg', 0) or 0),
            reverse=True
        )[:5]

        for idx, (src_mac, flow_data) in enumerate(sorted_devices):
            vendor = (flow_data.get('device_vendor') or 'Unknown')[:12]
            src_ip = flow_data.get('src_ip', '')
            threat_score = float(flow_data.get('threat_avg', 0) or 0)

            is_last = idx == len(sorted_devices) - 1
            prefix = "└" if is_last else "├"

            # Threat indicator
            threat_icon, threat_color = self._get_threat_style(threat_score)

            content.append(f"{prefix} ", style="cyan")
            content.append(f"{threat_icon} ", style=threat_color)
            content.append(f"{vendor:12s}\n", style=threat_color)
            content.append(f"│  MAC: {src_mac}\n", style="dim")

            if src_ip:
                content.append("│  IP:  ", style="dim")
                content.append(f"{src_ip}\n", style="cyan")

            # Top 2 destinations
            destinations = sorted(
                flow_data.get('destinations', {}).items(),
                key=lambda x: float(x[1].get('threat', 0) or 0),
                reverse=True
            )[:2]

            for dest_idx, (dest_key, data) in enumerate(destinations):
                threat = float(data.get('threat', 0) or 0)
                count = data.get('count', 0)
                protocol = data.get('protocol', 'TCP')

                # Parse IP:port
                if ':' in dest_key:
                    parts = dest_key.rsplit(':', 1)
                    dst_ip = parts[0][:15]
                    dst_port = parts[1]
                else:
                    dst_ip = dest_key[:15]
                    dst_port = '?'

                proto = "U" if protocol == "UDP" else "T"
                proto_color = "magenta" if protocol == "UDP" else "cyan"
                _, dest_color = self._get_threat_style(threat)

                is_dest_last = dest_idx == len(destinations) - 1
                flow_prefix = "│  └─" if is_dest_last else "│  ├─"

                content.append(f"{flow_prefix}", style="dim")
                content.append("→ ", style="cyan")
                content.append(f"{proto} ", style=proto_color)
                content.append(f"{dst_ip}:{dst_port}", style=dest_color)
                content.append(f" x{count}\n")

        content.append("\n")
        content.append("→=Out T=TCP U=UDP | !=Crit ~=Med .=Low\n", style="dim")

    def _render_devices(self, content: Text) -> None:
        """Render device inventory without flows."""
        total_flows = sum(d.get('connection_count', 0) or 0 for d in self.devices)
        high_risk = len([d for d in self.devices if float(d.get('threat_score', 0) or 0) >= 0.5])

        content.append(f"Devices: {len(self.devices)} | Flows: {total_flows} | High Risk: {high_risk}\n\n", style="dim")

        # Sort by threat
        sorted_devices = sorted(
            self.devices,
            key=lambda d: float(d.get('threat_score', 0) or 0),
            reverse=True
        )[:6]

        for idx, device in enumerate(sorted_devices):
            mac = device.get('mac', 'Unknown')
            vendor = (device.get('vendor') or 'Unknown')[:12]
            display_name = device.get('display_name', '')
            threat = float(device.get('threat_score', 0) or 0)
            conn_count = device.get('connection_count', 0) or 0

            # Get primary IP
            ip_addresses = device.get('ip_addresses', [])
            if isinstance(ip_addresses, str):
                try:
                    ip_addresses = json.loads(ip_addresses)
                except (json.JSONDecodeError, TypeError):
                    ip_addresses = []
            primary_ip = ip_addresses[0] if ip_addresses and isinstance(ip_addresses[0], str) else ''

            is_last = idx == len(sorted_devices) - 1
            prefix = "└" if is_last else "├"

            threat_icon, threat_color = self._get_threat_style(threat)

            content.append(f"{prefix} ", style="cyan")
            content.append(f"{threat_icon} ", style=threat_color)
            content.append(f"{vendor:12s}", style=threat_color)
            content.append(f" {conn_count} flows\n")
            content.append(f"│  MAC: {mac}\n", style="dim")

            if primary_ip:
                content.append("│  IP:  ", style="dim")
                content.append(f"{primary_ip}\n", style="cyan")

        content.append("\n")
        content.append("!=Crit ~=Med .=Low threat\n", style="dim")

    def _get_threat_style(self, threat_score: float) -> tuple:
        """Return (icon, color) based on threat score."""
        if threat_score >= 0.7:
            return "!", "bold red"
        elif threat_score >= 0.4:
            return "~", "bold yellow"
        else:
            return ".", "green"
