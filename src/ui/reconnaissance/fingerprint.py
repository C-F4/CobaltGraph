#!/usr/bin/env python3
"""
Passive Fingerprinting Panel

OS detection, TTL analysis, and network topology visualization:
- TTL-based OS fingerprinting
- Hop count and network distance analysis
- MAC vendor identification
- Protocol and port distribution
"""

import logging
from typing import Optional

from rich.panel import Panel as RichPanel
from textual.widgets import Static

from src.ui.reconnaissance.device_state import DeviceReconRecord

logger = logging.getLogger(__name__)


class PassiveFingerprintPanel(Static):
    """
    Passive fingerprinting and network analysis panel

    Shows:
    - TTL-based OS detection
    - Hop count analysis (network distance)
    - MAC vendor identification
    - Protocol distribution
    - Port usage patterns
    """

    DEFAULT_CSS = """
    PassiveFingerprintPanel {
        border: solid $info;
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: hidden;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_device: Optional[DeviceReconRecord] = None

    def render(self) -> RichPanel:
        """Render fingerprinting data"""
        if not self.selected_device:
            return RichPanel("No device selected", title="Passive Fingerprint")

        device = self.selected_device
        fp = device.fingerprint
        lines = []

        # MAC vendor (network mode)
        if fp.mac_address:
            lines.append(f"MAC Address: {fp.mac_address}")
            if fp.mac_vendor:
                lines.append(f"  Vendor: {fp.mac_vendor}")

        # OS detection via TTL
        if fp.estimated_os:
            lines.append("")
            lines.append(f"OS Fingerprint: {fp.estimated_os}")
            lines.append(f"  Confidence: {fp.os_confidence:.1%}")

        if fp.ttl_initial_estimate:
            lines.append(f"  Estimated Initial TTL: {fp.ttl_initial_estimate}")

        # Hop analysis
        if device.metrics.average_hop_count > 0:
            lines.append("")
            lines.append(f"Network Position:")
            lines.append(f"  Average Hops: {device.metrics.average_hop_count:.1f}")

            # Classify network position
            if device.metrics.average_hop_count <= 3:
                position = "Local network"
                color = "green"
            elif device.metrics.average_hop_count <= 7:
                position = "Regional network"
                color = "yellow"
            elif device.metrics.average_hop_count <= 15:
                position = "Cross-region"
                color = "bold yellow"
            else:
                position = "Distant/unusual"
                color = "bold red"

            lines.append(f"  Position: [{color}]{position}[/{color}]")

        # Protocol distribution
        if device.metrics.unique_protocols:
            lines.append("")
            lines.append(f"Protocols: {', '.join(sorted(device.metrics.unique_protocols))}")

        # Top ports
        if device.metrics.unique_ports:
            lines.append(f"Ports Used ({len(device.metrics.unique_ports)}): {', '.join(str(p) for p in sorted(device.metrics.unique_ports)[:10])}")

        # Additional analysis
        if device.fingerprint.is_local:
            lines.append("")
            lines.append("[green]Local Device[/green]")
        else:
            lines.append("")
            lines.append("[yellow]Remote Device[/yellow]")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Passive Fingerprint[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device
