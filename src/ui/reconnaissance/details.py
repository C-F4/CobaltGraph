#!/usr/bin/env python3
"""
Device Detail Panel

Detailed drill-down view showing:
- Device identity (MAC, IPs, vendor)
- State and threat metrics
- Timeline information
- Connection metrics
- Passive fingerprinting data
- Risk flags and analyst notes
"""

import logging
from typing import Optional

from rich.panel import Panel as RichPanel
from rich.text import Text
from textual.widgets import Static

from src.ui.reconnaissance.device_state import DeviceReconRecord, DeviceState

logger = logging.getLogger(__name__)


class DeviceDetailPanel(Static):
    """
    Detailed drill-down view of a single device

    Shows:
    - Device identity (MAC, IPs, vendor)
    - Connection history (top destinations)
    - Threat timeline (24h activity)
    - Passive fingerprinting (OS, hops)
    - Risk flags and analyst notes
    """

    DEFAULT_CSS = """
    DeviceDetailPanel {
        border: solid $secondary;
        height: 100%;
        width: 100%;
        padding: 1;
        overflow-y: scroll;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_device: Optional[DeviceReconRecord] = None

    def render(self) -> RichPanel:
        """Render device details"""
        if not self.selected_device:
            return RichPanel("No device selected", title="Device Details")

        device = self.selected_device
        device.update_state()
        device.update_timestamps()

        lines = []

        # Header
        device_id = device.mac_address or device.primary_ip
        lines.append(f"[bold cyan]{device_id}[/bold cyan]")

        if device.vendor:
            lines.append(f"  Vendor: {device.vendor}")

        # State and threat
        state_emoji = {
            DeviceState.ACTIVE: "🟢",
            DeviceState.IDLE: "🟡",
            DeviceState.OFFLINE: "⚫",
            DeviceState.DISCOVERED: "⚪",
        }

        threat_color = "green" if device.threat_score < 0.3 else (
            "yellow" if device.threat_score < 0.6 else (
                "bold yellow" if device.threat_score < 0.8 else "bold red"
            )
        )

        lines.append("")
        lines.append(f"  State: {state_emoji[device.state]} {device.state.value}")
        lines.append(f"  Threat: [{threat_color}]{device.threat_score:.3f}[/{threat_color}] (95th: {device.threat_percentile_95:.3f})")
        lines.append(f"  Role: {device.inferred_role.value.replace('_', ' ')}")

        # Timeline
        lines.append("")
        lines.append(f"  First Seen: {device.first_seen_human}")
        lines.append(f"  Last Seen: {device.last_seen_human}")

        # Metrics
        lines.append("")
        lines.append(f"  Connections: {device.metrics.total_connections}")
        lines.append(f"  Unique Destinations: {device.metrics.unique_destinations}")
        lines.append(f"  Unique Ports: {len(device.metrics.unique_ports)}")
        lines.append(f"  High-Threat Connections: {device.metrics.high_threat_count}")

        # Passive fingerprinting
        if device.fingerprint.estimated_os:
            lines.append("")
            lines.append(f"  OS Fingerprint: {device.fingerprint.estimated_os}")

        if device.metrics.average_hop_count > 0:
            lines.append(f"  Avg Hops: {device.metrics.average_hop_count:.1f}")

        # IP addresses
        if device.fingerprint.ip_addresses:
            lines.append("")
            lines.append(f"  IP Addresses: {', '.join(sorted(device.fingerprint.ip_addresses))}")

        # Risk flags
        if device.risk_flags:
            lines.append("")
            lines.append(f"  Risk Flags: {', '.join(device.risk_flags)}")

        # Notes
        if device.analyst_notes:
            lines.append("")
            lines.append(f"  Notes: {device.analyst_notes}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Device Details[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device
