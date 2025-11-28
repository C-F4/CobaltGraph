#!/usr/bin/env python3
"""
Device Correlation & Relationship Analysis

Identify related devices and behavioral patterns:
- Shared destination analysis
- Behavioral similarity clustering
- Device family detection
- Threat correlation
"""

import logging
from typing import Optional

from rich.panel import Panel as RichPanel
from textual.widgets import Static

from src.ui.reconnaissance.device_state import DeviceReconRecord, DeviceReconnaissanceEngine

logger = logging.getLogger(__name__)


class DeviceCorrelationPanel(Static):
    """
    Device-to-device relationship visualization

    Shows:
    - Devices with shared destination IPs
    - Behavioral similarity clustering
    - Device network relationships
    - Threat correlation
    """

    DEFAULT_CSS = """
    DeviceCorrelationPanel {
        border: solid $success;
        height: 100%;
        width: 100%;
        padding: 1;
        overflow: hidden;
    }
    """

    def __init__(self, engine: DeviceReconnaissanceEngine, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine
        self.selected_device: Optional[DeviceReconRecord] = None

    def render(self) -> RichPanel:
        """Render device correlations"""
        if not self.selected_device:
            return RichPanel("No device selected", title="Device Correlations")

        device = self.selected_device
        lines = []

        # Find devices with similar threat profiles
        all_devices = self.engine.get_devices()
        similar_devices = []

        for other in all_devices:
            if other.primary_ip == device.primary_ip:
                continue

            # Calculate similarity
            threat_diff = abs(other.threat_score - device.threat_score)
            role_match = 1.0 if other.inferred_role == device.inferred_role else 0.0

            similarity = (1.0 - min(threat_diff, 1.0)) * 0.5 + role_match * 0.5
            if similarity > 0.4:
                similar_devices.append((other, similarity))

        if similar_devices:
            similar_devices.sort(key=lambda x: x[1], reverse=True)
            lines.append("Similar Devices (Threat/Role):")
            for other, similarity in similar_devices[:5]:
                device_id = other.mac_address or other.primary_ip
                lines.append(f"  {device_id}: {similarity:.0%}")
        else:
            lines.append("No similar devices found")

        # Shared destinations would require connection data
        # This is a simplified version
        if device.metrics.unique_destinations > 0:
            lines.append("")
            lines.append(f"Destination Coverage:")
            lines.append(f"  {device.metrics.unique_destinations} unique destinations")

        # Family analysis (devices with same vendor)
        if device.vendor:
            same_vendor = [d for d in all_devices if d.vendor == device.vendor and d.primary_ip != device.primary_ip]
            if same_vendor:
                lines.append("")
                lines.append(f"Same Vendor Devices ({device.vendor}):")
                for other in same_vendor[:3]:
                    device_id = other.mac_address or other.primary_ip
                    lines.append(f"  {device_id}: threat={other.threat_score:.2f}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Device Correlations[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device
