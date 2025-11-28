#!/usr/bin/env python3
"""
CobaltGraph Advanced Device Reconnaissance Panels

Provides comprehensive UI widgets for device reconnaissance:
1. DeviceDiscoveryPanel - Real-time device inventory with state indicators
2. DeviceDetailPanel - Drill-down view with activity timeline
3. DeviceBehaviorPanel - Behavioral analysis and anomalies
4. DeviceCorrelationPanel - Device-to-device relationships
5. PassiveFingerprintPanel - OS, TTL, hop analysis

Works with both device and network modes through unified DeviceReconnaissanceEngine.
"""

import logging
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import math

from rich.text import Text
from rich.table import Table as RichTable
from rich.panel import Panel as RichPanel
from rich.console import Console
from textual.widgets import Static, DataTable
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

from src.ui.device_state_machine import (
    DeviceReconRecord,
    DeviceState,
    DeviceRole,
    DeviceReconnaissanceEngine,
)

logger = logging.getLogger(__name__)


class DeviceDiscoveryPanel(Static):
    """
    Real-time device discovery and inventory panel

    Features:
    - Active device list with state indicators
    - Threat level color coding
    - Real-time MAC learning animation
    - Sortable by threat, activity, vendor
    - Live status updates (🟢 online, 🟡 idle, ⚫ offline)
    """

    DEFAULT_CSS = """
    DeviceDiscoveryPanel {
        border: solid $primary;
        height: 100%;
        width: 100%;
        overflow: hidden;
    }

    DeviceDiscoveryPanel DataTable {
        height: 100%;
    }
    """

    def __init__(self, engine: DeviceReconnaissanceEngine, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine
        self.table: Optional[DataTable] = None
        self.sort_by = "threat"
        self.filter_state: Optional[DeviceState] = None

    def compose(self):
        """Create discovery table"""
        table = DataTable(show_cursor=True, show_header=True)
        table.add_columns(
            "Status",
            "MAC / IP",
            "Vendor",
            "Threat",
            "Role",
            "Connections",
            "Last Seen",
        )
        self.table = table
        yield table

    def update_devices(self) -> None:
        """Update device list from engine"""
        if not self.table:
            return

        self.table.clear()

        devices = self.engine.get_devices(
            filter_state=self.filter_state,
            sort_by=self.sort_by,
            limit=20
        )

        for device in devices:
            # State indicator
            if device.state == DeviceState.ACTIVE:
                status = "🟢"
            elif device.state == DeviceState.IDLE:
                status = "🟡"
            elif device.state == DeviceState.OFFLINE:
                status = "⚫"
            else:
                status = "⚪"

            # MAC or IP
            device_id = device.mac_address or device.primary_ip

            # Threat color
            threat = device.threat_score
            if threat >= 0.8:
                threat_style = "bold red"
            elif threat >= 0.6:
                threat_style = "bold yellow"
            elif threat >= 0.3:
                threat_style = "yellow"
            else:
                threat_style = "green"

            threat_text = Text(f"{threat:.2f}", style=threat_style)

            # Last activity
            time_since = datetime.now().timestamp() - device.last_seen
            if time_since < 60:
                last_seen = f"{int(time_since)}s ago"
            elif time_since < 3600:
                last_seen = f"{int(time_since/60)}m ago"
            else:
                last_seen = f"{int(time_since/3600)}h ago"

            self.table.add_row(
                status,
                device_id,
                device.vendor or "-",
                threat_text,
                device.inferred_role.value.replace("_", " "),
                str(device.metrics.total_connections),
                last_seen,
            )


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

    def __init__(self, engine: DeviceReconnaissanceEngine, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine
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
        lines.append(f"  Role: {device.inferred_role.value}")

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


class DeviceThreatTimelinePanel(Static):
    """
    Device threat evolution timeline

    Shows:
    - Threat score changes over time
    - Connection spike detection
    - Activity patterns (hourly)
    - Anomaly events
    """

    DEFAULT_CSS = """
    DeviceThreatTimelinePanel {
        border: solid $warning;
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
        """Render threat timeline"""
        if not self.selected_device:
            return RichPanel("No device selected", title="Threat Timeline")

        device = self.selected_device
        lines = []

        # Create ASCII sparkline from threat trend
        if device.metrics.threat_scores:
            # Get last 60 samples
            samples = device.metrics.threat_scores[-60:]
            normalized = []

            max_score = max(samples) if samples else 1.0
            min_score = min(samples) if samples else 0.0
            range_score = max_score - min_score if max_score > min_score else 1.0

            # Sparkline characters (full → empty)
            sparkline_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']

            spark_str = ""
            for score in samples:
                normalized_score = (score - min_score) / range_score if range_score > 0 else 0
                char_idx = min(int(normalized_score * (len(sparkline_chars) - 1)), len(sparkline_chars) - 1)
                spark_str += sparkline_chars[char_idx]

            lines.append(f"Threat Evolution (last 60 events):")
            lines.append(spark_str)
            lines.append(f"Range: {min_score:.3f} → {max_score:.3f}")

        # Hourly activity
        if device.metrics.connections_per_hour:
            lines.append("")
            lines.append("Hourly Activity:")

            # Simple bar chart
            max_per_hour = max(device.metrics.connections_per_hour) if device.metrics.connections_per_hour else 1
            for i, count in enumerate(device.metrics.connections_per_hour[-24:]):
                if max_per_hour > 0:
                    bar_width = int((count / max_per_hour) * 20)
                else:
                    bar_width = 0
                bar = '█' * bar_width + '░' * (20 - bar_width)
                lines.append(f"  {i:2d}h: {bar} {count}")

        # Anomalies
        if device.is_anomalous:
            lines.append("")
            lines.append(f"[bold yellow]Anomaly Detected: {device.anomaly_type}[/bold yellow]")
            lines.append(f"  Score: {device.anomaly_score:.3f}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Threat Timeline[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device


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
            elif device.metrics.average_hop_count <= 7:
                position = "Regional network"
            elif device.metrics.average_hop_count <= 15:
                position = "Cross-region"
            else:
                position = "Distant/unusual"

            lines.append(f"  Position: {position}")

        # Protocol distribution
        if device.metrics.unique_protocols:
            lines.append("")
            lines.append(f"Protocols: {', '.join(sorted(device.metrics.unique_protocols))}")

        # Top ports
        if device.metrics.unique_ports:
            lines.append(f"Ports Used ({len(device.metrics.unique_ports)}): {', '.join(str(p) for p in sorted(device.metrics.unique_ports)[:10])}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Passive Fingerprint[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device


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

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Device Correlations[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device
