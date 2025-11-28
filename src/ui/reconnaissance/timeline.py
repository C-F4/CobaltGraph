#!/usr/bin/env python3
"""
Timeline Visualization Panels

Device threat evolution and activity pattern visualization:
- ThreatTimelinePanel: Threat score changes with sparklines
- ActivityPatternPanel: Hourly activity heatmap
- AnomalyTimelinePanel: Anomaly event detection
"""

import logging
from typing import Optional

from rich.panel import Panel as RichPanel
from textual.widgets import Static

from src.ui.reconnaissance.device_state import DeviceReconRecord

logger = logging.getLogger(__name__)


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


class ActivityPatternPanel(Static):
    """
    Device activity pattern analysis

    Shows:
    - Connection rate over time
    - Activity variance
    - Peak activity hours
    - Periodic behavior detection (beaconing)
    """

    DEFAULT_CSS = """
    ActivityPatternPanel {
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
        """Render activity patterns"""
        if not self.selected_device:
            return RichPanel("No device selected", title="Activity Pattern")

        device = self.selected_device
        lines = []

        # Activity summary
        lines.append(f"Activity Statistics:")
        lines.append(f"  Total Connections: {device.metrics.total_connections}")
        lines.append(f"  Activity Variance: {device.metrics.activity_variance:.2f}")

        # Peak hours
        if device.metrics.connections_per_hour:
            max_hour = max(enumerate(device.metrics.connections_per_hour[-24:]), key=lambda x: x[1])
            lines.append(f"  Peak Hour: Hour {max_hour[0]} ({max_hour[1]} connections)")

        # Beaconing detection
        if device.metrics.activity_variance > 0.5:
            lines.append("")
            lines.append("[yellow]Periodic Activity Detected[/yellow]")
            lines.append("  Pattern suggests scheduled beaconing or C2 communication")

        # Connection distribution
        lines.append("")
        lines.append(f"Protocol Distribution:")
        for protocol in sorted(device.metrics.unique_protocols):
            lines.append(f"  {protocol}: used")

        # Port diversity
        lines.append("")
        lines.append(f"Port Behavior:")
        lines.append(f"  Unique Ports: {len(device.metrics.unique_ports)}")
        lines.append(f"  Preferred Ports: {', '.join(str(p) for p in sorted(device.metrics.unique_ports)[:5])}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Activity Pattern[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device


class AnomalyTimelinePanel(Static):
    """
    Anomaly event timeline

    Shows:
    - Detected anomalies over time
    - Anomaly types and severity
    - Contributing factors
    - Timeline of suspicious events
    """

    DEFAULT_CSS = """
    AnomalyTimelinePanel {
        border: solid $error;
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
        """Render anomaly timeline"""
        if not self.selected_device:
            return RichPanel("No anomalies detected", title="Anomaly Timeline")

        device = self.selected_device
        lines = []

        if device.is_anomalous:
            lines.append(f"[bold red]Anomaly Detected[/bold red]")
            lines.append(f"  Type: {device.anomaly_type or 'unknown'}")
            lines.append(f"  Score: {device.anomaly_score:.3f}")
            lines.append("")

        # Anomaly types reference
        lines.append("Anomaly Types:")
        anomaly_types = {
            "burst": "Sudden spike in connections",
            "cascade": "Sequential connections to multiple IPs",
            "sweep": "Rapid scanning across port range",
            "beacon": "Periodic regular connections (C2 pattern)",
            "exfiltration": "Large data transfer to untrusted org",
            "geographic": "Connections to high-risk regions",
            "temporal": "Activity outside normal patterns",
        }

        for atype, desc in anomaly_types.items():
            lines.append(f"  • {atype}: {desc}")

        content = "\n".join(lines)
        return RichPanel(content, title="[bold cyan]Anomaly Timeline[/bold cyan]", border_style="cyan")

    def select_device(self, device: DeviceReconRecord) -> None:
        """Select device to display"""
        self.selected_device = device
