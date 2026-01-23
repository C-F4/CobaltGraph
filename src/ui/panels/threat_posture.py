"""
Threat Posture Panel
====================

Top-left panel showing current threat level and top active threats.
Provides at-a-glance threat assessment with visual indicators.
"""

import logging
from typing import Dict, List, Any

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static
from textual.reactive import reactive

logger = logging.getLogger(__name__)


class ThreatPosturePanel(Static):
    """
    Displays current threat posture with key metrics.

    Shows:
        - Current average threat level (gauge)
        - Number of active high threats
        - Top 3 threat connections
        - Trend indicator (rising/falling)

    Attributes:
        threat_data: Reactive dict with threat metrics
    """

    DEFAULT_CSS = """
    ThreatPosturePanel {
        height: 100%;
        width: 100%;
        padding: 1;
    }
    """

    threat_data = reactive(dict)

    # Threat gauge characters
    GAUGE_CHARS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.threat_data = {
            'current_threat': 0.0,
            'baseline_threat': 0.0,
            'active_threats': 0,
            'monitored_ips': 0,
            'high_threat_count': 0,
            'top_threats': [],
        }
        self._pulse_frame = 0

    def watch_threat_data(self, new_data: dict) -> None:
        """Update display when threat data changes."""
        self.refresh()

    def pulse(self) -> None:
        """Animate threat indicator."""
        self._pulse_frame = (self._pulse_frame + 1) % 4
        self.refresh()

    def render(self) -> Panel:
        """Render the threat posture panel."""
        current = float(self.threat_data.get('current_threat', 0) or 0)
        baseline = float(self.threat_data.get('baseline_threat', 0) or 0)
        active = int(self.threat_data.get('active_threats', 0) or 0)
        monitored = int(self.threat_data.get('monitored_ips', 0) or 0)
        high_count = int(self.threat_data.get('high_threat_count', 0) or 0)
        top_threats = self.threat_data.get('top_threats', [])

        content = Text()

        # Threat level header with gauge
        content.append("THREAT LEVEL\n", style="bold")
        content.append(self._render_gauge(current))
        content.append(f"  {current:.1%}\n\n", style=self._get_threat_style(current))

        # Stats row
        content.append("Active: ", style="dim")
        content.append(f"{active}", style="bold red" if active > 0 else "green")
        content.append("  │  ", style="dim")
        content.append("High: ", style="dim")
        content.append(f"{high_count}", style="bold yellow" if high_count > 0 else "green")
        content.append("  │  ", style="dim")
        content.append("IPs: ", style="dim")
        content.append(f"{monitored}\n\n", style="cyan")

        # Trend indicator
        if baseline > 0:
            trend = current - baseline
            if trend > 0.1:
                content.append("↑ Rising", style="bold red")
            elif trend < -0.1:
                content.append("↓ Falling", style="bold green")
            else:
                content.append("→ Stable", style="dim")
            content.append(f" (baseline: {baseline:.1%})\n\n", style="dim")

        # Top threats
        if top_threats:
            content.append("TOP THREATS\n", style="bold")
            for i, threat in enumerate(top_threats[:3]):
                ip = threat.get('dst_ip', 'Unknown')[:15]
                score = float(threat.get('threat_score', 0) or 0)
                org = (threat.get('dst_org') or 'Unknown')[:10]

                style = self._get_threat_style(score)
                indicator = self._get_threat_indicator(score)

                content.append(f"{indicator} ", style=style)
                content.append(f"{ip:<15}", style=f"bold {style}")
                content.append(f" {org}\n", style="dim")
        else:
            content.append("[dim]No active threats[/dim]\n")

        return Panel(
            content,
            title="[bold cyan]Threat Posture[/bold cyan]",
            border_style="cyan"
        )

    def _render_gauge(self, level: float) -> Text:
        """Render a visual threat gauge."""
        gauge = Text()
        gauge.append("[", style="dim")

        # 10-segment gauge
        for i in range(10):
            threshold = i / 10
            if level > threshold:
                idx = min(7, int((level - threshold) * 80))
                char = self.GAUGE_CHARS[idx]
                style = self._get_threat_style(level)
            else:
                char = '░'
                style = "dim"
            gauge.append(char, style=style)

        gauge.append("]", style="dim")
        return gauge

    def _get_threat_style(self, score: float) -> str:
        """Get color style for threat score."""
        if score >= 0.8:
            return "bold red"
        elif score >= 0.6:
            return "bold yellow"
        elif score >= 0.4:
            return "yellow"
        elif score >= 0.2:
            return "cyan"
        return "green"

    def _get_threat_indicator(self, score: float) -> str:
        """Get indicator character for threat level."""
        if score >= 0.8:
            return "●"
        elif score >= 0.6:
            return "◉"
        elif score >= 0.4:
            return "◯"
        elif score >= 0.2:
            return "○"
        return "·"
