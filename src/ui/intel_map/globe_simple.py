"""
Simple Globe Threat Visualization
Lightweight fallback globe when full rendering isn't available.
"""

import math
import logging
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple, List
from rich.panel import Panel
from rich.text import Text

from .key import get_threat_char, get_threat_color

logger = logging.getLogger(__name__)


@dataclass
class Threat:
    """A threat event on the globe"""
    lat: float
    lon: float
    level: float  # 0-1
    ip: str = ""
    org_type: str = "unknown"
    age: float = 0.0


class SimpleGlobe:
    """
    Ultra-simple rotating globe visualization.
    Lightweight fallback when other implementations fail.

    Features:
    - Basic circle outline
    - Crosshair reference lines
    - Threat markers with rotation
    - Compact integrated key
    - Status indicator for debugging
    """

    MAP_TYPE = "SimpleGlobe"
    MAP_STATUS = "FALLBACK"  # Simple globe is always fallback mode

    def __init__(self, width: int = 70, height: int = 15):
        self.width = max(20, min(width, 150))
        self.height = max(8, min(height, 40))
        self.rotation = 0.0
        self.threats: deque = deque(maxlen=15)
        self.frame_count = 0
        self.time_elapsed = 0.0
        self.paused = False
        self._init_error = "Lightweight fallback"

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> None:
        """Add a threat marker"""
        self.threats.append(Threat(lat, lon, threat_score, ip, org_type))

    def update(self, dt: float = 0.1) -> None:
        """Update animation"""
        if not self.paused:
            self.rotation += 2 * dt  # Rotate 2 degrees per 100ms
        self.frame_count += 1
        self.time_elapsed += dt

        # Age threats
        for threat in self.threats:
            threat.age += dt

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """Convert lat/lon to screen position on rotating globe"""
        # Apply rotation
        rotated_lon = lon + self.rotation

        # Normalize to -180 to 180
        while rotated_lon > 180:
            rotated_lon -= 360
        while rotated_lon < -180:
            rotated_lon += 360

        # Only show front hemisphere (within +/- 90 degrees of center)
        if rotated_lon < -90 or rotated_lon > 90:
            return None  # Behind globe

        # Map to screen
        x = int((rotated_lon + 90) / 180 * (self.width - 1))
        y = int((90 - lat) / 180 * (self.height - 1))

        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    def render(self) -> Panel:
        """Render globe as simple grid"""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw status indicator in upper-left corner
        status_text = f"[{self.MAP_TYPE}:FALLBACK]"
        status_style = "dim yellow"
        for i, ch in enumerate(status_text):
            x = 1 + i
            if x < self.width:
                canvas[0][x] = Text(ch, style=status_style)

        # Draw simple globe outline
        cx, cy = self.width // 2, self.height // 2
        radius = min(self.width // 2, self.height) - 2

        # Draw sparse circle
        for angle in range(0, 360, 20):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad) * 0.8)
            y = int(cy + radius * math.sin(rad) * 0.4)
            if 0 <= x < self.width and 0 <= y < self.height:
                canvas[y][x] = '.'

        # Draw crosshair reference lines
        for x in range(self.width):
            if canvas[cy][x] == ' ':
                canvas[cy][x] = '·'

        for y in range(self.height):
            if canvas[y][cx] == ' ':
                canvas[y][cx] = '·'

        # Draw threats as colored markers
        for threat in self.threats:
            pos = self.latlon_to_screen(threat.lat, threat.lon)
            if pos:
                x, y = pos
                char = get_threat_char(threat.level)
                color = get_threat_color(threat.level)
                canvas[y][x] = Text(char, style=color)

        # Render compact key in bottom-right corner
        key_lines = [
            ("●Crit", "bold red"),
            ("◉High", "bold yellow"),
            ("○Med", "yellow"),
            ("·Low", "green"),
        ]
        key_x = max(0, self.width - 6)
        key_y = max(0, self.height - len(key_lines) - 1)

        for i, (text, style) in enumerate(key_lines):
            y = key_y + i
            if y < self.height:
                for j, ch in enumerate(text):
                    x = key_x + j
                    if x < self.width:
                        canvas[y][x] = Text(ch, style=style)

        # Convert canvas to Rich Text
        content = Text()
        for row_idx, row in enumerate(canvas):
            for cell in row:
                if isinstance(cell, Text):
                    content.append_text(cell)
                else:
                    content.append(cell)
            if row_idx < len(canvas) - 1:
                content.append("\n")

        # Add stats footer
        threat_count = len(self.threats)
        critical = sum(1 for t in self.threats if t.level >= 0.7)

        content.append(f"\n")
        content.append(f"Rot:{self.rotation:.0f} ", style="dim")
        content.append(f"[{threat_count}]", style="dim")
        if critical > 0:
            content.append(f" Crit:{critical}", style="bold red")

        return Panel(
            content,
            title="[bold cyan]Threat Globe[/bold cyan]",
            border_style="cyan"
        )

    def toggle_pause(self) -> None:
        """Toggle pause/resume rotation"""
        self.paused = not self.paused

    def clear_threats(self) -> None:
        """Clear all threats"""
        self.threats.clear()

    def resize(self, width: int, height: int) -> None:
        """Resize the globe"""
        self.width = max(20, min(width, 150))
        self.height = max(8, min(height, 40))
