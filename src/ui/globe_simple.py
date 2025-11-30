#!/usr/bin/env python3
"""
Simple, practical threat globe visualization
Renders as a compact rotating sphere showing threat markers
"""

import math
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple
from rich.panel import Panel
from rich.text import Text


@dataclass
class Threat:
    """A threat event on the globe"""
    lat: float
    lon: float
    level: float  # 0-1
    age: float = 0.0


class SimpleGlobe:
    """
    Ultra-simple rotating globe visualization
    Fits in a small panel and actually renders
    """

    def __init__(self, width: int = 70, height: int = 15):
        self.width = width
        self.height = height
        self.rotation = 0.0
        self.threats: deque = deque(maxlen=15)
        self.frame_count = 0

    def add_threat(self, lat: float, lon: float, level: float):
        """Add a threat marker"""
        self.threats.append(Threat(lat, lon, level))

    def update(self, dt: float = 0.1):
        """Update animation"""
        self.rotation += 2 * dt  # Rotate 2 degrees per 100ms
        self.frame_count += 1

        # Age threats
        for threat in self.threats:
            threat.age += dt

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """Convert lat/lon to screen position on rotating globe"""
        # Apply rotation
        rotated_lon = lon + self.rotation

        # Only show front hemisphere (within ±90 degrees of center)
        if rotated_lon > 180:
            rotated_lon -= 360
        if rotated_lon < -180:
            rotated_lon += 360

        if rotated_lon < -90 or rotated_lon > 90:
            return None  # Behind globe

        # Map to screen
        # Longitude: -90 to 90 → 0 to width
        # Latitude: -90 to 90 → height to 0

        x = int((rotated_lon + 90) / 180 * (self.width - 1))
        y = int((90 - lat) / 180 * (self.height - 1))

        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    def render(self) -> Panel:
        """Render globe as simple grid"""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw simple globe outline - just a circle
        cx, cy = self.width // 2, self.height // 2
        radius = min(self.width, self.height) // 2 - 2

        for angle in range(0, 360, 15):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad))
            y = int(cy + radius * math.sin(rad))
            if 0 <= x < self.width and 0 <= y < self.height:
                canvas[y][x] = '.'

        # Draw some horizontal and vertical lines as reference
        for x in range(self.width):
            y = cy
            if 0 <= y < self.height and canvas[y][x] == ' ':
                canvas[y][x] = '·'

        for y in range(self.height):
            x = cx
            if 0 <= x < self.width and canvas[y][x] == ' ':
                canvas[y][x] = '·'

        # Draw threats as colored markers
        for threat in self.threats:
            pos = self.latlon_to_screen(threat.lat, threat.lon)
            if pos:
                x, y = pos

                # Pick symbol and color based on threat level
                if threat.level >= 0.7:
                    symbol = '●'
                    color = 'bold red'
                elif threat.level >= 0.5:
                    symbol = '◉'
                    color = 'red'
                elif threat.level >= 0.3:
                    symbol = '○'
                    color = 'yellow'
                else:
                    symbol = '·'
                    color = 'green'

                # Apply color
                canvas[y][x] = Text(symbol, style=color)

        # Convert to string, handling Text objects
        lines = []
        for row in canvas:
            line_parts = []
            for cell in row:
                if isinstance(cell, Text):
                    line_parts.append(cell)
                else:
                    line_parts.append(cell)

            # Build line with text styling
            if any(isinstance(c, Text) for c in line_parts):
                line = Text(''.join(str(c) if isinstance(c, str) else '' for c in line_parts))
                # Apply colors properly
                for i, cell in enumerate(line_parts):
                    if isinstance(cell, Text):
                        line.stylize(cell.style, i, i+1)
                lines.append(line)
            else:
                lines.append(''.join(line_parts))

        content = '\n'.join(str(line) for line in lines)

        # Add stats
        threat_count = len(self.threats)
        critical = sum(1 for t in self.threats if t.level >= 0.7)

        stats = f"\n[dim]Rotation: {self.rotation:.0f}° | Threats: {threat_count} | Critical: {critical}[/dim]"

        return Panel(
            content + stats,
            title="[bold cyan]🌐 Threat Globe[/bold cyan]",
            border_style="cyan"
        )
