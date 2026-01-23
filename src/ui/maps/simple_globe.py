"""
Simple Globe Implementation
===========================

Lightweight fallback globe visualization with minimal dependencies.
Used when full geographic rendering is unavailable or for
resource-constrained environments.
"""

import math
import logging
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple, List

from rich.panel import Panel
from rich.text import Text

from .base import BaseMap
from .utils import int_to_roman

logger = logging.getLogger(__name__)


@dataclass
class SimpleThreat:
    """Minimal threat representation for simple globe."""
    lat: float
    lon: float
    level: float
    age: float = 0.0


class SimpleGlobe(BaseMap):
    """
    Ultra-lightweight static globe visualization.

    Features:
        - Minimal memory footprint
        - No external dependencies beyond Rich
        - Basic threat markers
        - Static view (no rotation) for fallback mode

    Best used as a fallback when other map types fail to initialize.
    This is visually distinct from RotatingGlobe to indicate degraded mode.
    """

    MAP_TYPE = "SIMPLE"

    # Fixed rotation showing Americas/Atlantic view
    FIXED_ROTATION = -30

    def __init__(self, width: int = 60, height: int = 15):
        """
        Initialize simple globe.

        Args:
            width: Canvas width
            height: Canvas height
        """
        # Enforce minimum viable globe size
        width = max(20, width)
        height = max(10, height)

        super().__init__(width=width, height=height, max_threats=15)

        # Simple threat storage
        self._simple_threats: deque = deque(maxlen=15)

        # Status
        self._status = self.STATUS_FALLBACK
        self._init_error = "Lightweight fallback"

        logger.debug(f"SimpleGlobe initialized: {width}x{height}")

    # =========================================================================
    # THREAT MANAGEMENT
    # =========================================================================

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> bool:
        """
        Add a simple threat marker.

        For SimpleGlobe, we only track position and threat level.
        """
        # Filter unknown locations
        if lat == 0.0 and lon == 0.0:
            if ip:
                self._unknown_ips.add(ip)
                self._unknown_count = len(self._unknown_ips)
            return False

        self._simple_threats.append(SimpleThreat(lat, lon, threat_score))
        return True

    def clear_threats(self) -> None:
        """Clear all threats."""
        super().clear_threats()
        self._simple_threats.clear()

    # =========================================================================
    # COORDINATE CONVERSION
    # =========================================================================

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """
        Convert lat/lon to screen coordinates on rotating sphere.

        Returns None if point is on back hemisphere.
        """
        # Apply rotation
        rotated_lon = lon + self.rotation
        rotated_lon = ((rotated_lon + 180) % 360) - 180

        # Back hemisphere check
        if abs(rotated_lon) > 90:
            return None

        # Convert to radians
        lat_rad = math.radians(lat)
        lon_rad = math.radians(rotated_lon)

        # Orthographic projection with aspect ratio compensation
        from .utils import CHAR_ASPECT_RATIO

        cx = self.width // 2
        cy = self.height // 2
        radius_x = self.width // 2 - 2
        radius_y = round((self.height // 2 - 1) * CHAR_ASPECT_RATIO)

        x = cx + round(radius_x * math.cos(lat_rad) * math.sin(lon_rad))
        y = cy - round(radius_y * math.sin(lat_rad))

        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    @property
    def rotation(self) -> float:
        """Fixed rotation showing Americas/Atlantic view (static fallback)."""
        return self.FIXED_ROTATION

    # =========================================================================
    # ANIMATION
    # =========================================================================

    def update(self, dt: float = 0.1) -> None:
        """Update animation state."""
        if self.paused:
            return

        super().update(dt)

        # Age simple threats
        for threat in self._simple_threats:
            threat.age += dt

    # =========================================================================
    # RENDERING
    # =========================================================================

    def render(self) -> Panel:
        """Render the simple globe (static fallback mode)."""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw globe outline (simplified, sparser than rotating globe)
        self._draw_outline(canvas)

        # Skip grid lines - keep it minimal for fallback mode

        # Draw threats
        self._draw_threats(canvas)

        # Draw status
        status_text = self.get_status_text()
        for i, ch in enumerate(status_text):
            x = 1 + i
            if x < self.width:
                canvas[0][x] = Text(ch, style="dim yellow")

        # Convert to text
        lines = []
        for row in canvas:
            line = Text()
            for cell in row:
                if isinstance(cell, Text):
                    line.append_text(cell)
                else:
                    line.append(str(cell))
            lines.append(line)

        content = Text("\n").join(lines)

        # Stats footer - note this is static
        threat_count = len(self._simple_threats)
        critical = sum(1 for t in self._simple_threats if t.level >= 0.7)
        unknown_part = f" | Unk:{int_to_roman(self._unknown_count)}" if self._unknown_count > 0 else ""

        footer = f"\n[dim]Static view | Threats: {threat_count} | Critical: {critical}{unknown_part}[/dim]"
        content.append(footer)

        return Panel(
            content,
            title="[bold cyan]Threat Globe[/bold cyan] [dim yellow](fallback)[/dim yellow]",
            border_style="yellow"  # Yellow border indicates degraded mode
        )

    def _draw_outline(self, canvas: List[List]) -> None:
        """Draw simple dotted globe circle (sparser than rotating globe)."""
        from .utils import CHAR_ASPECT_RATIO

        cx = self.width // 2
        cy = self.height // 2

        # Use same radii calculation as latlon_to_screen
        radius_x = self.width // 2 - 2
        radius_y = round((self.height // 2 - 1) * CHAR_ASPECT_RATIO)

        # Sparser outline (12° step instead of 5° for rotating globe)
        for angle in range(0, 360, 12):
            rad = math.radians(angle)
            x = round(cx + radius_x * math.cos(rad))
            y = round(cy - radius_y * math.sin(rad))

            if 0 <= x < self.width and 0 <= y < self.height:
                # Use simpler '.' character for lighter appearance
                canvas[y][x] = Text('.', style="dim")

    def _draw_grid(self, canvas: List[List]) -> None:
        """Draw simple latitude/longitude grid."""
        # Equator
        for lon in range(-90, 91, 15):
            pos = self.latlon_to_screen(0, lon)
            if pos:
                x, y = pos
                if canvas[y][x] == ' ':
                    canvas[y][x] = Text('─', style="dim")

        # Prime meridian
        for lat in range(-80, 81, 10):
            pos = self.latlon_to_screen(lat, 0)
            if pos:
                x, y = pos
                if canvas[y][x] == ' ':
                    canvas[y][x] = Text('│', style="dim")

    def _draw_threats(self, canvas: List[List]) -> None:
        """Draw threat markers."""
        for threat in self._simple_threats:
            pos = self.latlon_to_screen(threat.lat, threat.lon)
            if not pos:
                continue

            x, y = pos

            # Simple threat level coloring
            if threat.level >= 0.8:
                char, style = '●', 'bold red'
            elif threat.level >= 0.6:
                char, style = '◉', 'bold yellow'
            elif threat.level >= 0.4:
                char, style = '○', 'yellow'
            else:
                char, style = '·', 'green'

            canvas[y][x] = Text(char, style=style)
