"""
Rotating Globe Threat Visualization
3D rotating globe with coastlines, connection trails, and threat markers.
"""

import math
import logging
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List
from rich.panel import Panel
from rich.text import Text

from .key import get_threat_char, get_threat_color, ORG_TYPE_COLORS

try:
    from src.ui.geo_data import GeoData, Point
except ImportError:
    try:
        from ..geo_data import GeoData, Point
    except ImportError:
        GeoData = None
        Point = None

logger = logging.getLogger(__name__)


@dataclass
class Connection:
    """A threat connection to visualize"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float
    org_type: str
    ip: str
    age: float = 0.0


class RotatingGlobe:
    """
    Rotating 3D threat globe with geographic rendering.

    Features:
    - Smooth rotation animation
    - Continent outlines
    - Connection trails from center
    - Color-coded threat markers
    - Integrated compact key
    - Status indicator for debugging
    """

    MAP_TYPE = "RotatingGlobe"
    MAP_STATUS = "FULL"

    def __init__(self, width: int = 70, height: int = 15):
        self.width = max(30, min(width, 200))
        self.height = max(10, min(height, 50))
        self.rotation = 0.0  # Current rotation angle (degrees)
        self.paused = False
        self.frame_count = 0
        self.time_elapsed = 0.0

        # Connection tracking
        self.connections: deque = deque(maxlen=15)
        self.connection_trails: Dict[str, float] = {}

        # Geographic data and status
        self.geo_data = GeoData() if GeoData else None
        self._init_error = None

        if not self.geo_data:
            self._init_error = "GeoData unavailable"
            self.MAP_STATUS = "DEGRADED"

        # Interaction state
        self.selected_country = None

    def add_connection(self, src_lat: float, src_lon: float,
                       dst_lat: float, dst_lon: float,
                       threat_score: float, org_type: str, ip: str) -> None:
        """Add a threat connection to visualize"""
        conn = Connection(
            src_lat=src_lat, src_lon=src_lon,
            dst_lat=dst_lat, dst_lon=dst_lon,
            threat_score=threat_score, org_type=org_type, ip=ip
        )
        self.connections.append(conn)
        self.connection_trails[ip] = 0.0

    def add_threat(self, lat: float, lon: float, ip: str,
                   threat_score: float, org_type: str) -> None:
        """Convenience method matching FlatWorldMap interface"""
        # Assume source is center of view (0, 0)
        self.add_connection(0, 0, lat, lon, threat_score, org_type, ip)

    def update(self, dt: float = 0.05) -> None:
        """Update animation state"""
        if not self.paused:
            # Slow rotation: ~45 seconds per full rotation
            self.rotation = (self.rotation + 8.0 * dt) % 360.0

        self.time_elapsed += dt
        self.frame_count += 1

        # Age connections
        for conn in self.connections:
            conn.age += dt

        # Age trails (fade out over 2 seconds)
        for ip in list(self.connection_trails.keys()):
            self.connection_trails[ip] += dt
            if self.connection_trails[ip] > 2.0:
                del self.connection_trails[ip]

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """Convert lat/lon to screen position with rotation"""
        # Apply rotation
        rotated_lon = (lon + self.rotation) % 360
        if rotated_lon > 180:
            rotated_lon -= 360

        # Only show front hemisphere
        if rotated_lon < -90 or rotated_lon > 90:
            return None

        # Map to screen
        x = int((rotated_lon + 90) / 180 * (self.width - 1))
        y = int((90 - lat) / 180 * (self.height - 1))

        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    def render_globe_outline(self, canvas: List[List]) -> None:
        """Draw globe outline circle"""
        cx, cy = self.width // 2, self.height // 2
        radius = min(self.width // 2, self.height) - 1

        # Draw sparse circle outline
        for angle in range(0, 360, 15):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad) * 0.8)  # Slightly smaller for terminal aspect
            y = int(cy + radius * math.sin(rad) * 0.4)  # Compress vertically

            if 0 <= x < self.width and 0 <= y < self.height:
                if isinstance(canvas[y][x], str):
                    canvas[y][x] = Text('·', style="dim cyan")

    def render_coastlines(self, canvas: List[List]) -> None:
        """Render continent boundaries as simplified outlines"""
        continents = {
            'NAM': ([(50, -140), (50, -100), (42, -85), (35, -80), (25, -97), (30, -115)], "dim blue"),
            'SAM': ([(12, -60), (5, -70), (-5, -72), (-20, -68), (-35, -55), (-40, -60)], "dim green"),
            'EUR': ([(70, -10), (60, 10), (50, 25), (45, 20), (35, 0), (20, -30)], "dim yellow"),
            'ASA': ([(70, 30), (70, 100), (60, 120), (40, 135), (20, 130), (15, 90), (35, 40)], "dim magenta"),
            'AUS': ([(-10, 115), (-10, 155), (-40, 150), (-25, 128)], "dim white"),
        }

        for name, (points, style) in continents.items():
            self._draw_polygon_outline(canvas, points, style)

    def _draw_polygon_outline(self, canvas: List[List], points: List[Tuple[float, float]], style: str) -> None:
        """Draw polygon outline"""
        for i in range(len(points)):
            p1 = points[i]
            p2 = points[(i + 1) % len(points)]

            pos1 = self.latlon_to_screen(p1[0], p1[1])
            pos2 = self.latlon_to_screen(p2[0], p2[1])

            if pos1 and pos2:
                self._draw_line(canvas, pos1, pos2, style)

    def _draw_line(self, canvas: List[List], start: Tuple[int, int],
                   end: Tuple[int, int], style: str) -> None:
        """Draw a line using DDA algorithm"""
        x0, y0 = start
        x1, y1 = end

        dx = x1 - x0
        dy = y1 - y0
        steps = max(abs(dx), abs(dy))

        if steps == 0:
            return

        x_inc = dx / steps
        y_inc = dy / steps

        x, y = float(x0), float(y0)
        for _ in range(int(steps) + 1):
            ix, iy = int(round(x)), int(round(y))
            if 0 <= ix < self.width and 0 <= iy < self.height:
                cell = canvas[iy][ix]
                if isinstance(cell, str) and cell in (' ', '·'):
                    canvas[iy][ix] = Text('-', style=style)
            x += x_inc
            y += y_inc

    def render_connections(self, canvas: List[List]) -> None:
        """Render connection lines from center to destinations"""
        center = (self.width // 2, self.height // 2)

        for conn in self.connections:
            dst_pos = self.latlon_to_screen(conn.dst_lat, conn.dst_lon)
            if not dst_pos:
                continue

            # Get color based on org type
            color = ORG_TYPE_COLORS.get(conn.org_type, "white")

            # Draw line from center to destination
            self._draw_connection_line(canvas, center, dst_pos, color)

            # Draw threat marker at destination
            x, y = dst_pos
            char = get_threat_char(conn.threat_score)
            threat_color = get_threat_color(conn.threat_score)

            canvas[y][x] = Text(char, style=threat_color)

    def _draw_connection_line(self, canvas: List[List], start: Tuple[int, int],
                              end: Tuple[int, int], style: str) -> None:
        """Draw connection line with trail effect"""
        x0, y0 = start
        x1, y1 = end

        dx = x1 - x0
        dy = y1 - y0
        steps = max(abs(dx), abs(dy))

        if steps == 0:
            return

        x_inc = dx / steps
        y_inc = dy / steps

        x, y = float(x0), float(y0)
        for step in range(int(steps) + 1):
            ix, iy = int(round(x)), int(round(y))
            if 0 <= ix < self.width and 0 <= iy < self.height:
                cell = canvas[iy][ix]
                # Only draw on empty or background cells
                if isinstance(cell, str) and cell in (' ', '·', '-'):
                    # Fade effect based on distance from destination
                    progress = step / steps if steps > 0 else 1
                    if progress > 0.3:  # Only draw last 70% of line
                        canvas[iy][ix] = Text('·', style=f"dim {style}")
            x += x_inc
            y += y_inc

    def render_status_indicator(self, canvas: List[List]) -> None:
        """Render map status indicator in upper-left corner"""
        if self.MAP_STATUS == "FULL":
            status_text = f"[{self.MAP_TYPE}]"
            status_style = "dim green"
        else:
            error_info = self._init_error or "Unknown"
            status_text = f"[{self.MAP_TYPE}:DEGRADED:{error_info[:10]}]"
            status_style = "dim yellow"

        start_x = 1
        start_y = 0

        for i, ch in enumerate(status_text):
            x = start_x + i
            if x < self.width and start_y < self.height:
                canvas[start_y][x] = Text(ch, style=status_style)

    def render_key(self, canvas: List[List]) -> None:
        """Render compact key in bottom-right corner"""
        key_lines = [
            ("Key:", "dim white"),
            ("●Crit ◉Hi", "bold red"),
            ("○Med ·Lo", "yellow"),
        ]

        start_x = max(0, self.width - 12)
        start_y = max(0, self.height - len(key_lines) - 1)

        for i, (text, style) in enumerate(key_lines):
            y = start_y + i
            if y >= self.height:
                break
            for j, ch in enumerate(text):
                x = start_x + j
                if x < self.width:
                    canvas[y][x] = Text(ch, style=style)

    def render(self) -> Panel:
        """Render the rotating globe"""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Render layers in order
        self.render_status_indicator(canvas)
        self.render_globe_outline(canvas)
        self.render_coastlines(canvas)
        self.render_connections(canvas)
        self.render_key(canvas)

        # Convert canvas to text
        lines = []
        for row in canvas:
            line = Text("")
            for cell in row:
                if isinstance(cell, Text):
                    line.append_text(cell)
                else:
                    line.append(cell)
            lines.append(line)

        content = Text()
        for i, line in enumerate(lines):
            content.append_text(line)
            if i < len(lines) - 1:
                content.append("\n")

        # Add stats footer
        threat_count = len(self.connections)
        critical = sum(1 for c in self.connections if c.threat_score >= 0.7)
        rotation_display = f"{self.rotation:.0f}"
        pause_indicator = "PAUSED" if self.paused else "rotating"

        content.append(f"\n")
        content.append(f"Rot:{rotation_display} ", style="dim")
        if self.paused:
            content.append(pause_indicator, style="bold red")
        else:
            content.append(pause_indicator, style="dim")
        content.append(f" [{threat_count}]", style="dim")
        if critical > 0:
            content.append(f" Crit:{critical}", style="bold red")

        title = "[bold cyan]Threat Globe[/bold cyan]"
        if self.selected_country:
            title += f" [yellow]({self.selected_country})[/yellow]"

        return Panel(
            content,
            title=title,
            border_style="cyan"
        )

    def toggle_pause(self) -> None:
        """Toggle pause/resume rotation"""
        self.paused = not self.paused

    def clear_connections(self) -> None:
        """Clear all connections"""
        self.connections.clear()
        self.connection_trails.clear()

    def clear_threats(self) -> None:
        """Alias for clear_connections to match FlatWorldMap interface"""
        self.clear_connections()

    def resize(self, width: int, height: int) -> None:
        """Resize the globe"""
        self.width = max(30, min(width, 200))
        self.height = max(10, min(height, 50))
