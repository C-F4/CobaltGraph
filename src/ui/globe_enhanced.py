#!/usr/bin/env python3
"""
Enhanced Interactive Threat Globe
- Rotating globe with country boundaries and coastlines
- Animated connection lines from center to threat destinations
- Color-coded by threat score with organization type opacity
- Interactive controls: pause/resume, country filtering, tooltips
"""

import math
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List
from rich.panel import Panel
from rich.text import Text
from .geo_data import GeoData, Point


@dataclass
class Connection:
    """A threat connection to visualize"""
    src_lat: float
    src_lon: float
    dst_lat: float
    dst_lon: float
    threat_score: float  # 0-1
    org_type: str  # cloud, cdn, hosting, isp, vpn, tor, etc
    ip: str
    age: float = 0.0  # For fade out effect


class EnhancedGlobe:
    """
    Advanced rotating threat globe with real geographic rendering
    """

    def __init__(self, width: int = 70, height: int = 15):
        self.width = width
        self.height = height
        self.rotation = 0.0  # Current rotation angle (degrees)
        self.paused = False
        self.frame_count = 0
        self.time_elapsed = 0.0

        # Connection tracking
        self.connections: deque = deque(maxlen=15)  # Top 15 threats
        self.connection_trails: Dict[str, float] = {}  # IP -> age

        # Geographic data
        self.geo_data = GeoData()

        # Org type colors and opacity mapping
        self.org_colors = {
            'cloud': ('cyan', 0.8),
            'cdn': ('cyan', 0.75),
            'hosting': ('blue', 0.7),
            'isp': ('magenta', 0.6),
            'vpn': ('bold magenta', 0.3),
            'tor': ('bold red', 0.1),
            'enterprise': ('bold green', 0.85),
            'government': ('bold blue', 0.9),
            'education': ('green', 0.8),
            'unknown': ('dim white', 0.5),
        }

        # Interaction state
        self.selected_country = None
        self.hover_ip = None

    def add_connection(self, src_lat: float, src_lon: float,
                       dst_lat: float, dst_lon: float,
                       threat_score: float, org_type: str, ip: str):
        """Add a threat connection to visualize"""
        conn = Connection(
            src_lat=src_lat, src_lon=src_lon,
            dst_lat=dst_lat, dst_lon=dst_lon,
            threat_score=threat_score, org_type=org_type, ip=ip
        )
        self.connections.append(conn)
        self.connection_trails[ip] = 0.0

    def update(self, dt: float = 0.05):
        """Update animation state"""
        if not self.paused:
            # Slow rotation: ~45 seconds per full rotation
            # 360 degrees / 45 seconds = 8 degrees/second
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

    def get_threat_color(self, score: float) -> str:
        """Get color for threat score"""
        if score >= 0.8:
            return "bold red"
        elif score >= 0.6:
            return "bold yellow"
        elif score >= 0.4:
            return "yellow"
        elif score >= 0.2:
            return "cyan"
        else:
            return "green"

    def get_threat_char(self, score: float) -> str:
        """Get character for threat intensity"""
        if score >= 0.8:
            return "●"
        elif score >= 0.6:
            return "◉"
        elif score >= 0.4:
            return "○"
        elif score >= 0.2:
            return "·"
        else:
            return "."

    def render_coastlines(self, canvas: List[List]) -> None:
        """Render continent boundaries as simplified outlines"""
        # Pre-defined continent regions for clean rendering
        continents = {
            'NAM': (self._draw_continent_na, "dim blue"),   # North America
            'SAM': (self._draw_continent_sa, "dim green"),  # South America
            'EUR': (self._draw_continent_eu, "dim yellow"), # Europe/Africa
            'ASA': (self._draw_continent_as_, "dim magenta"),# Asia
            'AUS': (self._draw_continent_au, "dim white"),  # Australia
        }

        # Draw each continent
        for name, (drawer, style) in continents.items():
            drawer(canvas, style)

    def _draw_continent_na(self, canvas: List[List], style: str) -> None:
        """Draw North America outline"""
        points = [
            (50, -140), (50, -100), (42, -85), (35, -80),
            (25, -97), (30, -115), (50, -140)
        ]
        self._draw_polygon_outline(canvas, points, style)

    def _draw_continent_sa(self, canvas: List[List], style: str) -> None:
        """Draw South America outline"""
        points = [
            (12, -60), (5, -70), (-5, -72), (-20, -68),
            (-35, -55), (-40, -60), (12, -60)
        ]
        self._draw_polygon_outline(canvas, points, style)

    def _draw_continent_eu(self, canvas: List[List], style: str) -> None:
        """Draw Europe/Africa outline"""
        points = [
            (70, -10), (60, 10), (50, 25), (45, 20),
            (35, 0), (20, -30), (15, -35), (-20, 10),
            (-15, 20), (5, 20), (35, 5), (70, -10)
        ]
        self._draw_polygon_outline(canvas, points, style)

    def _draw_continent_as_(self, canvas: List[List], style: str) -> None:
        """Draw Asia outline"""
        points = [
            (70, 30), (70, 100), (60, 120), (40, 135),
            (20, 130), (15, 90), (35, 40), (70, 30)
        ]
        self._draw_polygon_outline(canvas, points, style)

    def _draw_continent_au(self, canvas: List[List], style: str) -> None:
        """Draw Australia outline"""
        points = [
            (-10, 115), (-10, 155), (-40, 150),
            (-25, 128), (-10, 115)
        ]
        self._draw_polygon_outline(canvas, points, style)

    def _draw_polygon_outline(self, canvas: List[List], points: List[Tuple[int, int]], style: str) -> None:
        """Draw polygon outline"""
        for i in range(len(points)):
            p1 = points[i]
            p2 = points[(i + 1) % len(points)]

            pos1 = self.latlon_to_screen(p1[0], p1[1])
            pos2 = self.latlon_to_screen(p2[0], p2[1])

            if pos1 and pos2:
                self._draw_line_thin(canvas, pos1, pos2, style)

    def _draw_line_thin(self, canvas: List[List], start: Tuple[int, int],
                        end: Tuple[int, int], style: str) -> None:
        """Draw a thin line using simple DDA algorithm"""
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
                if isinstance(canvas[iy][ix], str) and canvas[iy][ix] in (' ', '·'):
                    canvas[iy][ix] = Text('-', style=style)
            x += x_inc
            y += y_inc

    def _draw_line(self, canvas: List[List], start: Tuple[int, int],
                   end: Tuple[int, int], style: str) -> None:
        """Draw a thick line between two points using Bresenham's algorithm"""
        x0, y0 = start
        x1, y1 = end

        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x1 > x0 else -1
        sy = 1 if y1 > y0 else -1
        err = dx - dy

        x, y = x0, y0
        while True:
            if 0 <= x < self.width and 0 <= y < self.height:
                current = canvas[y][x]
                if isinstance(current, str) and current in (' ', '·', '─', '-'):
                    canvas[y][x] = Text('█', style=style)

            if x == x1 and y == y1:
                break

            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x += sx
            if e2 < dx:
                err += dx
                y += sy

    def render_connections(self, canvas: List[List]) -> None:
        """Render connection lines from center to destinations"""
        # Center point (assuming device is at center)
        center = (self.width // 2, self.height // 2)

        for conn in self.connections:
            # Get destination screen position
            dst_pos = self.latlon_to_screen(conn.dst_lat, conn.dst_lon)
            if not dst_pos:
                continue

            # Get color and opacity based on org type
            color, opacity = self.org_colors.get(conn.org_type, ("white", 0.5))

            # Draw line from center to destination
            self._draw_line(canvas, center, dst_pos, color)

            # Draw threat marker at destination
            x, y = dst_pos
            char = self.get_threat_char(conn.threat_score)
            threat_color = self.get_threat_color(conn.threat_score)

            # Apply opacity effect by reducing brightness for low opacity
            if opacity < 0.5:
                threat_color = f"dim {threat_color}"

            canvas[y][x] = Text(char, style=threat_color)

    def render_globe_outline(self, canvas: List[List]) -> None:
        """Draw globe outline circle"""
        cx, cy = self.width // 2, self.height // 2
        radius = min(self.width, self.height) // 2 - 1

        for angle in range(0, 360, 20):
            rad = math.radians(angle)
            x = int(cx + radius * math.cos(rad))
            y = int(cy + radius * math.sin(rad))

            if 0 <= x < self.width and 0 <= y < self.height:
                if isinstance(canvas[y][x], str):
                    canvas[y][x] = Text('·', style="dim cyan")

    def render(self) -> Panel:
        """Render the enhanced globe"""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Render in order: globe outline, coastlines, connections
        self.render_globe_outline(canvas)
        self.render_coastlines(canvas)
        self.render_connections(canvas)

        # Convert canvas to text
        lines = []
        for row in canvas:
            line_parts = []
            for cell in row:
                if isinstance(cell, Text):
                    line_parts.append(cell)
                else:
                    line_parts.append(cell)

            # Build line with styling
            if any(isinstance(c, Text) for c in line_parts):
                line = Text("")
                for cell in line_parts:
                    if isinstance(cell, Text):
                        line.append(cell)
                    else:
                        line.append(cell)
                lines.append(line)
            else:
                lines.append("".join(line_parts))

        content = "\n".join(str(line) for line in lines)

        # Add stats footer
        threat_count = len(self.connections)
        high_threat = sum(1 for c in self.connections if c.threat_score >= 0.7)
        rotation_display = f"{self.rotation:.0f}°"
        pause_indicator = "[bold red]PAUSED[/bold red]" if self.paused else "[dim]rotating[/dim]"

        stats = f"\n[dim]Rotation: {rotation_display} | {pause_indicator} | Threats: {threat_count} | Critical: {high_threat}[/dim]"

        title = "[bold cyan]🌐 Threat Globe[/bold cyan]"
        if self.selected_country:
            title += f" [yellow]({self.selected_country})[/yellow]"

        return Panel(
            content + stats,
            title=title,
            border_style="cyan"
        )

    def toggle_pause(self) -> None:
        """Toggle pause/resume rotation"""
        self.paused = not self.paused

    def set_selected_country(self, country: Optional[str]) -> None:
        """Set or clear country selection"""
        self.selected_country = country

    def get_connections_for_country(self, country: str) -> List[Connection]:
        """Get connections for a specific country"""
        # This would require mapping lat/lon to country
        # For now, return empty
        return []

    def clear_connections(self) -> None:
        """Clear all connections"""
        self.connections.clear()
        self.connection_trails.clear()
