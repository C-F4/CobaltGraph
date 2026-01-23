"""
Rotating Globe Implementation
=============================

3D-style rotating globe visualization with animated threat connections.
Provides a dynamic view of global threat distribution with great-circle
arcs showing connection paths.

Best suited for presentations and high-level threat overview.
"""

import math
import logging
from typing import Optional, Tuple, List, Dict

from rich.panel import Panel
from rich.text import Text

from .base import BaseMap, ThreatMarker, ConnectionArc
from .utils import (
    get_threat_char,
    get_threat_color,
    get_org_color,
    int_to_roman,
    clamp,
)

# Import geographic data
try:
    from src.ui.geo_data import GeoData, Point
except ImportError:
    try:
        from ..geo_data import GeoData, Point
    except ImportError:
        GeoData = None
        Point = None

logger = logging.getLogger(__name__)


class RotatingGlobe(BaseMap):
    """
    Animated rotating globe visualization.

    Features:
        - Simulated 3D sphere with rotation
        - Country coastlines (visible hemisphere only)
        - Connection arcs with animation
        - Threat markers with depth fading
        - Organization-based coloring

    The globe rotates continuously, showing different parts of the world
    over time. Connection arcs animate from source to destination.
    """

    MAP_TYPE = "GLOBE"

    # Default rotation speed (degrees per second)
    DEFAULT_ROTATION_SPEED = 2.0

    def __init__(self, width: int = 70, height: int = 20):
        """
        Initialize rotating globe.

        Args:
            width: Canvas width in characters
            height: Canvas height in lines
        """
        # Enforce minimum viable globe size
        width = max(20, width)
        height = max(10, height)

        super().__init__(width=width, height=height, max_threats=20)

        # Rotation state
        self.rotation: float = 0.0
        self._rotation_speed: float = self.DEFAULT_ROTATION_SPEED

        # Connection tracking (for arcs)
        self.connections: List[ConnectionArc] = []
        self.connection_trails: Dict[str, float] = {}

        # Geographic data
        self._geo = GeoData() if GeoData else None

        if not self._geo:
            self._status = self.STATUS_DEGRADED
            self._init_error = "GeoData unavailable"

        # Interaction state
        self.selected_country: Optional[str] = None

        logger.debug(f"RotatingGlobe initialized: {width}x{height}")

    # =========================================================================
    # CONNECTION MANAGEMENT
    # =========================================================================

    def add_connection(self, src_lat: float, src_lon: float,
                       dst_lat: float, dst_lon: float,
                       threat_score: float, org_type: str = "unknown",
                       ip: str = "") -> bool:
        """
        Add a connection arc to the globe.

        Args:
            src_lat: Source latitude
            src_lon: Source longitude
            dst_lat: Destination latitude
            dst_lon: Destination longitude
            threat_score: Threat level (0-1)
            org_type: Organization type
            ip: Destination IP address

        Returns:
            True if added, False if filtered
        """
        # Filter unknown destinations
        if dst_lat == 0.0 and dst_lon == 0.0:
            if ip:
                self._unknown_ips.add(ip)
                self._unknown_count = len(self._unknown_ips)
            return False

        arc = ConnectionArc(
            src_lat=src_lat,
            src_lon=src_lon,
            dst_lat=dst_lat,
            dst_lon=dst_lon,
            threat_score=threat_score,
            org_type=org_type.lower(),
            ip=ip,
        )

        # Keep only recent connections
        if len(self.connections) >= 15:
            self.connections.pop(0)
        self.connections.append(arc)

        # Track IP for trail effect
        if ip:
            self.connection_trails[ip] = 0.0

        return True

    def clear_connections(self) -> None:
        """Clear all connection arcs."""
        self.connections.clear()
        self.connection_trails.clear()
        self._unknown_ips.clear()
        self._unknown_count = 0

    # Alias for compatibility
    def clear_threats(self) -> None:
        """Clear all visualizations (alias for clear_connections)."""
        super().clear_threats()
        self.clear_connections()

    # =========================================================================
    # COORDINATE CONVERSION
    # =========================================================================

    def latlon_to_screen(self, lat: float, lon: float) -> Optional[Tuple[int, int]]:
        """
        Convert lat/lon to screen coordinates on rotating sphere.

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)

        Returns:
            Tuple (x, y) if point is visible, None if on back side
        """
        # Apply rotation
        rotated_lon = lon + self.rotation
        rotated_lon = ((rotated_lon + 180) % 360) - 180

        # Check if point is on visible hemisphere
        if abs(rotated_lon) > 90:
            return None  # Back side of globe

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

        # Check bounds
        if 0 <= x < self.width and 0 <= y < self.height:
            return (x, y)
        return None

    # =========================================================================
    # ANIMATION
    # =========================================================================

    def set_rotation_speed(self, speed: float) -> None:
        """Set rotation speed (degrees/second). 0 = paused."""
        self._rotation_speed = max(0, speed)

    def set_rotation_angle(self, angle: float) -> None:
        """Manually set rotation angle."""
        self.rotation = angle % 360

    def get_rotation_speed(self) -> float:
        """Get current rotation speed."""
        return self._rotation_speed

    def update(self, dt: float = 0.1) -> None:
        """Update rotation and animation state."""
        if self.paused:
            return

        super().update(dt)

        # Update rotation
        self.rotation += self._rotation_speed * dt
        if self.rotation >= 360:
            self.rotation -= 360

        # Age connections
        for arc in self.connections:
            arc.age += dt

        # Update trails
        expired = []
        for ip, age in self.connection_trails.items():
            self.connection_trails[ip] = age + dt
            if age > 2.0:
                expired.append(ip)
        for ip in expired:
            del self.connection_trails[ip]

    # =========================================================================
    # RENDERING
    # =========================================================================

    def render(self) -> Panel:
        """Render the rotating globe."""
        try:
            return self._render_globe()
        except Exception as e:
            logger.warning(f"Globe render failed: {e}")
            return self._render_fallback()

    def _render_globe(self) -> Panel:
        """Full globe rendering."""
        # Create canvas
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Render layers
        self._render_globe_outline(canvas)
        self._render_coastlines(canvas)
        self._render_connections(canvas)
        self._render_legend(canvas)

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

        # Add stats footer
        stats = self.get_stats()
        pause_indicator = "[PAUSED]" if stats['paused'] else "rotating"
        unknown_part = f" | Unk:{int_to_roman(stats['unknown'])}" if stats['unknown'] > 0 else ""

        footer = (
            f"\n[dim]Rotation: {self.rotation:.0f}° | {pause_indicator} | "
            f"Connections: {len(self.connections)} | "
            f"Critical: {stats['critical']}{unknown_part}[/dim]"
        )
        content.append(footer)

        # Build title
        title = "[bold cyan]Threat Globe[/bold cyan]"
        if self.selected_country:
            title += f" [yellow]({self.selected_country})[/yellow]"

        return Panel(content, title=title, border_style="cyan")

    def _render_fallback(self) -> Panel:
        """Minimal fallback rendering."""
        return Panel(
            f"[dim]Globe unavailable[/dim]\n{self.get_status_text()}",
            title="[bold cyan]Threat Globe[/bold cyan]",
            border_style="yellow"
        )

    def _render_globe_outline(self, canvas: List[List]) -> None:
        """Draw globe circle outline matching marker projection."""
        from .utils import CHAR_ASPECT_RATIO

        cx = self.width // 2
        cy = self.height // 2

        # Use SAME radii as latlon_to_screen for consistency
        radius_x = self.width // 2 - 2
        radius_y = round((self.height // 2 - 1) * CHAR_ASPECT_RATIO)

        # Draw circle using parametric equation
        for angle in range(0, 360, 5):
            rad = math.radians(angle)
            x = round(cx + radius_x * math.cos(rad))
            y = round(cy - radius_y * math.sin(rad))

            if 0 <= x < self.width and 0 <= y < self.height:
                if canvas[y][x] == ' ':
                    canvas[y][x] = Text('·', style="dim cyan")

    def _render_coastlines(self, canvas: List[List]) -> None:
        """Draw visible coastlines with connected lines."""
        if not self._geo:
            return

        coastlines = self._geo.get_coastlines()
        for segment in coastlines:
            # Skip empty or single-point segments
            if len(segment.points) < 2:
                continue

            prev_pos = None
            for point in segment.points:
                pos = self.latlon_to_screen(point.lat, point.lon)

                # Draw point
                if pos:
                    x, y = pos
                    if canvas[y][x] == ' ':
                        canvas[y][x] = Text('·', style="dim green")

                    # Draw line from previous point
                    if prev_pos:
                        self._draw_line_segment(canvas, prev_pos, pos, "dim green")

                prev_pos = pos if pos else None  # Reset if point hidden

    def _draw_line_segment(self, canvas: List[List], p1: Tuple[int, int],
                           p2: Tuple[int, int], style: str) -> None:
        """Draw line between two screen points using DDA algorithm."""
        x0, y0 = p1
        x1, y1 = p2

        # Skip segments that would cross entire screen (date line wrap)
        if abs(x1 - x0) > self.width // 2:
            return

        dx = x1 - x0
        dy = y1 - y0
        steps = max(abs(dx), abs(dy))

        if steps == 0:
            return

        x_inc = dx / steps
        y_inc = dy / steps
        x, y = float(x0), float(y0)

        for _ in range(int(steps) + 1):
            ix, iy = round(x), round(y)
            if 0 <= ix < self.width and 0 <= iy < self.height:
                if canvas[iy][ix] == ' ':
                    canvas[iy][ix] = Text('·', style=style)
            x += x_inc
            y += y_inc

    def _get_depth_style(self, lon_offset: float, base_color: str) -> str:
        """
        Get style based on distance from center (depth effect).

        Args:
            lon_offset: Degrees from center (-90 to 90 visible)
            base_color: Base color to modify

        Returns:
            Style string with depth modification
        """
        depth = abs(lon_offset) / 90  # 0 = center, 1 = edge

        if depth < 0.3:
            return f"bold {base_color}"
        elif depth < 0.6:
            return base_color
        else:
            return f"dim {base_color}"

    def _interpolate_arc_linear(self, lat1: float, lon1: float,
                                 lat2: float, lon2: float,
                                 steps: int = 10) -> List[Tuple[float, float]]:
        """
        Interpolate points along connection arc using linear interpolation.

        Note: This is NOT true great-circle (geodesic) interpolation.
        For visual purposes on a small terminal globe, linear interpolation
        produces acceptable results while being computationally simpler.

        Args:
            lat1, lon1: Source coordinates
            lat2, lon2: Destination coordinates
            steps: Number of interpolation points

        Returns:
            List of (lat, lon) tuples along the path
        """
        points = []
        for i in range(steps + 1):
            t = i / steps
            lat = lat1 + t * (lat2 - lat1)
            lon = lon1 + t * (lon2 - lon1)
            points.append((lat, lon))
        return points

    def _render_connections(self, canvas: List[List]) -> None:
        """Draw connection arcs with depth-based styling."""
        for arc in self.connections:
            # Interpolate arc path
            points = self._interpolate_arc_linear(
                arc.src_lat, arc.src_lon,
                arc.dst_lat, arc.dst_lon,
                steps=8
            )

            # Animate: show partial arc based on age (up to 2 seconds for full arc)
            visible_count = min(len(points), int(arc.age * 5) + 1)

            for i, (lat, lon) in enumerate(points[:visible_count]):
                pos = self.latlon_to_screen(lat, lon)
                if not pos:
                    continue

                x, y = pos

                # Calculate depth for this point
                rotated_lon = lon + self.rotation
                rotated_lon = ((rotated_lon + 180) % 360) - 180

                # Different markers for path vs destination
                if i == len(points) - 1:
                    # Destination marker
                    char = get_threat_char(arc.threat_score)
                    base_color = get_org_color(arc.org_type)
                else:
                    # Path marker
                    intensity = (i + 1) / visible_count
                    char = '·' if intensity < 0.5 else '•'
                    base_color = "yellow"

                style = self._get_depth_style(rotated_lon, base_color)
                canvas[y][x] = Text(char, style=style)

    def _render_legend(self, canvas: List[List]) -> None:
        """Render compact legend."""
        legend = [
            ("Threat:", "dim"),
            ("● Crit", "bold red"),
            ("◉ High", "yellow"),
            ("○ Med", "cyan"),
            ("· Low", "green"),
        ]

        start_x = self.width - 12
        start_y = self.height - len(legend) - 1

        for i, (text, style) in enumerate(legend):
            y = start_y + i
            if y >= self.height:
                break
            for j, ch in enumerate(text):
                x = start_x + j
                if x < self.width:
                    canvas[y][x] = Text(ch, style=style)

    # =========================================================================
    # INTERACTION
    # =========================================================================

    def select_country(self, country: Optional[str]) -> None:
        """Set or clear country selection."""
        self.selected_country = country
