"""
Flat World Map Implementation
=============================

2D flat world map with rich geographic rendering and threat visualization.

Rendering pipeline:
    1. Base terrain (cached per size)
    2. Coastlines (cached per size)
    3. Threat markers (live)
    4. Legend overlay
"""

import logging
import math
from collections import defaultdict
from typing import Optional, Tuple, Dict, List

from rich.panel import Panel
from rich.text import Text

from .base import BaseMap, ThreatMarker
from .utils import (
    get_threat_char,
    get_threat_color,
    get_org_color,
    int_to_roman,
    miller_projection,
    is_unknown_location,
)

try:
    from src.ui.geo_data import GeoData
except ImportError:
    try:
        from ..geo_data import GeoData
    except ImportError:
        GeoData = None

logger = logging.getLogger(__name__)


class FlatWorldMap(BaseMap):
    """
    2D flat world map with rich geographic rendering.

    Features:
        - Distinct land/water/coastline rendering
        - Miller cylindrical projection (reduced polar distortion)
        - Marker clustering at same screen position
        - Cached base map with resize invalidation
        - Integrated compact legend
    """

    MAP_TYPE = "FLAT"

    # Size constraints
    MIN_WIDTH = 60
    MIN_HEIGHT = 15

    def __init__(self, width: int = 120, height: int = 30,
                 projection: str = "miller"):
        """
        Initialize flat world map.

        Args:
            width: Canvas width (minimum 60 characters)
            height: Canvas height (minimum 15 rows)
            projection: Projection type (only "miller" supported)
        """
        width = max(self.MIN_WIDTH, width)
        height = max(self.MIN_HEIGHT, height)

        super().__init__(width=width, height=height, max_threats=50)

        # Geographic data
        self._geo = GeoData() if GeoData else None

        if not self._geo:
            self._status = self.STATUS_DEGRADED
            self._init_error = "GeoData unavailable"

        # Cluster tracking: screen_pos -> list of ThreatMarker
        self._clusters: Dict[Tuple[int, int], List[ThreatMarker]] = defaultdict(list)

        # Rendering cache
        self._base_cache: Optional[List[List]] = None
        self._cache_size: Optional[Tuple[int, int]] = None

        logger.debug(f"FlatWorldMap initialized: {width}x{height}, geo={bool(self._geo)}")

    def latlon_to_screen(self, lat: float, lon: float) -> Tuple[int, int]:
        """
        Convert latitude/longitude to screen coordinates using Miller projection.

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)

        Returns:
            Tuple of (x, y) screen coordinates
        """
        norm_x, norm_y = miller_projection(lat, lon)

        x = round(norm_x * (self.width - 1))
        y = round(norm_y * (self.height - 1))

        x = max(0, min(self.width - 1, x))
        y = max(0, min(self.height - 1, y))

        return (x, y)

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> bool:
        """
        Add threat marker and track clusters.

        Args:
            lat: Latitude
            lon: Longitude
            ip: IP address
            threat_score: Threat level (0-1)
            org_type: Organization type

        Returns:
            True if added, False if filtered (unknown location)
        """
        if not super().add_threat(lat, lon, ip, threat_score, org_type):
            return False

        marker = self.threats[-1]
        screen_pos = self.latlon_to_screen(lat, lon)
        self._clusters[screen_pos].append(marker)

        return True

    def clear_threats(self) -> None:
        """Clear threats and clusters."""
        super().clear_threats()
        self._clusters.clear()

    def resize(self, width: int, height: int) -> None:
        """Resize map and invalidate caches."""
        self.width = max(self.MIN_WIDTH, width)
        self.height = max(self.MIN_HEIGHT, height)
        self._base_cache = None
        self._cache_size = None
        self._clusters.clear()

    def _on_resize(self) -> None:
        """Invalidate cache on resize."""
        self._base_cache = None
        self._cache_size = None

    def render(self) -> Panel:
        """Render the flat world map."""
        try:
            return self._render_full()
        except Exception as e:
            logger.warning(f"Full render failed: {e}")
            return self._render_fallback()

    def _render_full(self) -> Panel:
        """Full layered rendering pipeline."""
        if self._cache_size != (self.width, self.height):
            self._base_cache = None
            self._cache_size = (self.width, self.height)

        canvas = [row[:] for row in self._get_base_map()]

        self._render_status(canvas)
        self._render_markers(canvas)
        self._render_labels(canvas)
        self._render_key(canvas)

        content = self._canvas_to_text(canvas)

        content.append("\n")
        content.append(self.format_stats_line(), style="dim")

        return Panel(
            content,
            title="[bold cyan]World Threat Map[/bold cyan]",
            border_style="cyan"
        )

    def _render_fallback(self) -> Panel:
        """Minimal fallback rendering."""
        lines = [
            "[dim]Map rendering unavailable[/dim]",
            "",
            f"Status: {self.get_status_text()}",
            f"Threats: {len(self.threats)}",
        ]

        if self._unknown_count > 0:
            lines.append(f"Unknown locations: {int_to_roman(self._unknown_count)}")

        return Panel(
            "\n".join(lines),
            title="[bold cyan]World Threat Map[/bold cyan]",
            border_style="yellow"
        )

    def _get_base_map(self) -> List[List]:
        """Get or create cached base map."""
        if self._base_cache and self._cache_size == (self.width, self.height):
            return self._base_cache

        self._base_cache = self._render_terrain()
        self._cache_size = (self.width, self.height)
        return self._base_cache

    def _render_terrain(self) -> List[List]:
        """Render base terrain with land, ocean, and coastlines."""
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        if not self._geo:
            self._draw_grid(canvas)
            return canvas

        # Build the map in layers: ocean base, land fill, coastline edges
        self._draw_ocean(canvas)
        self._draw_land(canvas)
        self._draw_coastlines(canvas)

        return canvas

    def _draw_ocean(self, canvas: List[List]) -> None:
        """Fill canvas with uniform ocean."""
        for y in range(self.height):
            for x in range(self.width):
                canvas[y][x] = Text('~', style="dim blue")

    def _draw_land(self, canvas: List[List]) -> None:
        """Draw land masses with single character."""
        for y in range(self.height):
            for x in range(self.width):
                lat, lon = self._screen_to_latlon(x, y)
                if self._geo.is_land_at(lat, lon):
                    canvas[y][x] = Text('\u2592', style="dim green")  # ▒

    def _screen_to_latlon(self, x: int, y: int) -> Tuple[float, float]:
        """
        Convert screen coordinates back to latitude/longitude.

        Inverse of the Miller projection used in latlon_to_screen.
        """
        # Inverse of x normalization
        norm_x = x / max(1, self.width - 1)
        lon = norm_x * 360 - 180

        # Inverse of Miller y projection
        norm_y = y / max(1, self.height - 1)

        # Miller projection constants
        MILLER_MAX_LAT = 85
        MILLER_MAX_LAT_RAD = math.radians(MILLER_MAX_LAT)
        MILLER_Y_MAX = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * MILLER_MAX_LAT_RAD))
        MILLER_Y_RANGE = 2 * MILLER_Y_MAX

        # Inverse: y_raw = MILLER_Y_MAX - norm_y * MILLER_Y_RANGE
        y_raw = MILLER_Y_MAX - norm_y * MILLER_Y_RANGE

        # Inverse of Miller formula: lat = 2.5 * (atan(exp(y_raw / 1.25)) - pi/4)
        try:
            lat_rad = 2.5 * (math.atan(math.exp(y_raw / 1.25)) - math.pi / 4)
            lat = math.degrees(lat_rad)
            lat = max(-85, min(85, lat))
        except (ValueError, OverflowError):
            lat = 0

        return lat, lon

    def _draw_coastlines(self, canvas: List[List]) -> None:
        """Skip coastlines for minimal clean style."""
        pass  # Removed - land/ocean contrast is sufficient

    def _draw_grid(self, canvas: List[List]) -> None:
        """Draw latitude/longitude grid (fallback when no geo data)."""
        for lat in range(-60, 90, 30):
            _, y = self.latlon_to_screen(lat, 0)
            if 0 <= y < self.height:
                for x in range(0, self.width, 4):
                    if canvas[y][x] == ' ':
                        canvas[y][x] = Text('\u00b7', style="dim")

        for lon in range(-150, 180, 30):
            x, _ = self.latlon_to_screen(0, lon)
            if 0 <= x < self.width:
                for y in range(0, self.height, 2):
                    if canvas[y][x] == ' ':
                        canvas[y][x] = Text('\u00b7', style="dim")

    def _draw_line(self, canvas: List[List], x0: int, y0: int,
                   x1: int, y1: int, style: str, char: str = '\u25aa') -> None:
        """Draw line using DDA algorithm."""
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
                canvas[iy][ix] = Text(char, style=style)
            x += x_inc
            y += y_inc

    def _render_status(self, canvas: List[List]) -> None:
        """Render status indicator in upper-left corner."""
        status_text = self.get_status_text()
        status_style = self.get_status_style()

        for i, ch in enumerate(status_text):
            x = 1 + i
            if x < self.width:
                canvas[0][x] = Text(ch, style=status_style)

    def _render_markers(self, canvas: List[List]) -> None:
        """Render threat markers with inverse styling for visibility."""
        clustered = self._cluster_markers()

        for marker, count in clustered:
            x, y = self.latlon_to_screen(marker.lat, marker.lon)

            if 0 <= x < self.width and 0 <= y < self.height:
                char = get_threat_char(marker.threat_score)
                color = get_threat_color(marker.threat_score)

                if marker.org_type in ('tor', 'vpn'):
                    color = get_org_color(marker.org_type)

                # Inverse styling makes markers pop against any terrain
                canvas[y][x] = Text(char, style=f"reverse {color}")

    def _cluster_markers(self) -> List[Tuple[ThreatMarker, int]]:
        """
        Cluster overlapping markers at same screen position.

        Returns list of (representative_marker, cluster_count) tuples.
        Representative is the highest threat score in each cluster.
        """
        clustered = []

        for pos, markers in self._clusters.items():
            if not markers:
                continue
            representative = max(markers, key=lambda m: m.threat_score)
            clustered.append((representative, len(markers)))

        return clustered

    def _render_labels(self, canvas: List[List]) -> None:
        """Render IP labels for top threats."""
        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)[:10]

        occupied = set()

        for threat in sorted_threats:
            if threat.threat_score < 0.5:
                continue

            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            label = threat.ip[:15] if threat.ip else "?"
            label_x = x + 2
            label_y = y

            if label_x + len(label) >= self.width:
                label_x = x - len(label) - 1
            if label_x < 0:
                continue

            collision = False
            for i in range(len(label)):
                pos = (label_x + i, label_y)
                if pos in occupied:
                    collision = True
                    break
            if collision:
                continue

            style = get_threat_color(threat.threat_score)
            for i, ch in enumerate(label):
                lx = label_x + i
                if 0 <= lx < self.width and 0 <= label_y < self.height:
                    canvas[label_y][lx] = Text(ch, style=f"dim {style}")
                    occupied.add((lx, label_y))

    def _render_key(self, canvas: List[List]) -> None:
        """Render single-line legend at bottom."""
        y = self.height - 1
        x = 1

        # Legend items: (char, style, label)
        items = [
            ("\u2592", "dim green", "Land "),
            ("~", "dim blue", "Ocean "),
            ("\u2502", "dim", " "),
            ("\u25cf", "reverse bold red", "Crit "),
            ("\u25c9", "reverse bold yellow", "High "),
            ("\u25ef", "reverse yellow", "Med "),
            ("\u25cb", "reverse cyan", "Low "),
            ("\u00b7", "reverse green", "Info"),
        ]

        for char, style, label in items:
            if x < self.width - 1:
                canvas[y][x] = Text(char, style=style)
                x += 1
            for ch in label:
                if x < self.width - 1:
                    canvas[y][x] = Text(ch, style="dim")
                    x += 1

    def _canvas_to_text(self, canvas: List[List]) -> Text:
        """Convert canvas to Rich Text object."""
        content = Text()

        for row in canvas:
            for cell in row:
                if isinstance(cell, Text):
                    content.append_text(cell)
                else:
                    content.append(str(cell))
            content.append("\n")

        return content
