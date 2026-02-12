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

    # Size constraints (minimal to fit any panel size)
    MIN_WIDTH = 20
    MIN_HEIGHT = 6

    # Reserved rows for legend/UI elements (keeps southern regions visible)
    LEGEND_ROWS = 1

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

    @property
    def map_height(self) -> int:
        """Effective map height excluding legend rows."""
        return max(self.MIN_HEIGHT - self.LEGEND_ROWS, self.height - self.LEGEND_ROWS)

    def latlon_to_screen(self, lat: float, lon: float) -> Tuple[int, int]:
        """
        Convert latitude/longitude to screen coordinates using Miller projection.

        Uses land-centric centering and cropped latitude range (MIN_LAT to MAX_LAT)
        for better landmass visualization.

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)

        Returns:
            Tuple of (x, y) screen coordinates
        """
        # Land-centric longitude mapping
        adjusted_lon = lon - self.CENTER_LON + self.LON_RANGE / 2
        # Normalize to 0-LON_RANGE range
        while adjusted_lon < 0:
            adjusted_lon += 360
        while adjusted_lon > self.LON_RANGE:
            adjusted_lon -= 360

        norm_x = adjusted_lon / self.LON_RANGE

        # Cropped Miller projection for Y
        # Clamp latitude to our display range
        lat_clamped = max(self.MIN_LAT, min(self.MAX_LAT, lat))
        lat_rad = math.radians(lat_clamped)

        # Miller projection Y values at our latitude bounds
        max_lat_rad = math.radians(self.MAX_LAT)
        min_lat_rad = math.radians(self.MIN_LAT)
        y_at_max = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * max_lat_rad))
        y_at_min = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * min_lat_rad))
        y_range = y_at_max - y_at_min

        # Current latitude in Miller projection space
        y_raw = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * lat_rad))

        # Normalize to [0, 1] within our cropped range
        norm_y = (y_at_max - y_raw) / y_range

        x = round(norm_x * (self.width - 1))
        y = round(norm_y * (self.map_height - 1))

        x = max(0, min(self.width - 1, x))
        y = max(0, min(self.map_height - 1, y))

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
        # Use normalized marker coords (not original) to match _render_markers
        screen_pos = self.latlon_to_screen(marker.lat, marker.lon)
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
        # Rebuild clusters with new screen positions after resize
        self._rebuild_clusters()

    def _rebuild_clusters(self) -> None:
        """Rebuild cluster dict from existing threats (needed after resize)."""
        self._clusters.clear()
        for marker in self.threats:
            screen_pos = self.latlon_to_screen(marker.lat, marker.lon)
            self._clusters[screen_pos].append(marker)

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

        # Stats line (no extra newline - canvas already ends with newline)
        content.append(self.format_stats_line(), style="dim")

        return Panel(
            content,
            title="[bold cyan]World Threat Map[/bold cyan]",
            border_style="cyan",
            padding=0,  # No internal padding - use full space
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
        """Fill map area with uniform ocean (reserve legend rows)."""
        for y in range(self.map_height):
            for x in range(self.width):
                canvas[y][x] = Text('~', style="dim blue")

    def _draw_land(self, canvas: List[List]) -> None:
        """Draw land masses with single character."""
        for y in range(self.map_height):
            for x in range(self.width):
                lat, lon = self._screen_to_latlon(x, y)
                if self._geo.is_land_at(lat, lon):
                    canvas[y][x] = Text('\u2592', style="dim green")  # ▒

    # Land-centric map: shift center to minimize Pacific Ocean visibility
    # Center on 10°E puts Atlantic in center, splits Pacific at edges
    CENTER_LON = 10  # Degrees East - optimal for showing populated continents
    LON_RANGE = 340  # Show 340° of longitude (crops 20° of empty Pacific)

    # Latitude range: crop to -65° to focus on populated landmasses
    # This removes most of empty Southern Ocean while keeping key landmasses
    MIN_LAT = -65  # Southern limit (includes South America, Australia, New Zealand)
    MAX_LAT = 85   # Northern limit (includes Arctic regions)

    def _screen_to_latlon(self, x: int, y: int) -> Tuple[float, float]:
        """
        Convert screen coordinates back to latitude/longitude.

        Uses land-centric centering and cropped latitude range for better
        landmass visualization (MIN_LAT to MAX_LAT instead of full ±85°).
        """
        # Land-centric longitude mapping
        # Maps screen x to longitude range centered on CENTER_LON
        norm_x = x / max(1, self.width - 1)
        half_range = self.LON_RANGE / 2
        lon = self.CENTER_LON - half_range + norm_x * self.LON_RANGE
        # Normalize to -180 to 180
        while lon > 180:
            lon -= 360
        while lon < -180:
            lon += 360

        # Cropped Miller projection for latitude
        # Maps screen y to latitude range [MAX_LAT, MIN_LAT] using Miller projection
        norm_y = y / max(1, self.map_height - 1)

        # Miller projection Y values at our latitude bounds
        max_lat_rad = math.radians(self.MAX_LAT)
        min_lat_rad = math.radians(self.MIN_LAT)
        y_at_max = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * max_lat_rad))
        y_at_min = 1.25 * math.log(math.tan(math.pi / 4 + 0.4 * min_lat_rad))
        y_range = y_at_max - y_at_min

        # Interpolate in Miller projection space
        y_raw = y_at_max - norm_y * y_range

        # Inverse Miller formula
        try:
            lat_rad = 2.5 * (math.atan(math.exp(y_raw / 1.25)) - math.pi / 4)
            lat = math.degrees(lat_rad)
            lat = max(self.MIN_LAT, min(self.MAX_LAT, lat))
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
            if 0 <= y < self.map_height:
                for x in range(0, self.width, 4):
                    if canvas[y][x] == ' ':
                        canvas[y][x] = Text('\u00b7', style="dim")

        for lon in range(-150, 180, 30):
            x, _ = self.latlon_to_screen(0, lon)
            if 0 <= x < self.width:
                for y in range(0, self.map_height, 2):
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
            if 0 <= ix < self.width and 0 <= iy < self.map_height:
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

            if 0 <= x < self.width and 0 <= y < self.map_height:
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

        # Pre-populate occupied set with marker positions to prevent label overwrites
        occupied = set()
        for marker, _ in self._cluster_markers():
            pos = self.latlon_to_screen(marker.lat, marker.lon)
            if pos:
                occupied.add(pos)

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
                if 0 <= lx < self.width and 0 <= label_y < self.map_height:
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
