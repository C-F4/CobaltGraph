"""
Flat World Map Implementation
=============================

2D equirectangular projection world map with threat visualization.
Shows country boundaries, heatmap overlay, threat markers, and labels.

This is the primary map visualization, providing the most detailed view
of geographic threat distribution.
"""

import logging
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
    HEATMAP_GRADIENT,
    miller_projection,
    equirectangular_projection,
    CHAR_ASPECT_RATIO,
)
from .key import render_key_box

# Import geographic data
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
    Flat 2D world map with configurable projection.

    Features:
        - Country boundaries from GeoData module
        - Individual threat markers (configurable max)
        - Heatmap overlay showing threat concentration
        - IP labels for high-threat connections
        - Integrated compact legend
        - Status indicator with unknown location count
        - Miller or equirectangular projection options

    The map uses a layered rendering approach:
        1. Base map (country outlines, cached)
        2. Heatmap overlay
        3. Threat markers
        4. IP labels
        5. Legend/key
        6. Status indicator
    """

    MAP_TYPE = "FLAT"

    # Projection constants
    PROJECTION_EQUIRECT = "equirectangular"
    PROJECTION_MILLER = "miller"

    # Size constraints
    MIN_WIDTH = 40
    MAX_WIDTH = 300
    MIN_HEIGHT = 12
    MAX_HEIGHT = 80

    def __init__(self, width: int = 120, height: int = 25,
                 projection: str = "miller"):
        """
        Initialize flat world map.

        Args:
            width: Canvas width (40-300 characters)
            height: Canvas height (12-80 lines)
            projection: "miller" (default, less polar distortion) or "equirectangular"
        """
        self._projection = projection
        # Clamp dimensions
        width = max(self.MIN_WIDTH, min(self.MAX_WIDTH, width))
        height = max(self.MIN_HEIGHT, min(self.MAX_HEIGHT, height))

        super().__init__(width=width, height=height, max_threats=50)

        # Geographic data
        self._geo = GeoData() if GeoData else None
        self._world_map = self._geo.get_world_map_detailed() if self._geo else {}

        # Set status based on geo data availability
        if not self._geo:
            self._status = self.STATUS_DEGRADED
            self._init_error = "GeoData unavailable"
        elif not self._world_map:
            self._status = self.STATUS_DEGRADED
            self._init_error = "No map data"

        # Heatmap: 5-degree grid (72 lon x 36 lat cells) for better threat clustering
        self._heatmap: Dict[Tuple[int, int], float] = defaultdict(float)
        self._heatmap_max = 0.01
        self._heatmap_resolution = 5  # degrees per cell

        # Cluster tracking: screen_pos -> list of (ip, threat_score)
        self._clusters: Dict[Tuple[int, int], List[Tuple[str, float]]] = defaultdict(list)

        # Rendering cache
        self._base_map_cache: Optional[List[List]] = None
        self._cache_size: Tuple[int, int] = (width, height)

        logger.debug(f"FlatWorldMap initialized: {width}x{height}, geo={bool(self._geo)}")

    # =========================================================================
    # COORDINATE CONVERSION
    # =========================================================================

    def latlon_to_screen(self, lat: float, lon: float) -> Tuple[int, int]:
        """
        Convert latitude/longitude to screen coordinates.

        Uses Miller (default) or equirectangular projection based on config.
        Miller projection reduces polar distortion (Greenland appears more accurate).

        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)

        Returns:
            Tuple of (x, y) screen coordinates
        """
        # Use configured projection
        if self._projection == self.PROJECTION_MILLER:
            norm_x, norm_y = miller_projection(lat, lon)
        else:
            norm_x, norm_y = equirectangular_projection(lat, lon)

        # Map normalized coordinates to screen with round() to avoid bias
        x = round(norm_x * (self.width - 1))
        y = round(norm_y * (self.height - 1))

        # Clamp to screen bounds
        x = max(0, min(self.width - 1, x))
        y = max(0, min(self.height - 1, y))

        return (x, y)

    # =========================================================================
    # THREAT MANAGEMENT (override to add heatmap)
    # =========================================================================

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> bool:
        """
        Add threat marker and update heatmap.

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

        # Update heatmap grid with finer resolution - use floor for consistent assignment
        import math
        max_x = 360 // self._heatmap_resolution - 1
        max_y = 180 // self._heatmap_resolution - 1
        grid_x = math.floor((lon + 180) / self._heatmap_resolution)
        grid_y = math.floor((90 - lat) / self._heatmap_resolution)
        grid_x = max(0, min(max_x, grid_x))
        grid_y = max(0, min(max_y, grid_y))

        self._heatmap[(grid_x, grid_y)] += threat_score
        self._heatmap_max = max(self._heatmap_max, self._heatmap[(grid_x, grid_y)])

        # Track clusters for display
        screen_pos = self.latlon_to_screen(lat, lon)
        if screen_pos:
            self._clusters[screen_pos].append((ip, threat_score))

        return True

    def clear_threats(self) -> None:
        """Clear threats, heatmap, and clusters."""
        super().clear_threats()
        self._heatmap.clear()
        self._heatmap_max = 0.01
        self._clusters.clear()

    def get_cluster_count(self, x: int, y: int) -> int:
        """Get number of threats at screen position."""
        return len(self._clusters.get((x, y), []))

    # =========================================================================
    # RENDERING
    # =========================================================================

    def render(self) -> Panel:
        """
        Render the flat world map.

        Returns:
            Rich Panel with rendered map
        """
        try:
            return self._render_full()
        except Exception as e:
            logger.warning(f"Full render failed: {e}")
            return self._render_fallback()

    def _render_full(self) -> Panel:
        """Full layered rendering pipeline."""
        # Invalidate cache if size changed
        if self._cache_size != (self.width, self.height):
            self._base_map_cache = None
            self._cache_size = (self.width, self.height)

        # Create canvas from cached base map
        canvas = [row[:] for row in self._get_base_map()]

        # Render layers
        self._render_status(canvas)
        self._render_heatmap(canvas)
        self._render_markers(canvas)
        self._render_labels(canvas)
        self._render_key(canvas)

        # Convert to Rich Text
        content = self._canvas_to_text(canvas)

        # Add stats footer
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

    def _on_resize(self) -> None:
        """Invalidate cache on resize."""
        self._base_map_cache = None

    # =========================================================================
    # BASE MAP RENDERING
    # =========================================================================

    def _get_base_map(self) -> List[List]:
        """Get or create cached base map."""
        if self._base_map_cache is None:
            self._base_map_cache = self._create_base_map()
        return self._base_map_cache

    def _create_base_map(self) -> List[List]:
        """Create static base map with grid and country outlines."""
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw grid first (background)
        self._draw_grid(canvas)

        # Draw country boundaries
        if self._world_map:
            for country, points in self._world_map.items():
                self._draw_polygon(canvas, points, "dim cyan")

        return canvas

    def _draw_grid(self, canvas: List[List]) -> None:
        """Draw latitude/longitude grid."""
        # Horizontal lines (every 30 degrees latitude)
        for lat in range(-60, 90, 30):
            _, y = self.latlon_to_screen(lat, 0)
            if 0 <= y < self.height:
                for x in range(0, self.width, 4):
                    if canvas[y][x] == ' ':
                        canvas[y][x] = '·'

        # Vertical lines (every 30 degrees longitude)
        for lon in range(-150, 180, 30):
            x, _ = self.latlon_to_screen(0, lon)
            if 0 <= x < self.width:
                for y in range(0, self.height, 2):
                    if canvas[y][x] == ' ':
                        canvas[y][x] = '·'

    def _draw_polygon(self, canvas: List[List], points: List[Tuple[float, float]], style: str) -> None:
        """Draw polygon outline (country boundary)."""
        for i in range(len(points)):
            p1 = points[i]
            p2 = points[(i + 1) % len(points)]

            x1, y1 = self.latlon_to_screen(p1[0], p1[1])
            x2, y2 = self.latlon_to_screen(p2[0], p2[1])

            self._draw_line(canvas, x1, y1, x2, y2, style)

    def _draw_line(self, canvas: List[List], x0: int, y0: int, x1: int, y1: int, style: str) -> None:
        """Draw line using DDA algorithm."""
        # Skip trans-date-line segments (would draw across entire screen)
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
                if canvas[iy][ix] == ' ' or canvas[iy][ix] == '·':
                    canvas[iy][ix] = Text('░', style=style)
            x += x_inc
            y += y_inc

    # =========================================================================
    # OVERLAY RENDERING
    # =========================================================================

    def _render_status(self, canvas: List[List]) -> None:
        """Render status indicator in upper-left corner."""
        status_text = self.get_status_text()
        status_style = self.get_status_style()

        for i, ch in enumerate(status_text):
            x = 1 + i
            if x < self.width:
                canvas[0][x] = Text(ch, style=status_style)

    def _render_heatmap(self, canvas: List[List]) -> None:
        """Render heatmap overlay on empty cells."""
        if not self._heatmap:
            return

        res = self._heatmap_resolution
        for (grid_x, grid_y), intensity in self._heatmap.items():
            # Convert grid to screen coordinates (center of cell)
            lon = grid_x * res - 180 + res / 2
            lat = 90 - grid_y * res - res / 2

            x, y = self.latlon_to_screen(lat, lon)

            # Skip if outside bounds or cell occupied
            if not (0 <= x < self.width and 0 <= y < self.height):
                continue
            if isinstance(canvas[y][x], Text):
                continue
            if canvas[y][x] not in (' ', '·', '░'):
                continue

            # Calculate intensity level
            normalized = intensity / max(self._heatmap_max, 0.01)
            level = min(3, int(normalized * 4))

            char, style = HEATMAP_GRADIENT[level]
            canvas[y][x] = Text(char, style=style)

    def _render_markers(self, canvas: List[List]) -> None:
        """Render individual threat markers."""
        for threat in self.threats:
            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            if 0 <= x < self.width and 0 <= y < self.height:
                char = get_threat_char(threat.threat_score)
                color = get_threat_color(threat.threat_score)

                # Use org color for certain types
                if threat.org_type in ('tor', 'vpn'):
                    color = get_org_color(threat.org_type)

                canvas[y][x] = Text(char, style=color)

    def _render_labels(self, canvas: List[List]) -> None:
        """Render IP labels for top threats."""
        # Sort by threat score and take top 10
        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)[:10]

        occupied = set()

        # Reserve key area
        key_x1 = self.width - 18
        key_y1 = self.height - 8

        for threat in sorted_threats:
            if threat.threat_score < 0.5:
                continue

            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            # Find label position (try right, then left)
            label = threat.ip[:15] if threat.ip else "?"
            label_x = x + 2
            label_y = y

            # Check bounds and key overlap
            if label_x + len(label) >= self.width:
                label_x = x - len(label) - 1
            if label_x >= key_x1 and label_y >= key_y1:
                continue

            # Check collision
            collision = False
            for i in range(len(label)):
                pos = (label_x + i, label_y)
                if pos in occupied:
                    collision = True
                    break
            if collision:
                continue

            # Render label
            style = get_threat_color(threat.threat_score)
            for i, ch in enumerate(label):
                lx = label_x + i
                if 0 <= lx < self.width and 0 <= label_y < self.height:
                    canvas[label_y][lx] = Text(ch, style=f"dim {style}")
                    occupied.add((lx, label_y))

    def _render_key(self, canvas: List[List]) -> None:
        """Render legend in bottom-right corner."""
        key_lines = render_key_box(width=16, include_verification=False)

        start_x = self.width - 18
        start_y = self.height - len(key_lines) - 1

        for i, (text, style) in enumerate(key_lines):
            y = start_y + i
            if y >= self.height:
                break

            for j, ch in enumerate(text):
                x = start_x + j
                if x < self.width:
                    canvas[y][x] = Text(ch, style=style or "dim")

    # =========================================================================
    # OUTPUT CONVERSION
    # =========================================================================

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
