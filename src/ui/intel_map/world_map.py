"""
Flat 2D World Map Threat Visualization
Equirectangular projection with threat markers, heatmap overlay, and integrated key.
"""

import logging
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List
from rich.panel import Panel
from rich.text import Text

from .key import get_threat_char, get_threat_color, ORG_TYPE_COLORS, render_key_box

try:
    from src.ui.geo_data import GeoData
except ImportError:
    try:
        from ..geo_data import GeoData
    except ImportError:
        GeoData = None

logger = logging.getLogger(__name__)


@dataclass
class ThreatPin:
    """A threat marker on the map"""
    lat: float
    lon: float
    threat_score: float
    org_type: str
    ip: str
    age: float = 0.0


class FlatWorldMap:
    """
    Flat 2D world map visualization using equirectangular projection.

    Features:
    - Country boundaries from GeoData
    - Individual threat markers (top 50)
    - Heatmap overlay showing threat concentration
    - Integrated compact key/legend
    - Label placement for top threats
    - Status indicator for debugging
    """

    MAP_TYPE = "FlatWorldMap"
    MAP_STATUS = "FULL"  # FULL or FALLBACK

    def __init__(self, width: int = 140, height: int = 30):
        self.width = max(40, min(width, 300))
        self.height = max(12, min(height, 80))
        self.time_elapsed = 0.0
        self.frame_count = 0

        # Threat tracking
        self.threats: deque = deque(maxlen=50)
        self.threat_map: Dict[Tuple[int, int], ThreatPin] = {}

        # Geographic data and status
        self.geo = GeoData() if GeoData else None
        self.world_map = self.geo.get_world_map_detailed() if self.geo else {}
        self._init_error = None

        # Track if we're in degraded mode
        if not self.geo:
            self._init_error = "GeoData unavailable"
            self.MAP_STATUS = "DEGRADED"
        elif not self.world_map:
            self._init_error = "No map data"
            self.MAP_STATUS = "DEGRADED"

        # Heatmap: 10 degree grid (36 lon x 18 lat cells)
        self.heatmap: Dict[Tuple[int, int], float] = defaultdict(float)
        self.heatmap_max = 0.01  # Start low for proper gradient

        # Rendering cache
        self._base_map_cache = None
        self._last_size = (width, height)

    def add_threat(self, lat: float, lon: float, ip: str,
                   threat_score: float, org_type: str) -> None:
        """Add a threat marker to the map"""
        pin = ThreatPin(lat, lon, threat_score, org_type, ip)
        self.threats.append(pin)

        # Track in map for fast lookup
        x, y = self.latlon_to_screen(lat, lon)
        self.threat_map[(x, y)] = pin

        # Update heatmap (10 degree grid aggregation)
        grid_x = int((lon + 180) / 10)
        grid_y = int((90 - lat) / 10)
        grid_x = max(0, min(35, grid_x))
        grid_y = max(0, min(17, grid_y))

        self.heatmap[(grid_x, grid_y)] += threat_score
        self.heatmap_max = max(self.heatmap_max, self.heatmap[(grid_x, grid_y)])

    def latlon_to_screen(self, lat: float, lon: float) -> Tuple[int, int]:
        """Convert lat/lon to screen coordinates using equirectangular projection"""
        # Clamp lat/lon to valid ranges
        lat = max(-85, min(85, lat))
        lon = (lon + 180) % 360 - 180

        # Simple linear mapping
        x = int((lon + 180) / 360 * (self.width - 1))
        y = int((90 - lat) / 180 * (self.height - 1))

        # Clamp to screen bounds
        x = max(0, min(self.width - 1, x))
        y = max(0, min(self.height - 1, y))

        return (x, y)

    def update(self, dt: float = 0.1) -> None:
        """Update state and age threats"""
        self.time_elapsed += dt
        self.frame_count += 1

        # Age threats
        for threat in self.threats:
            threat.age += dt

    def render(self) -> Panel:
        """Render the flat world map with all layers"""
        try:
            return self._render_full_map()
        except Exception as e:
            logger.warning(f"Full map render failed: {e}")
            try:
                return self._render_text_fallback()
            except Exception:
                return Panel(
                    "[dim]Globe rendering failed[/dim]",
                    title="[bold cyan]World Threat Map[/bold cyan]",
                    border_style="cyan"
                )

    def _render_full_map(self) -> Panel:
        """Full rendering pipeline: base map + layers"""
        # Invalidate cache if size changed
        if self._last_size != (self.width, self.height):
            self._base_map_cache = None
            self._last_size = (self.width, self.height)

        # Create canvas (copy cached base map)
        canvas = [row[:] for row in self._get_base_map_cache()]

        # Layer 1: Status indicator (upper-left corner for debugging)
        self._render_status_indicator(canvas)

        # Layer 2: Heatmap overlay (only on empty cells)
        self._render_heatmap(canvas)

        # Layer 3: Individual threat markers (always on top)
        self._render_markers(canvas)

        # Layer 4: IP address labels for top threats
        self._render_labels(canvas)

        # Layer 5: Integrated key (bottom-right corner)
        self._render_key(canvas)

        # Convert to Rich Text object
        content = self._canvas_to_text(canvas)

        # Add compact stats footer
        threat_count = len(self.threats)
        critical = sum(1 for t in self.threats if t.threat_score >= 0.8)
        high = sum(1 for t in self.threats if 0.6 <= t.threat_score < 0.8)

        content.append(f"\n")
        content.append(f"[{threat_count}] ", style="dim")
        if critical > 0:
            content.append(f"Crit:{critical} ", style="bold red")
        if high > 0:
            content.append(f"High:{high} ", style="bold yellow")
        content.append(f"T:{self.time_elapsed:.0f}s", style="dim")

        return Panel(
            content,
            title="[bold cyan]World Threat Map[/bold cyan]",
            border_style="cyan"
        )

    def _get_base_map_cache(self) -> List[List]:
        """Get or create cached base map"""
        if self._base_map_cache is None:
            self._base_map_cache = self._render_base_map()
        return self._base_map_cache

    def _render_base_map(self) -> List[List]:
        """Render static base map (continents + grid) and cache"""
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw lat/lon grid first (background)
        self._draw_grid(canvas)

        # Draw country boundaries on top
        self._draw_countries(canvas)

        return canvas

    def _draw_countries(self, canvas: List[List]) -> None:
        """Draw country boundaries on canvas"""
        if not self.world_map:
            return

        for country_name, points in self.world_map.items():
            self._draw_polygon(canvas, points, "dim cyan")

    def _draw_polygon(self, canvas: List[List], points: List[Tuple[float, float]], style: str) -> None:
        """Draw polygon outline (country boundary)"""
        for i in range(len(points)):
            p1 = points[i]
            p2 = points[(i + 1) % len(points)]

            x1, y1 = self.latlon_to_screen(p1[0], p1[1])
            x2, y2 = self.latlon_to_screen(p2[0], p2[1])

            self._draw_line(canvas, (x1, y1), (x2, y2), style)

    def _draw_line(self, canvas: List[List], start: Tuple[int, int],
                   end: Tuple[int, int], style: str) -> None:
        """Draw line using DDA algorithm"""
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
                # Only draw on empty or grid cells
                if isinstance(cell, str) and cell in (' ', '│', '─'):
                    canvas[iy][ix] = Text('─', style=style)
            x += x_inc
            y += y_inc

    def _draw_grid(self, canvas: List[List]) -> None:
        """Draw latitude/longitude grid lines"""
        # Vertical lines (longitude every 30 degrees)
        for lon in range(-180, 180, 30):
            x, _ = self.latlon_to_screen(0, lon)
            if 0 <= x < self.width:
                for y in range(self.height):
                    if isinstance(canvas[y][x], str) and canvas[y][x] == ' ':
                        canvas[y][x] = Text('│', style="dim black")

        # Horizontal lines (latitude every 20 degrees)
        for lat in range(-60, 61, 20):
            _, y = self.latlon_to_screen(lat, 0)
            if 0 <= y < self.height:
                for x in range(self.width):
                    if isinstance(canvas[y][x], str) and canvas[y][x] == ' ':
                        canvas[y][x] = Text('─', style="dim black")

    def _render_heatmap(self, canvas: List[List]) -> None:
        """Render heatmap overlay showing threat concentration"""
        if not self.heatmap:
            return

        # Heatmap block characters (8 levels)
        heatmap_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']

        # Colors: green -> yellow -> red gradient
        heatmap_colors = [
            'green', 'cyan', 'cyan', 'yellow',
            'bold yellow', 'bold yellow', 'bold red', 'bold red'
        ]

        # Render each heatmap cell
        for (gx, gy), score in self.heatmap.items():
            if score <= 0:
                continue

            # Normalize score to 0-1
            norm_score = min(1.0, score / self.heatmap_max) if self.heatmap_max > 0 else 0

            # Get character and color
            char_idx = int(norm_score * (len(heatmap_chars) - 1))
            char = heatmap_chars[char_idx]
            color = heatmap_colors[char_idx]

            # Map grid cell to screen position (center of cell)
            lat = 90 - (gy + 0.5) * 10
            lon = (gx + 0.5) * 10 - 180

            x, y = self.latlon_to_screen(lat, lon)

            # Only render on empty cells (preserve boundaries and markers)
            if 0 <= y < self.height and 0 <= x < self.width:
                cell = canvas[y][x]
                if isinstance(cell, str) and cell == ' ':
                    canvas[y][x] = Text(char, style=color)

    def _render_markers(self, canvas: List[List]) -> None:
        """Render individual threat markers"""
        for threat in self.threats:
            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            if 0 <= x < self.width and 0 <= y < self.height:
                char = get_threat_char(threat.threat_score)
                color = get_threat_color(threat.threat_score)

                # Org type can influence color for certain types
                if threat.org_type in ('tor', 'vpn'):
                    color = ORG_TYPE_COLORS.get(threat.org_type, color)

                canvas[y][x] = Text(char, style=color)

    def _render_status_indicator(self, canvas: List[List]) -> None:
        """Render map status indicator in upper-left corner for debugging"""
        # Status text based on map state
        if self.MAP_STATUS == "FULL":
            status_text = f"[{self.MAP_TYPE}]"
            status_style = "dim green"
        else:
            error_info = self._init_error or "Unknown"
            status_text = f"[{self.MAP_TYPE}:DEGRADED:{error_info[:12]}]"
            status_style = "dim yellow"

        # Render at position (1, 0) - upper left, slight offset from edge
        start_x = 1
        start_y = 0

        for i, ch in enumerate(status_text):
            x = start_x + i
            if x < self.width and start_y < self.height:
                canvas[start_y][x] = Text(ch, style=status_style)

    def _get_key_bounds(self) -> tuple:
        """Get the bounding box for the key area to prevent overlap"""
        key_width = 16
        key_height = 6
        start_x = self.width - key_width - 2
        start_y = self.height - key_height - 1
        return (start_x, start_y, start_x + key_width, start_y + key_height)

    def _render_labels(self, canvas: List[List]) -> None:
        """Render IP addresses and threat scores for top threats"""
        # Sort by threat score (descending) and take top 15
        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)[:15]

        # Track occupied positions to avoid overlaps
        occupied = set()

        # Reserve key area to prevent label overlap
        key_x1, key_y1, key_x2, key_y2 = self._get_key_bounds()
        for ky in range(max(0, key_y1), min(self.height, key_y2 + 1)):
            for kx in range(max(0, key_x1), min(self.width, key_x2 + 1)):
                occupied.add((kx, ky))

        for threat in sorted_threats:
            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            # Format: "0.82" (compact score)
            label = f"{threat.threat_score:.2f}"

            # Try to place label with offsets to avoid overlap
            offsets = [
                (2, 0),    # Right
                (0, 1),    # Below
                (-len(label) - 1, 0),  # Left
                (0, -1),   # Above
                (2, 1),    # Diagonal right-down
            ]

            for dx, dy in offsets:
                lx = x + dx
                ly = y + dy

                # Check bounds and availability
                if not (0 <= lx < self.width - len(label) and 0 <= ly < self.height):
                    continue

                # Check if space is available (no overlap with other labels or key)
                positions = [(lx + i, ly) for i in range(len(label))]
                if any(pos in occupied for pos in positions):
                    continue

                # Check underlying cells are not markers
                can_place = all(
                    isinstance(canvas[ly][lx + i], str) and canvas[ly][lx + i] in (' ', '─', '│')
                    for i in range(len(label))
                    if 0 <= lx + i < self.width
                )

                if can_place:
                    # Place label
                    color = get_threat_color(threat.threat_score)
                    for i, ch in enumerate(label):
                        if lx + i < self.width:
                            canvas[ly][lx + i] = Text(ch, style=f"dim {color}")
                            occupied.add((lx + i, ly))
                    break

    def _render_key(self, canvas: List[List]) -> None:
        """Render compact key in bottom-right corner with proper border"""
        # Key dimensions
        key_width = 16
        key_height = 6
        start_x = self.width - key_width - 2
        start_y = self.height - key_height - 1
        end_x = start_x + key_width - 1
        end_y = start_y + key_height - 1

        # Only render if there's space
        if start_x < 0 or start_y < 0:
            return

        # Key content
        key_lines = render_key_box()

        # Clear key area first (fix artifacts from underlying content)
        for y in range(start_y, min(end_y + 1, self.height)):
            for x in range(start_x, min(end_x + 1, self.width)):
                canvas[y][x] = ' '

        # Draw key box border with proper corners
        style = 'dim cyan'

        # Top border with corners
        if start_y >= 0 and start_y < self.height:
            canvas[start_y][start_x] = Text('┌', style=style)
            for x in range(start_x + 1, min(end_x, self.width)):
                canvas[start_y][x] = Text('─', style=style)
            if end_x < self.width:
                canvas[start_y][end_x] = Text('┐', style=style)

        # Bottom border with corners
        if end_y >= 0 and end_y < self.height:
            canvas[end_y][start_x] = Text('└', style=style)
            for x in range(start_x + 1, min(end_x, self.width)):
                canvas[end_y][x] = Text('─', style=style)
            if end_x < self.width:
                canvas[end_y][end_x] = Text('┘', style=style)

        # Side borders
        for y in range(start_y + 1, min(end_y, self.height)):
            if start_x >= 0:
                canvas[y][start_x] = Text('│', style=style)
            if end_x < self.width:
                canvas[y][end_x] = Text('│', style=style)

        # Render key content
        content_x = start_x + 1
        content_y = start_y + 1

        for line_text, line_style in key_lines[:key_height - 2]:
            if content_y >= end_y:
                break
            for i, ch in enumerate(line_text[:key_width - 2]):
                x = content_x + i
                if x < end_x and content_y < self.height:
                    if line_style:
                        canvas[content_y][x] = Text(ch, style=line_style)
                    else:
                        canvas[content_y][x] = Text(ch, style='dim white')
            content_y += 1

    def _canvas_to_text(self, canvas: List[List]) -> Text:
        """Convert canvas to formatted Rich Text"""
        result = Text()
        for row_idx, row in enumerate(canvas):
            for cell in row:
                if isinstance(cell, Text):
                    result.append_text(cell)
                else:
                    result.append(str(cell))
            if row_idx < len(canvas) - 1:
                result.append("\n")
        return result

    def _render_text_fallback(self) -> Panel:
        """Fallback text-based rendering when map fails"""
        lines = []
        lines.append("[bold cyan]THREAT MAP (Text Mode)[/bold cyan]")
        lines.append("")

        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)
        for threat in sorted_threats[:20]:
            color = get_threat_color(threat.threat_score)
            lines.append(f"[{color}]{threat.ip:15s}[/{color}] {threat.threat_score:.2f} - {threat.org_type}")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]World Threat Map[/bold cyan]",
            border_style="cyan"
        )

    def clear_threats(self) -> None:
        """Clear all threats"""
        self.threats.clear()
        self.threat_map.clear()
        self.heatmap.clear()
        self.heatmap_max = 0.01

    def resize(self, width: int, height: int) -> None:
        """Resize the map and clear cache"""
        self.width = max(40, min(width, 300))
        self.height = max(12, min(height, 80))
        self._base_map_cache = None
