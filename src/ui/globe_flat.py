#!/usr/bin/env python3
"""
Flat 2D World Map Threat Visualization
Shows actual continents and countries on equirectangular projection
with real-time threat connection markers, heatmap overlay, and IP labels
"""

import math
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List, Set
from rich.panel import Panel
from rich.text import Text

try:
    from src.ui.geo_data import GeoData
except ImportError:
    from geo_data import GeoData


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
    Flat 2D world map visualization using equirectangular projection
    Shows:
    - 30 major countries with recognizable boundaries
    - Individual threat markers (top 50)
    - Heatmap overlay showing threat concentration
    - IP addresses and threat scores for top 10-15
    """

    def __init__(self, width: int = 140, height: int = 30):
        self.width = width
        self.height = height
        self.time_elapsed = 0.0
        self.frame_count = 0

        # Threat tracking
        self.threats: deque = deque(maxlen=50)
        self.threat_map: Dict[Tuple[int, int], ThreatPin] = {}

        # Geographic data
        self.geo = GeoData()
        self.world_map = self.geo.get_world_map_detailed()

        # Heatmap: 10° grid (36 lon × 18 lat)
        self.heatmap: Dict[Tuple[int, int], float] = defaultdict(float)
        self.heatmap_max = 0.01  # Start low for proper gradient normalization

        # Rendering cache
        self._base_map_cache = None
        self._last_cache_time = 0.0

        # Org type colors
        self.org_colors = {
            'cloud': 'cyan',
            'cdn': 'cyan',
            'hosting': 'blue',
            'isp': 'magenta',
            'vpn': 'bold magenta',
            'tor': 'bold red',
            'enterprise': 'bold green',
            'government': 'bold blue',
            'education': 'green',
            'unknown': 'dim white',
        }

    def add_threat(self, lat: float, lon: float, ip: str,
                   threat_score: float, org_type: str) -> None:
        """Add a threat marker to the map"""
        pin = ThreatPin(lat, lon, threat_score, org_type, ip)
        self.threats.append(pin)

        # Track in map for fast lookup
        x, y = self.latlon_to_screen(lat, lon)
        self.threat_map[(x, y)] = pin

        # Update heatmap (10° grid aggregation)
        grid_x = int((lon + 180) / 10)
        grid_y = int((90 - lat) / 10)
        grid_x = max(0, min(35, grid_x))
        grid_y = max(0, min(17, grid_y))

        self.heatmap[(grid_x, grid_y)] += threat_score
        self.heatmap_max = max(self.heatmap_max, self.heatmap[(grid_x, grid_y)])

    def latlon_to_screen(self, lat: float, lon: float) -> Tuple[int, int]:
        """
        Convert lat/lon to screen coordinates using equirectangular projection
        """
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

    def get_threat_char(self, score: float) -> str:
        """Get character for threat intensity"""
        if score >= 0.8:
            return "●"
        elif score >= 0.6:
            return "◉"
        elif score >= 0.4:
            return "◯"
        elif score >= 0.2:
            return "○"
        else:
            return "·"

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
            logger = __import__('logging').getLogger(__name__)
            logger.warning(f"Full map render failed: {e}")
            try:
                return self._render_text_fallback()
            except:
                return Panel(
                    "[dim]Globe rendering failed[/dim]",
                    title="[bold cyan]🌍 World Threat Map[/bold cyan]",
                    border_style="cyan"
                )

    def _render_full_map(self) -> Panel:
        """Full rendering pipeline: base map + layers"""
        # Create canvas (copy cached base map)
        canvas = [row[:] for row in self._get_base_map_cache()]

        # Layer 2: Heatmap overlay
        self._render_heatmap(canvas)

        # Layer 3: Individual threat markers
        self._render_markers(canvas)

        # Layer 4: IP address labels
        self._render_labels(canvas)

        # Layer 5: Legend (bottom-right corner)
        self._render_legend(canvas)

        # Convert to Rich Text object (preserves all styles)
        content = self._canvas_to_text(canvas)

        # Add stats footer
        threat_count = len(self.threats)
        high_threat = sum(1 for t in self.threats if t.threat_score >= 0.7)
        critical = sum(1 for t in self.threats if t.threat_score >= 0.8)

        # Append stats to content Text object
        content.append(f"\n")
        content.append(f"Threats: {threat_count} | Critical: {critical} | High: {high_threat} | Time: {self.time_elapsed:.1f}s", style="dim")

        return Panel(
            content,
            title="[bold cyan]🌍 World Threat Map[/bold cyan]",
            border_style="cyan"
        )

    def _get_base_map_cache(self) -> List[List]:
        """Get or create cached base map"""
        if self._base_map_cache is None:
            self._base_map_cache = self._render_base_map()
        return self._base_map_cache

    def _render_base_map(self) -> List[List]:
        """Render static base map (continents + grid) once and cache"""
        canvas = [[' ' for _ in range(self.width)] for _ in range(self.height)]

        # Draw country boundaries
        self._draw_countries(canvas)

        # Draw lat/lon grid
        self._draw_grid(canvas)

        return canvas

    def _draw_countries(self, canvas: List[List]) -> None:
        """Draw country boundaries on canvas"""
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
                if isinstance(canvas[iy][ix], str) and canvas[iy][ix] == ' ':
                    canvas[iy][ix] = Text('─', style=style)
            x += x_inc
            y += y_inc

    def _draw_grid(self, canvas: List[List]) -> None:
        """Draw latitude/longitude grid lines"""
        # Vertical lines (longitude every 30°)
        for lon in range(-180, 180, 30):
            x, _ = self.latlon_to_screen(0, lon)
            if 0 <= x < self.width:
                for y in range(self.height):
                    if isinstance(canvas[y][x], str) and canvas[y][x] == ' ':
                        canvas[y][x] = Text('│', style="dim black")

        # Horizontal lines (latitude every 20°)
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

        # Colors: yellow → red gradient
        heatmap_colors = [
            'yellow', 'bold yellow', 'yellow',
            'bold red', 'bold red', 'bold red', 'bold red', 'bold red'
        ]

        # Render each heatmap cell
        for (gx, gy), score in self.heatmap.items():
            if score == 0:
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

            # Only render if currently empty (don't overwrite boundaries/markers)
            if isinstance(canvas[y][x], str) and canvas[y][x] == ' ':
                canvas[y][x] = Text(char, style=color)

    def _render_markers(self, canvas: List[List]) -> None:
        """Render individual threat markers"""
        for threat in self.threats:
            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            char = self.get_threat_char(threat.threat_score)
            color = self.get_threat_color(threat.threat_score)

            canvas[y][x] = Text(char, style=color)

    def _render_labels(self, canvas: List[List]) -> None:
        """Render IP addresses and threat scores for top threats"""
        # Sort by threat score (descending) and take top 15
        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)[:15]

        for threat in sorted_threats:
            x, y = self.latlon_to_screen(threat.lat, threat.lon)

            # Format: "●0.82" (symbol + score)
            label = f"{self.get_threat_char(threat.threat_score)}{threat.threat_score:.2f}"

            # Try to place label with offsets to avoid overlap
            offsets = [
                (3, 0),           # Right
                (0, 1),           # Below
                (-len(label), 0), # Left
                (0, -1),          # Above
                (3, 1),           # Diagonal right-down
                (3, -1),          # Diagonal right-up
                (-len(label), 1), # Diagonal left-down
                (-len(label), -1),# Diagonal left-up
                (5, 0),           # Far right
                (0, 2),           # Far below
            ]

            placed = False
            for dx, dy in offsets:
                lx = x + dx
                ly = y + dy

                # Check if position is valid and empty
                if 0 <= lx < self.width - len(label) and 0 <= ly < self.height:
                    # Check if space is available
                    can_place = all(
                        isinstance(canvas[ly][lx + i], str) and canvas[ly][lx + i] in (' ', '─', '│')
                        for i in range(len(label))
                    )

                    if can_place:
                        # Place label
                        color = self.get_threat_color(threat.threat_score)
                        for i, ch in enumerate(label):
                            canvas[ly][lx + i] = Text(ch, style=color)
                        placed = True
                        break

    def _render_legend(self, canvas: List[List]) -> None:
        """Render legend box in bottom-right corner"""
        # Legend dimensions
        legend_width = 18
        legend_height = 10
        start_x = self.width - legend_width - 1
        start_y = self.height - legend_height - 1

        # Only render if there's space
        if start_x < 0 or start_y < 0:
            return

        # Draw legend box border
        # Top border
        for x in range(start_x, min(start_x + legend_width, self.width)):
            if isinstance(canvas[start_y][x], str) and canvas[start_y][x] == ' ':
                canvas[start_y][x] = Text('─', style='dim cyan')

        # Bottom border
        end_y = min(start_y + legend_height - 1, self.height - 1)
        for x in range(start_x, min(start_x + legend_width, self.width)):
            if isinstance(canvas[end_y][x], str) and canvas[end_y][x] == ' ':
                canvas[end_y][x] = Text('─', style='dim cyan')

        # Side borders
        for y in range(start_y, end_y + 1):
            if start_x >= 0:
                if isinstance(canvas[y][start_x], str) and canvas[y][start_x] == ' ':
                    canvas[y][start_x] = Text('│', style='dim cyan')

            end_x = min(start_x + legend_width - 1, self.width - 1)
            if end_x < self.width:
                if isinstance(canvas[y][end_x], str) and canvas[y][end_x] == ' ':
                    canvas[y][end_x] = Text('│', style='dim cyan')

        # Legend content rows
        legend_lines = [
            ("Threat Level:", None),
            ("●=Critical  ◉=High", "bold red"),
            ("◯=Medium   ○=Low", "yellow"),
            ("·=Info", "green"),
            ("", None),
            ("Heatmap:", None),
            ("▇▆▅▄ = Intensity", "bold red"),
        ]

        # Render legend content
        content_start_x = start_x + 2
        content_y = start_y + 1

        for line_text, style in legend_lines:
            if content_y >= end_y:
                break

            # Render each character
            for i, ch in enumerate(line_text):
                x = content_start_x + i
                if x < self.width - 1 and content_y < self.height:
                    if isinstance(canvas[content_y][x], str) and canvas[content_y][x] in (' ', '─', '│'):
                        if style:
                            canvas[content_y][x] = Text(ch, style=style)
                        else:
                            canvas[content_y][x] = Text(ch, style='dim white')

            content_y += 1

    def _canvas_to_text(self, canvas: List[List]) -> Text:
        """Convert canvas to formatted Rich Text with proper styling preserved"""
        result = Text()
        for row_idx, row in enumerate(canvas):
            for cell in row:
                if isinstance(cell, Text):
                    result.append_text(cell)
                else:
                    result.append(str(cell))
            # Add newline between rows (except after last row)
            if row_idx < len(canvas) - 1:
                result.append("\n")
        return result

    def _render_text_fallback(self) -> Panel:
        """Fallback text-based rendering"""
        lines = []
        lines.append("[bold cyan]THREAT MAP (Text Mode)[/bold cyan]")
        lines.append("")

        # Sort and display threats
        sorted_threats = sorted(self.threats, key=lambda t: t.threat_score, reverse=True)
        for i, threat in enumerate(sorted_threats[:20]):
            color = self.get_threat_color(threat.threat_score)
            lines.append(f"[{color}]{threat.ip:15s}[/{color}] {threat.threat_score:.2f} - {threat.org_type}")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold cyan]🌍 World Threat Map[/bold cyan]",
            border_style="cyan"
        )

    def clear_threats(self) -> None:
        """Clear all threats"""
        self.threats.clear()
        self.threat_map.clear()
        self.heatmap.clear()
        self.heatmap_max = 0.01

    def resize(self, width: int, height: int) -> None:
        """Resize the map and clear cache for dynamic panel adjustment."""
        self.width = max(40, min(width, 300))
        self.height = max(12, min(height, 80))
        self._base_map_cache = None  # Force recache on next render
