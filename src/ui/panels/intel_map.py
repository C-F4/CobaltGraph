"""
Intel Map Panel
===============

Top-right panel displaying geographic threat visualization.
Wraps the maps module to provide a Textual widget interface.

Supports multiple map types with automatic fallback:
    - flat: Detailed world map (default)
    - rotating: Animated 3D globe
    - simple: Lightweight fallback
"""

import logging
from typing import Optional

from rich.panel import Panel
from textual.widgets import Static
from textual.reactive import reactive

from ..maps import (
    create_map,
    FlatWorldMap,
    RotatingGlobe,
    SimpleGlobe,
    is_unknown_location,
)

logger = logging.getLogger(__name__)


class IntelMapPanel(Static):
    """
    Geographic threat map visualization panel.

    Wraps map implementations from the maps module, providing:
        - Automatic map type selection with fallback
        - Connection data binding
        - Unknown location tracking (displayed as Roman numerals)
        - Map type cycling (for user preference)

    Attributes:
        globe_data: Reactive dict containing connections to display
        map_type: Current map type ('flat', 'rotating', 'simple')
    """

    DEFAULT_CSS = """
    IntelMapPanel {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    MAP_TYPES = ['flat', 'rotating', 'simple']

    globe_data = reactive(dict)

    def __init__(self, map_type: str = "flat", **kwargs):
        super().__init__(**kwargs)
        self._preferred_type = map_type
        self._current_type = map_type
        self._map = None
        self._unknown_ips: set = set()
        self._map_width = 120
        self._map_height = 30

        self.globe_data = {
            'connections': [],
            'heatmap': {},
        }

        self._init_map()

    def _init_map(self) -> None:
        """Initialize the map implementation."""
        self._map = create_map(
            map_type=self._preferred_type,
            width=self._map_width,
            height=self._map_height,
            fallback=True
        )

        if self._map:
            self._current_type = self._map.MAP_TYPE.lower()
            logger.debug(f"IntelMapPanel using {self._current_type} map ({self._map_width}x{self._map_height})")
        else:
            logger.warning("IntelMapPanel: No map implementation available")

    def cycle_map_type(self) -> str:
        """
        Cycle to the next available map type.

        Returns:
            Name of the new active map type
        """
        if not self._map:
            return "none"

        try:
            idx = self.MAP_TYPES.index(self._current_type)
        except ValueError:
            idx = 0

        for i in range(1, len(self.MAP_TYPES) + 1):
            next_type = self.MAP_TYPES[(idx + i) % len(self.MAP_TYPES)]
            new_map = create_map(next_type, width=self.width, height=self.height, fallback=False)

            if new_map:
                self._map = new_map
                self._current_type = next_type
                self._reapply_data()
                self.refresh()
                return next_type

        return self._current_type

    @property
    def current_map_type(self) -> str:
        """Get current map type name."""
        return self._current_type

    @property
    def width(self) -> int:
        """Get current map width."""
        return self._map.width if self._map else self._map_width

    @property
    def height(self) -> int:
        """Get current map height."""
        return self._map.height if self._map else self._map_height

    def watch_globe_data(self, new_data: dict) -> None:
        """Update map when data changes."""
        if self._map is None:
            self.refresh()
            return

        connections = new_data.get('connections', [])

        self._map.clear_threats()
        self._unknown_ips.clear()

        for conn in connections[-50:]:
            try:
                lat = float(conn.get('dst_lat', 0) or 0)
                lon = float(conn.get('dst_lon', 0) or 0)
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()
                ip = conn.get('dst_ip', 'Unknown')

                if is_unknown_location(lat, lon):
                    self._unknown_ips.add(ip)
                    continue

                if hasattr(self._map, 'add_connection'):
                    self._map.add_connection(0, 0, lat, lon, threat, org_type, ip)
                else:
                    self._map.add_threat(lat, lon, ip, threat, org_type)

            except Exception as e:
                logger.debug(f"Failed to add threat: {e}")

        self._map.set_unknown_count(len(self._unknown_ips))
        self.refresh()

    def _reapply_data(self) -> None:
        """Reapply current data to new map instance."""
        if self.globe_data:
            self.watch_globe_data(self.globe_data)

    def add_threat(self, lat: float, lon: float, ip: str,
                   threat_score: float, org_type: str) -> None:
        """
        Directly add a threat marker.

        Args:
            lat: Latitude
            lon: Longitude
            ip: IP address
            threat_score: Threat level (0-1)
            org_type: Organization type
        """
        if self._map:
            if is_unknown_location(lat, lon):
                self._unknown_ips.add(ip)
                self._map.set_unknown_count(len(self._unknown_ips))
            else:
                self._map.add_threat(lat, lon, ip, threat_score, org_type)

    def clear_threats(self) -> None:
        """Clear all threat markers."""
        if self._map:
            self._map.clear_threats()
        self._unknown_ips.clear()

    def update(self, dt: float = 0.05) -> None:
        """Update map animation."""
        if self._map:
            self._map.update(dt)

    def resize(self, width: int, height: int) -> None:
        """Resize the map."""
        self._map_width = width
        self._map_height = height
        if self._map:
            self._map.resize(width, height)

    def on_resize(self, event) -> None:
        """Handle resize events to maximize map space usage."""
        new_width = max(60, event.size.width - 2)
        new_height = max(15, event.size.height - 3)
        self.resize(new_width, new_height)
        self.refresh()

    def render(self) -> Panel:
        """Render the intel map."""
        if self._map:
            try:
                self.update(0.05)
                return self._map.render()
            except Exception as e:
                logger.debug(f"Map render failed: {e}")

        return Panel(
            "[dim]Map visualization unavailable[/dim]\n\n"
            "[cyan]Waiting for geographic data...[/cyan]",
            title="[bold cyan]Intel Map[/bold cyan]",
            border_style="yellow"
        )
