"""
Intel Map Panel - Unified threat visualization panel.
Provides automatic fallback between map implementations with consistent interface.
"""

import logging
from typing import Dict, List, Optional, Any

from rich.panel import Panel
from textual.widgets import Static
from textual.reactive import reactive

from .key import IntelMapKey, render_map_key

logger = logging.getLogger(__name__)


class IntelMapPanel(Static):
    """
    Unified Intel Map Panel for threat geographic visualization.

    Automatically selects the best available map implementation:
    1. FlatWorldMap (2D projection) - Primary, most detailed
    2. RotatingGlobe (3D rotating) - Alternative visualization
    3. SimpleGlobe - Lightweight fallback

    Provides consistent interface for adding threats and updating display.
    """

    DEFAULT_CSS = """
    IntelMapPanel {
        height: 100%;
        width: 100%;
        padding: 0;
    }
    """

    # Map type options
    MAP_TYPE_FLAT = "flat"
    MAP_TYPE_ROTATING = "rotating"
    MAP_TYPE_SIMPLE = "simple"

    globe_data = reactive(dict)

    def __init__(self, map_type: str = MAP_TYPE_FLAT,
                 width: int = 60, height: int = 15, **kwargs):
        super().__init__(**kwargs)
        self.map_type = map_type
        self.preferred_width = width
        self.preferred_height = height
        self.globe_data = {
            'connections': [],
            'heatmap': {},
        }
        self._map_impl = None
        self._init_map()

    def _init_map(self) -> None:
        """Initialize the map implementation based on type preference"""
        # Try preferred type first, then fall back
        impl_order = {
            self.MAP_TYPE_FLAT: [self._try_flat_map, self._try_rotating_globe, self._try_simple_globe],
            self.MAP_TYPE_ROTATING: [self._try_rotating_globe, self._try_flat_map, self._try_simple_globe],
            self.MAP_TYPE_SIMPLE: [self._try_simple_globe, self._try_flat_map, self._try_rotating_globe],
        }

        attempts = impl_order.get(self.map_type, impl_order[self.MAP_TYPE_FLAT])

        for attempt in attempts:
            try:
                impl = attempt()
                if impl:
                    self._map_impl = impl
                    logger.debug(f"Intel map initialized: {type(impl).__name__}")
                    return
            except Exception as e:
                logger.debug(f"Map init failed: {e}")
                continue

        logger.warning("All map implementations failed - using fallback rendering")
        self._map_impl = None

    def _try_flat_map(self):
        """Try to initialize FlatWorldMap"""
        from .world_map import FlatWorldMap
        return FlatWorldMap(width=self.preferred_width, height=self.preferred_height)

    def _try_rotating_globe(self):
        """Try to initialize RotatingGlobe"""
        from .globe_rotating import RotatingGlobe
        return RotatingGlobe(width=self.preferred_width, height=self.preferred_height)

    def _try_simple_globe(self):
        """Try to initialize SimpleGlobe"""
        from .globe_simple import SimpleGlobe
        return SimpleGlobe(width=self.preferred_width, height=self.preferred_height)

    def add_threat(self, lat: float, lon: float, ip: str,
                   threat_score: float, org_type: str) -> None:
        """Add a threat marker to the map"""
        if self._map_impl:
            try:
                self._map_impl.add_threat(lat, lon, ip, threat_score, org_type)
            except Exception as e:
                logger.debug(f"Failed to add threat: {e}")

    def clear_threats(self) -> None:
        """Clear all threats from the map"""
        if self._map_impl:
            try:
                self._map_impl.clear_threats()
            except Exception as e:
                logger.debug(f"Failed to clear threats: {e}")

    def update(self, dt: float = 0.05) -> None:
        """Update map animation state"""
        if self._map_impl:
            try:
                self._map_impl.update(dt)
            except Exception as e:
                logger.debug(f"Failed to update map: {e}")

    def toggle_pause(self) -> None:
        """Toggle rotation pause (for rotating globes)"""
        if self._map_impl and hasattr(self._map_impl, 'toggle_pause'):
            self._map_impl.toggle_pause()

    def resize(self, width: int, height: int) -> None:
        """Resize the map"""
        self.preferred_width = width
        self.preferred_height = height
        if self._map_impl and hasattr(self._map_impl, 'resize'):
            self._map_impl.resize(width, height)

    def watch_globe_data(self, new_data: dict) -> None:
        """Update map when data changes"""
        if self._map_impl is None:
            self.refresh()
            return

        connections = new_data.get('connections', [])

        # Clear and re-add threats
        self.clear_threats()
        for conn in connections[-30:]:  # Limit to last 30
            try:
                lat = float(conn.get('dst_lat', 0) or 0)
                lon = float(conn.get('dst_lon', 0) or 0)
                threat = float(conn.get('threat_score', 0) or 0)
                org_type = (conn.get('dst_org_type') or 'unknown').lower()
                ip = conn.get('dst_ip', 'Unknown')

                self.add_threat(lat, lon, ip, threat, org_type)
            except Exception as e:
                logger.debug(f"Failed to add threat to map: {e}")

        self.refresh()

    def render(self):
        """Render the intel map"""
        if self._map_impl:
            try:
                self.update(0.05)
                return self._map_impl.render()
            except Exception as e:
                logger.debug(f"Map render failed: {e}")

        # Fallback rendering
        return self._render_fallback()

    def _render_fallback(self) -> Panel:
        """Fallback rendering when map implementation fails"""
        connections = self.globe_data.get('connections', [])

        content_lines = []
        # Status indicator at top
        content_lines.append("[dim yellow][TextFallback:NO_MAP_IMPL][/dim yellow]")
        content_lines.append("")
        content_lines.append("[bold cyan]Intel Map[/bold cyan]")
        content_lines.append("[dim]Visualization loading...[/dim]")

        if connections:
            # Show top countries
            countries = {}
            for conn in connections:
                country = (conn.get('dst_country') or 'XX')[:2]
                threat = float(conn.get('threat_score', 0) or 0)
                if country not in countries:
                    countries[country] = []
                countries[country].append(threat)

            sorted_countries = sorted(
                [(c, sum(t)/len(t), len(t)) for c, t in countries.items()],
                key=lambda x: x[1] * x[2],
                reverse=True
            )[:5]

            content_lines.append("")
            content_lines.append("[bold]Top Threat Regions[/bold]")
            for country, avg_threat, count in sorted_countries:
                if avg_threat >= 0.7:
                    color = "red"
                elif avg_threat >= 0.5:
                    color = "yellow"
                else:
                    color = "green"

                bar = chr(0x2588) * int(avg_threat * 10)  # Block character
                content_lines.append(f"{country} [{color}]{bar:10s}[/{color}] {avg_threat:.2f}")

            # Add key
            content_lines.append("")
            content_lines.append("[dim]Key: ●Crit ◉High ○Med ·Low[/dim]")

        content = "\n".join(content_lines)
        return Panel(content, title="[bold cyan]Intel Map[/bold cyan]", border_style="cyan")

    @property
    def map_implementation(self) -> str:
        """Return the name of the current map implementation"""
        if self._map_impl:
            return type(self._map_impl).__name__
        return "Fallback"

    @property
    def map_status(self) -> str:
        """Return the status of the current map (FULL, DEGRADED, FALLBACK)"""
        if self._map_impl:
            return getattr(self._map_impl, 'MAP_STATUS', 'UNKNOWN')
        return "FALLBACK"

    @property
    def map_error(self) -> Optional[str]:
        """Return any initialization error from the map implementation"""
        if self._map_impl:
            return getattr(self._map_impl, '_init_error', None)
        return "No map implementation available"
