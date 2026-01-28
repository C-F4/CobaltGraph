"""
Map Manager
===========

Central management for map types with proper lifecycle handling.
Provides:
    - Map type registration
    - Clean cycling between map types
    - Threat data synchronization across map switches
    - Status reporting

Usage:
    from src.ui.maps import MapManager

    manager = MapManager(width=120, height=30)
    panel = manager.render()

    # Cycle to next available map
    manager.cycle()

    # Add threats (syncs across all maps)
    manager.add_threat(lat, lon, ip, threat_score, org_type)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type, Tuple, Any
from collections import OrderedDict

from rich.panel import Panel

from .base import BaseMap

logger = logging.getLogger(__name__)


@dataclass
class MapRegistration:
    """Registration info for a map type."""
    name: str
    map_class: Type[BaseMap]
    priority: int = 10
    enabled: bool = True
    display_name: str = ""

    def __post_init__(self):
        if not self.display_name:
            self.display_name = self.name.replace('_', ' ').title()


class MapManager:
    """
    Centralized map management with cycling and sync capabilities.

    Handles:
        - Map type registration and instantiation
        - Clean cycling between available map types
        - Threat data synchronization when switching maps
        - Lifecycle management (resize, update, clear)
    """

    def __init__(self, width: int = 120, height: int = 30, default_type: str = 'flat'):
        """
        Initialize the map manager.

        Args:
            width: Canvas width in characters
            height: Canvas height in rows
            default_type: Default map type to use
        """
        self._width = width
        self._height = height
        self._default_type = default_type

        # Registered map types (insertion-ordered)
        self._registrations: OrderedDict[str, MapRegistration] = OrderedDict()

        # Active map instances (lazily created)
        self._instances: Dict[str, BaseMap] = {}

        # Current active map type
        self._current_type: Optional[str] = None

        # Shared threat data for synchronization
        self._threat_buffer: List[Tuple[float, float, str, float, str]] = []
        self._unknown_ips: set = set()

        # Register default map types
        self._register_defaults()

        # Initialize current map
        self._init_current()

    def _register_defaults(self) -> None:
        """Register the built-in map types."""
        try:
            from .flat_map import FlatWorldMap
            self.register('flat', FlatWorldMap, priority=1, display_name='Flat World')
        except ImportError as e:
            logger.debug(f"FlatWorldMap unavailable: {e}")

        try:
            from .rotating_globe import RotatingGlobe
            self.register('rotating', RotatingGlobe, priority=2, display_name='Rotating Globe')
        except ImportError as e:
            logger.debug(f"RotatingGlobe unavailable: {e}")

        try:
            from .simple_globe import SimpleGlobe
            self.register('simple', SimpleGlobe, priority=3, display_name='Simple Globe')
        except ImportError as e:
            logger.debug(f"SimpleGlobe unavailable: {e}")

    def _init_current(self) -> None:
        """Initialize the current map based on default or first available."""
        if self._default_type in self._registrations:
            self._current_type = self._default_type
        elif self._registrations:
            self._current_type = next(iter(self._registrations))
        else:
            self._current_type = None

        if self._current_type:
            self._ensure_instance(self._current_type)

    def register(self, name: str, map_class: Type[BaseMap],
                 priority: int = 10, enabled: bool = True,
                 display_name: str = "") -> None:
        """
        Register a map type.

        Args:
            name: Unique identifier for this map type
            map_class: The map class to instantiate
            priority: Lower values = higher priority for default selection
            enabled: Whether this map type is available
            display_name: Human-readable name for UI
        """
        reg = MapRegistration(
            name=name,
            map_class=map_class,
            priority=priority,
            enabled=enabled,
            display_name=display_name
        )
        self._registrations[name] = reg

        # Re-sort by priority
        self._registrations = OrderedDict(
            sorted(self._registrations.items(), key=lambda x: x[1].priority)
        )

        logger.debug(f"Registered map type: {name} (priority={priority})")

    def _ensure_instance(self, map_type: str) -> Optional[BaseMap]:
        """Get or create a map instance."""
        if map_type in self._instances:
            return self._instances[map_type]

        reg = self._registrations.get(map_type)
        if not reg or not reg.enabled:
            return None

        try:
            instance = reg.map_class(width=self._width, height=self._height)
            self._instances[map_type] = instance
            # Sync any existing threats
            self._sync_threats_to(instance)
            logger.debug(f"Created {map_type} map instance")
            return instance
        except Exception as e:
            logger.warning(f"Failed to create {map_type} map: {e}")
            return None

    def _sync_threats_to(self, map_instance: BaseMap) -> None:
        """Sync buffered threat data to a map instance."""
        for lat, lon, ip, threat_score, org_type in self._threat_buffer:
            map_instance.add_threat(lat, lon, ip, threat_score, org_type)
        if hasattr(map_instance, 'set_unknown_count'):
            map_instance.set_unknown_count(len(self._unknown_ips))

    @property
    def current_map(self) -> Optional[BaseMap]:
        """Get the currently active map instance."""
        if self._current_type:
            return self._instances.get(self._current_type)
        return None

    @property
    def current_type(self) -> str:
        """Get the current map type name."""
        return self._current_type or 'none'

    @property
    def current_display_name(self) -> str:
        """Get the display name of the current map type."""
        if self._current_type:
            reg = self._registrations.get(self._current_type)
            if reg:
                return reg.display_name
        return 'None'

    @property
    def available_types(self) -> List[str]:
        """Get list of available map type names."""
        return [name for name, reg in self._registrations.items() if reg.enabled]

    def cycle(self) -> str:
        """
        Cycle to the next available map type.

        Returns:
            The name of the new active map type
        """
        available = self.available_types
        if not available:
            return 'none'

        if self._current_type not in available:
            self._current_type = available[0]
        else:
            idx = available.index(self._current_type)
            self._current_type = available[(idx + 1) % len(available)]

        self._ensure_instance(self._current_type)
        return self._current_type

    def add_threat(self, lat: float, lon: float, ip: str = "",
                   threat_score: float = 0.5, org_type: str = "unknown") -> bool:
        """
        Add a threat marker to all active maps.

        Args:
            lat: Latitude
            lon: Longitude
            ip: IP address
            threat_score: Threat level (0-1)
            org_type: Organization type

        Returns:
            True if threat was added (not an unknown location)
        """
        # Check for unknown location
        from .utils import is_unknown_location
        if is_unknown_location(lat, lon):
            if ip:
                self._unknown_ips.add(ip)
            # Update unknown count on current map
            if self.current_map and hasattr(self.current_map, 'set_unknown_count'):
                self.current_map.set_unknown_count(len(self._unknown_ips))
            return False

        # Buffer the threat for sync when switching maps
        self._threat_buffer.append((lat, lon, ip, threat_score, org_type))

        # Keep buffer manageable
        if len(self._threat_buffer) > 100:
            self._threat_buffer = self._threat_buffer[-50:]

        # Add to current map
        if self.current_map:
            return self.current_map.add_threat(lat, lon, ip, threat_score, org_type)
        return True

    def clear_threats(self) -> None:
        """Clear all threats from all maps."""
        self._threat_buffer.clear()
        self._unknown_ips.clear()
        for instance in self._instances.values():
            instance.clear_threats()

    def update(self, dt: float = 0.05) -> None:
        """Update animation state on current map."""
        if self.current_map:
            self.current_map.update(dt)

    def resize(self, width: int, height: int) -> None:
        """Resize all map instances."""
        self._width = width
        self._height = height
        for instance in self._instances.values():
            instance.resize(width, height)

    def render(self) -> Panel:
        """Render the current map."""
        if self.current_map:
            try:
                self.update()
                return self.current_map.render()
            except Exception as e:
                logger.debug(f"Map render failed: {e}")

        return Panel(
            "[dim]Map visualization unavailable[/dim]\n\n"
            "[cyan]No map types available[/cyan]",
            title="[bold cyan]Intel Map[/bold cyan]",
            border_style="yellow"
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get combined stats from current map."""
        if self.current_map:
            stats = self.current_map.get_stats()
            stats['map_type'] = self.current_type
            stats['unknown'] = len(self._unknown_ips)
            return stats
        return {
            'total': 0,
            'critical': 0,
            'high': 0,
            'unknown': len(self._unknown_ips),
            'map_type': 'none'
        }
