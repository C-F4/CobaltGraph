"""
Maps Module
===========

Consolidated map and globe visualizations for CobaltGraph.

This module provides all geographic threat visualization components:
- FlatWorldMap: 2D equirectangular projection (primary)
- RotatingGlobe: Animated 3D-style globe
- SimpleGlobe: Lightweight fallback

All implementations share a common interface through BaseMap.

Usage:
    from src.ui.maps import FlatWorldMap, RotatingGlobe, SimpleGlobe

    # Create a map
    world_map = FlatWorldMap(width=120, height=25)

    # Add threats (automatically filters unknown locations)
    world_map.add_threat(lat=40.7, lon=-74.0, ip="1.2.3.4", threat_score=0.8)

    # Update animation
    world_map.update(dt=0.1)

    # Render to Rich Panel
    panel = world_map.render()

Map Selection:
    Use FlatWorldMap for detailed geographic analysis.
    Use RotatingGlobe for presentations and overview.
    Use SimpleGlobe as fallback when others fail.
"""

import logging

from .base import BaseMap, ThreatMarker, ConnectionArc
from .utils import (
    int_to_roman,
    get_threat_char,
    get_threat_color,
    get_threat_style,
    get_org_color,
    is_unknown_location,
    normalize_coordinates,
    miller_projection,
    equirectangular_projection,
    THREAT_LEVELS,
    ORG_TYPE_COLORS,
    HEATMAP_GRADIENT,
    CHAR_ASPECT_RATIO,
)
from .key import (
    MapKeyWidget,
    render_compact_key,
    render_detailed_key,
    render_key_box,
    get_verification_char,
    get_verification_color,
    get_triangulation_char,
    get_triangulation_color,
)

logger = logging.getLogger(__name__)

# Map implementations with lazy loading for optional dependencies
_FlatWorldMap = None
_RotatingGlobe = None
_SimpleGlobe = None


def _load_flat_map():
    """Lazy load FlatWorldMap."""
    global _FlatWorldMap
    if _FlatWorldMap is None:
        try:
            from .flat_map import FlatWorldMap as FM
            _FlatWorldMap = FM
        except ImportError as e:
            logger.warning(f"FlatWorldMap unavailable: {e}")
            _FlatWorldMap = False
    return _FlatWorldMap if _FlatWorldMap else None


def _load_rotating_globe():
    """Lazy load RotatingGlobe."""
    global _RotatingGlobe
    if _RotatingGlobe is None:
        try:
            from .rotating_globe import RotatingGlobe as RG
            _RotatingGlobe = RG
        except ImportError as e:
            logger.warning(f"RotatingGlobe unavailable: {e}")
            _RotatingGlobe = False
    return _RotatingGlobe if _RotatingGlobe else None


def _load_simple_globe():
    """Lazy load SimpleGlobe."""
    global _SimpleGlobe
    if _SimpleGlobe is None:
        try:
            from .simple_globe import SimpleGlobe as SG
            _SimpleGlobe = SG
        except ImportError as e:
            logger.warning(f"SimpleGlobe unavailable: {e}")
            _SimpleGlobe = False
    return _SimpleGlobe if _SimpleGlobe else None


# Property-like access for map classes
class _MapLoader:
    """Provides lazy-loaded access to map classes."""

    @property
    def FlatWorldMap(self):
        return _load_flat_map()

    @property
    def RotatingGlobe(self):
        return _load_rotating_globe()

    @property
    def SimpleGlobe(self):
        return _load_simple_globe()


_loader = _MapLoader()


def get_map_class(map_type: str):
    """
    Get map class by type name.

    Args:
        map_type: One of 'flat', 'rotating', 'simple'

    Returns:
        Map class or None if unavailable
    """
    type_map = {
        'flat': _load_flat_map,
        'rotating': _load_rotating_globe,
        'simple': _load_simple_globe,
    }
    loader = type_map.get(map_type.lower())
    return loader() if loader else None


def create_map(map_type: str = "flat", width: int = 80, height: int = 20, fallback: bool = True):
    """
    Create a map instance with optional fallback.

    Args:
        map_type: Preferred map type ('flat', 'rotating', 'simple')
        width: Canvas width
        height: Canvas height
        fallback: If True, try other map types if preferred fails

    Returns:
        Map instance or None if all fail
    """
    # Try preferred type first
    MapClass = get_map_class(map_type)
    if MapClass:
        try:
            return MapClass(width=width, height=height)
        except Exception as e:
            logger.warning(f"Failed to create {map_type} map: {e}")

    if not fallback:
        return None

    # Fallback chain
    fallback_order = ['flat', 'rotating', 'simple']
    for fb_type in fallback_order:
        if fb_type == map_type:
            continue
        MapClass = get_map_class(fb_type)
        if MapClass:
            try:
                return MapClass(width=width, height=height)
            except Exception as e:
                logger.warning(f"Fallback {fb_type} map failed: {e}")

    logger.error("All map types failed to initialize")
    return None


# Direct imports for common usage
try:
    from .flat_map import FlatWorldMap
except ImportError:
    FlatWorldMap = None

try:
    from .rotating_globe import RotatingGlobe
except ImportError:
    RotatingGlobe = None

try:
    from .simple_globe import SimpleGlobe
except ImportError:
    SimpleGlobe = None


__all__ = [
    # Base classes
    'BaseMap',
    'ThreatMarker',
    'ConnectionArc',

    # Map implementations
    'FlatWorldMap',
    'RotatingGlobe',
    'SimpleGlobe',

    # Factory functions
    'get_map_class',
    'create_map',

    # Utilities
    'int_to_roman',
    'get_threat_char',
    'get_threat_color',
    'get_threat_style',
    'get_org_color',
    'is_unknown_location',
    'normalize_coordinates',
    'miller_projection',
    'equirectangular_projection',

    # Constants
    'THREAT_LEVELS',
    'ORG_TYPE_COLORS',
    'HEATMAP_GRADIENT',
    'CHAR_ASPECT_RATIO',

    # Key/Legend
    'MapKeyWidget',
    'render_compact_key',
    'render_detailed_key',
    'render_key_box',
    'get_verification_char',
    'get_verification_color',
    'get_triangulation_char',
    'get_triangulation_color',
]
