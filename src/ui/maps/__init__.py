"""
Maps Module
===========

Geographic threat visualization for CobaltGraph.

Provides:
    - FlatWorldMap: 2D map with Miller projection (primary)
    - RotatingGlobe: Animated 3D-style globe
    - SimpleGlobe: Lightweight fallback

Usage:
    from src.ui.maps import create_map, FlatWorldMap

    # Create with auto-fallback
    world_map = create_map('flat', width=120, height=30)

    # Direct instantiation
    map = FlatWorldMap(width=120, height=30)
"""

import logging

from .base import BaseMap, ThreatMarker, ConnectionArc
from .flat_map import FlatWorldMap
from .rotating_globe import RotatingGlobe
from .simple_globe import SimpleGlobe
from .utils import (
    int_to_roman,
    get_threat_char,
    get_threat_color,
    get_threat_style,
    get_org_color,
    is_unknown_location,
    miller_projection,
)
from .key import render_compact_key, render_key_box

logger = logging.getLogger(__name__)


def create_map(map_type: str = 'flat', width: int = 120,
               height: int = 30, fallback: bool = True):
    """
    Create a map instance.

    Args:
        map_type: 'flat', 'rotating', or 'simple'
        width: Canvas width in characters
        height: Canvas height in rows
        fallback: If True, fall back to simpler maps on failure

    Returns:
        Map instance or None if all fail
    """
    types = {
        'flat': FlatWorldMap,
        'rotating': RotatingGlobe,
        'simple': SimpleGlobe,
    }

    cls = types.get(map_type)
    if cls:
        try:
            return cls(width=width, height=height)
        except Exception as e:
            logger.warning(f"Failed to create {map_type} map: {e}")
            if not fallback:
                raise

    if fallback:
        for fallback_type in ['flat', 'simple']:
            fallback_cls = types.get(fallback_type)
            if fallback_cls and fallback_cls != cls:
                try:
                    return fallback_cls(width=width, height=height)
                except Exception:
                    continue

    return None


__all__ = [
    'BaseMap',
    'ThreatMarker',
    'ConnectionArc',
    'FlatWorldMap',
    'RotatingGlobe',
    'SimpleGlobe',
    'create_map',
    'is_unknown_location',
    'int_to_roman',
    'get_threat_char',
    'get_threat_color',
    'get_threat_style',
    'get_org_color',
    'miller_projection',
    'render_compact_key',
    'render_key_box',
]
