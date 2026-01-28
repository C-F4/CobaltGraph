"""
Panels Module
=============

UI panel components for CobaltGraph's dashboard layout.

NOTE: Most panel implementations live in unified_components.py.
This module provides specialized wrappers.

Panel Locations (canonical sources):
- unified_components.py - Primary panel implementations (ThreatPosturePanel,
  ConnectionTablePanel, ConsensusBreakdownPanel, etc.)
- dashboard_enhanced.py - Dashboard-specific enhanced variants
- connection_modal.py - Modal-specific panels (ModalConsensusBreakdownPanel)
- panels/intel_map.py - Intel map wrapper (uses maps module)

IntelMapPanel wraps the maps module to provide a Textual widget interface
for geographic threat visualization.
"""

import logging

logger = logging.getLogger(__name__)

# IntelMapPanel - wraps the maps module for geographic visualization
try:
    from .intel_map import IntelMapPanel
except ImportError as e:
    logger.debug(f"IntelMapPanel unavailable: {e}")
    IntelMapPanel = None


__all__ = [
    'IntelMapPanel',
]
