"""
CobaltGraph Dashboard
Unified threat monitoring interface with multi-dimensional visualization

Features:
- ASCII globe with heatmaps
- Organization triage matrix with trust scoring
- Hop count topology visualization
- Event log viewer with filtering
- Adaptive table density modes (LOW/MEDIUM/HIGH/FULL)
- Multi-dimensional threat vector analysis
"""

# Import Dashboard (main terminal interface)
try:
    from .dashboard import CobaltGraphDashboard
    DASHBOARD_AVAILABLE = True
except ImportError:
    CobaltGraphDashboard = None
    DASHBOARD_AVAILABLE = False

# Import ASCII globe component
try:
    from .ascii_globe import ASCIIGlobe, GlobeWidget
    GLOBE_AVAILABLE = True
except ImportError:
    ASCIIGlobe = None
    GlobeWidget = None
    GLOBE_AVAILABLE = False

# Import visualization engine
try:
    from .viz_engine import (
        ThreatGlobe,
        ThreatHeatmap,
        OrganizationTriageMatrix,
        HopTopologyVisualizer,
        ParallelCoordinatesThreat,
        VisualizationEngine,
        ThreatVector,
        OrganizationTriage,
        THREAT_COLORS,
        ORG_TYPE_RISK,
    )
    VIZ_ENGINE_AVAILABLE = True
except ImportError:
    ThreatGlobe = None
    ThreatHeatmap = None
    OrganizationTriageMatrix = None
    HopTopologyVisualizer = None
    ParallelCoordinatesThreat = None
    VisualizationEngine = None
    ThreatVector = None
    OrganizationTriage = None
    THREAT_COLORS = None
    ORG_TYPE_RISK = None
    VIZ_ENGINE_AVAILABLE = False

__all__ = [
    # Main dashboard
    'CobaltGraphDashboard',
    'DASHBOARD_AVAILABLE',
    # Globes
    'ASCIIGlobe',
    'GlobeWidget',
    'GLOBE_AVAILABLE',
    # Visualization engine
    'ThreatGlobe',
    'ThreatHeatmap',
    'OrganizationTriageMatrix',
    'HopTopologyVisualizer',
    'ParallelCoordinatesThreat',
    'VisualizationEngine',
    'ThreatVector',
    'OrganizationTriage',
    'THREAT_COLORS',
    'ORG_TYPE_RISK',
    'VIZ_ENGINE_AVAILABLE',
]
