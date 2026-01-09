"""
CobaltGraph Pipeline Module

Clean, stage-based data processing pipeline for network intelligence.
Replaces the monolithic DataPipeline with modular, testable stages.

Architecture:
    Connection → ValidationStage → EnrichmentStage → ScoringStage
                                                   → AnalyticsStage → StorageStage

Each stage:
- Has single responsibility
- Returns StageResult with success/failure
- Can be tested independently
- Reports metrics for monitoring
"""

from .config import PipelineConfig
from .events import (
    ConnectionEvent,
    DeviceEvent,
    StageResult,
    GeoData,
    ASNData,
    ThreatIntelData,
    ConsensusResult,
    AnomalyData,
    ThreatLevel,
    EventType,
    PipelineStats,
)
from .stages import (
    PipelineStage,
    StageContext,
    CompositeStage,
    ValidationStage,
    EnrichmentStage,
    ScoringStage,
    AnalyticsStage,
    StorageStage,
)

__all__ = [
    # Configuration
    "PipelineConfig",
    # Events
    "ConnectionEvent",
    "DeviceEvent",
    "StageResult",
    "GeoData",
    "ASNData",
    "ThreatIntelData",
    "ConsensusResult",
    "AnomalyData",
    "ThreatLevel",
    "EventType",
    "PipelineStats",
    # Stages
    "PipelineStage",
    "StageContext",
    "CompositeStage",
    "ValidationStage",
    "EnrichmentStage",
    "ScoringStage",
    "AnalyticsStage",
    "StorageStage",
]
