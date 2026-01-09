"""
Pipeline Stages

Modular processing stages that replace the monolithic _process_connection() method.
Each stage is responsible for one concern and can be tested independently.
"""

from .base import PipelineStage, StageContext, CompositeStage
from .validation import ValidationStage
from .enrichment import EnrichmentStage
from .scoring import ScoringStage
from .analytics import AnalyticsStage
from .storage import StorageStage

__all__ = [
    # Base classes
    "PipelineStage",
    "StageContext",
    "CompositeStage",
    # Concrete stages
    "ValidationStage",
    "EnrichmentStage",
    "ScoringStage",
    "AnalyticsStage",
    "StorageStage",
]
