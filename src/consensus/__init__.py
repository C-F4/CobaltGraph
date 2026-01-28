"""
CobaltGraph Consensus Module
Multi-scorer Byzantine fault tolerant threat assessment

This module implements distributed consensus for threat scoring:
- Multiple independent scorers (synthetic diversity)
- Byzantine fault tolerant voting
- Cryptographic verification (HMAC-SHA256)
- Automated ground truth tracking
- Organization-based scoring with ASN analysis
- Neural network scorer with GRU temporal learning
- Comprehensive metrics: classification (precision/recall/F1), drift detection, latency tracking
"""

from .bft_consensus import BFTConsensus
from .scorer_base import ScorerAssessment, ThreatScorer
from .threat_scorer import ConsensusThreatScorer
from .rule_scorer import RuleScorer
from .statistical_scorer import StatisticalScorer
from .ml_scorer import HeuristicScorer
# Backwards compatibility alias
MLScorer = HeuristicScorer

# Comprehensive metrics module
try:
    from .metrics import (
        MetricsManager,
        ClassificationMetrics,
        ConfusionMatrix,
        DriftDetector,
        LatencyTracker,
        ScorerAgreementMetrics,
        FeedbackCollector,
        GroundTruthFeedback,
        MetricsPersistence,
    )
    METRICS_AVAILABLE = True
except ImportError:
    MetricsManager = None
    ClassificationMetrics = None
    ConfusionMatrix = None
    DriftDetector = None
    LatencyTracker = None
    ScorerAgreementMetrics = None
    FeedbackCollector = None
    GroundTruthFeedback = None
    MetricsPersistence = None
    METRICS_AVAILABLE = False

# Organization scorer with graceful fallback
try:
    from .organization_scorer import OrganizationScorer, create_organization_scorer
    ORG_SCORER_AVAILABLE = True
except ImportError:
    OrganizationScorer = None
    create_organization_scorer = None
    ORG_SCORER_AVAILABLE = False

# Neural network scorer with GRU temporal learning
try:
    from .neural_scorer import NeuralScorer, create_neural_scorer
    from .neural_network import PacketClassifierNN, ConnectionFeatureExtractor
    NEURAL_SCORER_AVAILABLE = True
except ImportError:
    NeuralScorer = None
    create_neural_scorer = None
    PacketClassifierNN = None
    ConnectionFeatureExtractor = None
    NEURAL_SCORER_AVAILABLE = False

__all__ = [
    # Core consensus
    "ConsensusThreatScorer",
    "BFTConsensus",
    "ThreatScorer",
    "ScorerAssessment",
    # Scorers
    "RuleScorer",
    "StatisticalScorer",
    "HeuristicScorer",
    "MLScorer",  # Backwards compatibility alias for HeuristicScorer
    "OrganizationScorer",
    "create_organization_scorer",
    "ORG_SCORER_AVAILABLE",
    # Neural network scorer
    "NeuralScorer",
    "create_neural_scorer",
    "PacketClassifierNN",
    "ConnectionFeatureExtractor",
    "NEURAL_SCORER_AVAILABLE",
    # Comprehensive metrics
    "MetricsManager",
    "ClassificationMetrics",
    "ConfusionMatrix",
    "DriftDetector",
    "LatencyTracker",
    "ScorerAgreementMetrics",
    "FeedbackCollector",
    "GroundTruthFeedback",
    "MetricsPersistence",
    "METRICS_AVAILABLE",
]
