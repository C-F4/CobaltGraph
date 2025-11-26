"""
CobaltGraph Consensus Module
Multi-scorer Byzantine fault tolerant threat assessment

This module implements distributed consensus for threat scoring:
- Multiple independent scorers (synthetic diversity)
- Byzantine fault tolerant voting
- Cryptographic verification (HMAC-SHA256)
- Automated ground truth tracking
- Organization-based scoring with ASN analysis
"""

from .bft_consensus import BFTConsensus
from .scorer_base import ScorerAssessment, ThreatScorer
from .threat_scorer import ConsensusThreatScorer
from .rule_scorer import RuleScorer
from .statistical_scorer import StatisticalScorer
from .ml_scorer import MLScorer

# Organization scorer with graceful fallback
try:
    from .organization_scorer import OrganizationScorer, create_organization_scorer
    ORG_SCORER_AVAILABLE = True
except ImportError:
    OrganizationScorer = None
    create_organization_scorer = None
    ORG_SCORER_AVAILABLE = False

__all__ = [
    "ConsensusThreatScorer",
    "BFTConsensus",
    "ThreatScorer",
    "ScorerAssessment",
    "RuleScorer",
    "StatisticalScorer",
    "MLScorer",
    "OrganizationScorer",
    "create_organization_scorer",
    "ORG_SCORER_AVAILABLE",
]
