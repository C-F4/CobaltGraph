"""
CobaltGraph Consensus Module
Multi-scorer Byzantine fault tolerant threat assessment

This module implements distributed consensus for threat scoring:
- Multiple independent scorers (synthetic diversity)
- Byzantine fault tolerant voting
- Cryptographic verification (HMAC-SHA256)
- Automated ground truth tracking
"""

from .bft_consensus import BFTConsensus
from .scorer_base import ScorerAssessment, ThreatScorer
from .threat_scorer import ConsensusThreatScorer

__all__ = [
    "ConsensusThreatScorer",
    "BFTConsensus",
    "ThreatScorer",
    "ScorerAssessment",
]
