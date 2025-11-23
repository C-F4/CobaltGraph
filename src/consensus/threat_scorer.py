"""
Consensus Threat Scorer
Main orchestrator for multi-scorer threat assessment

This is the replacement for ip_reputation.check_ip() in orchestrator.py
Coordinates multiple scorers with BFT consensus
"""

import logging
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

from .bft_consensus import BFTConsensus
from .ml_scorer import MLScorer
from .rule_scorer import RuleScorer
from .scorer_base import ScorerAssessment, ThreatScorer
from .statistical_scorer import StatisticalScorer

logger = logging.getLogger(__name__)


class ConsensusThreatScorer:
    """
    Multi-scorer consensus threat assessment system

    Coordinates:
    - 3 synthetic diversity scorers (statistical, rule, ML)
    - Byzantine fault tolerant consensus
    - Cryptographic verification
    - In-memory cache + disk persistence
    """

    def __init__(self, config: Optional[Dict] = None, enable_persistence: bool = True):
        """
        Initialize consensus threat scorer

        Args:
            config: Configuration dictionary
            enable_persistence: Enable disk persistence (hybrid storage)
        """
        self.config = config or {}
        self.enable_persistence = enable_persistence

        # Initialize scorers
        logger.info("Initializing consensus threat scorers...")
        self.scorers: List[ThreatScorer] = [
            StatisticalScorer(),
            RuleScorer(),
            MLScorer(),
        ]
        logger.info(
            f"Initialized {len(self.scorers)} scorers: " f"{[s.scorer_id for s in self.scorers]}"
        )

        # Initialize consensus algorithm
        self.consensus = BFTConsensus(
            min_scorers=2, outlier_threshold=0.3, uncertainty_threshold=0.25
        )

        # In-memory cache for recent assessments
        self.cache_size = self.config.get("consensus_cache_size", 1000)
        self.assessment_cache = deque(maxlen=self.cache_size)

        # Secret keys for signature verification
        self.secret_keys = {scorer.scorer_id: scorer.secret_key for scorer in self.scorers}

        # Statistics
        self.total_assessments = 0
        self.consensus_failures = 0
        self.high_uncertainty_count = 0

        logger.info("ConsensusThreatScorer initialized successfully")

    def check_ip(
        self,
        dst_ip: str,
        threat_intel: Optional[Dict] = None,
        geo_data: Optional[Dict] = None,
        connection_metadata: Optional[Dict] = None,
    ) -> Tuple[float, Dict]:
        """
        Assess threat level for IP address using consensus

        This method signature matches ip_reputation.check_ip() for
        drop-in replacement in orchestrator.py

        Args:
            dst_ip: Destination IP address
            threat_intel: Threat intelligence data (from VT, AbuseIPDB, etc.)
            geo_data: Geographic data
            connection_metadata: Connection context (port, protocol, etc.)

        Returns:
            Tuple of (threat_score, details_dict)
            - threat_score: Consensus score (0.0-1.0)
            - details_dict: Full consensus details including all votes
        """
        self.total_assessments += 1

        # Handle missing inputs gracefully
        threat_intel = threat_intel or {}
        geo_data = geo_data or {}
        connection_metadata = connection_metadata or {}

        # Get assessments from all scorers
        assessments: List[ScorerAssessment] = []

        for scorer in self.scorers:
            try:
                assessment = scorer.assess(
                    dst_ip=dst_ip,
                    threat_intel=threat_intel,
                    geo_data=geo_data,
                    connection_metadata=connection_metadata,
                )
                assessments.append(assessment)

            except Exception as e:
                logger.error("Scorer {scorer.scorer_id} failed for {dst_ip}: %s", e, exc_info=True)
                # Continue with other scorers

        # Check if we got enough assessments
        if len(assessments) < 2:
            logger.error(
                f"Insufficient assessments for {dst_ip}: "
                f"only {len(assessments)} scorers responded"
            )
            self.consensus_failures += 1
            # Fallback to safe default
            return 0.5, {
                "error": "insufficient_scorers",
                "available_scorers": len(assessments),
                "required_scorers": 2,
            }

        # Verify signatures
        valid_assessments, failed_scorers = self.consensus.verify_assessments(
            assessments, self.secret_keys
        )

        if failed_scorers:
            logger.warning("Signature verification failed for: %s", failed_scorers)

        if len(valid_assessments) < 2:
            logger.error(
                f"Insufficient valid assessments for {dst_ip} " f"after signature verification"
            )
            self.consensus_failures += 1
            return 0.5, {
                "error": "signature_verification_failed",
                "failed_scorers": failed_scorers,
            }

        # Achieve consensus
        consensus_result = self.consensus.achieve_consensus(valid_assessments)

        if consensus_result is None:
            logger.error("Consensus failed for %s", dst_ip)
            self.consensus_failures += 1
            return 0.5, {"error": "consensus_failed"}

        # Track high uncertainty
        if consensus_result.high_uncertainty:
            self.high_uncertainty_count += 1
            logger.warning(
                f"High uncertainty for {dst_ip}: "
                f"spread={consensus_result.metadata.get('score_spread', 0):.3f}"
            )

        # Cache assessment
        cache_entry = {
            "timestamp": time.time(),
            "dst_ip": dst_ip,
            "consensus": consensus_result.to_dict(),
            "threat_intel": threat_intel,
            "geo_data": geo_data,
            "connection_metadata": connection_metadata,
        }
        self.assessment_cache.append(cache_entry)

        # Periodic persistence (every N assessments)
        if self.enable_persistence and self.total_assessments % 100 == 0:
            self._flush_to_disk()

        # Format return value to match ip_reputation.check_ip() interface
        threat_score = consensus_result.consensus_score
        details = {
            "source": "consensus",
            "is_malicious": threat_score >= 0.7,
            "threat_score": threat_score,
            "confidence": consensus_result.confidence,
            "high_uncertainty": consensus_result.high_uncertainty,
            "votes": consensus_result.votes,
            "outliers": consensus_result.outliers,
            "method": consensus_result.method,
            "metadata": consensus_result.metadata,
        }

        logger.debug(
            f"Consensus for {dst_ip}: score={threat_score:.3f}, "
            f"confidence={consensus_result.confidence:.3f}, "
            f"uncertainty={'HIGH' if consensus_result.high_uncertainty else 'LOW'}"
        )

        return threat_score, details

    def _flush_to_disk(self):
        """Persist in-memory cache to disk"""
        # TODO: Implement periodic flush to SQLite
        # This will be added in the next iteration with storage integration
        logger.debug(f"Cache flush triggered: {len(self.assessment_cache)} assessments")

    def get_statistics(self) -> Dict:
        """
        Get scorer statistics

        Returns:
            Dictionary with performance metrics
        """
        stats = {
            "total_assessments": self.total_assessments,
            "consensus_failures": self.consensus_failures,
            "high_uncertainty_count": self.high_uncertainty_count,
            "failure_rate": self.consensus_failures / max(self.total_assessments, 1),
            "uncertainty_rate": self.high_uncertainty_count / max(self.total_assessments, 1),
            "cache_size": len(self.assessment_cache),
            "scorers": {},
        }

        # Per-scorer statistics
        for scorer in self.scorers:
            stats["scorers"][scorer.scorer_id] = {
                "assessments_made": scorer.assessments_made,
                "avg_confidence": scorer.get_avg_confidence(),
                "accuracy": scorer.get_accuracy(),
                "ground_truth_total": scorer.ground_truth_total,
            }

        return stats

    def shutdown(self):
        """Graceful shutdown with final persistence"""
        if self.enable_persistence:
            logger.info("Flushing final assessments to disk...")
            self._flush_to_disk()

        logger.info(
            f"ConsensusThreatScorer shutdown complete. "
            f"Total assessments: {self.total_assessments}"
        )
