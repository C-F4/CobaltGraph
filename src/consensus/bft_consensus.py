"""
Byzantine Fault Tolerant Consensus Algorithm
Handles voting and consensus among multiple threat scorers

Key features:
- 2/3 majority required for consensus
- Outlier detection and handling
- Confidence-weighted voting
- Median-based resolution with uncertainty flags
"""

import logging
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .scorer_base import ScorerAssessment

logger = logging.getLogger(__name__)


@dataclass
class ConsensusResult:
    """
    Result of consensus process

    Attributes:
        consensus_score: Final agreed-upon threat score
        confidence: Overall confidence in consensus
        high_uncertainty: Flag indicating significant disagreement
        votes: All individual scorer assessments
        outliers: Scorers identified as outliers
        method: How consensus was achieved
        metadata: Additional consensus details
    """

    consensus_score: float
    confidence: float
    high_uncertainty: bool
    votes: List[Dict]
    outliers: List[str]
    method: str
    metadata: Dict

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "consensus_score": self.consensus_score,
            "confidence": self.confidence,
            "high_uncertainty": self.high_uncertainty,
            "votes": self.votes,
            "outliers": self.outliers,
            "method": self.method,
            "metadata": self.metadata,
        }


class BFTConsensus:
    """
    Byzantine Fault Tolerant consensus implementation

    Assumes up to f < n/3 scorers may be faulty or compromised.
    For 3 scorers, can tolerate 1 faulty scorer.
    """

    def __init__(
        self,
        min_scorers: int = 2,
        outlier_threshold: float = 0.3,
        uncertainty_threshold: float = 0.25,
    ):
        """
        Initialize BFT consensus

        Args:
            min_scorers: Minimum number of scorers required (default: 2)
            outlier_threshold: Max deviation to not be considered outlier
            uncertainty_threshold: Spread threshold for high uncertainty flag
        """
        self.min_scorers = min_scorers
        self.outlier_threshold = outlier_threshold
        self.uncertainty_threshold = uncertainty_threshold

    def achieve_consensus(self, assessments: List[ScorerAssessment]) -> Optional[ConsensusResult]:
        """
        Achieve consensus from multiple scorer assessments

        Process:
        1. Verify we have enough scorers
        2. Detect outliers (scores far from median)
        3. Use median of non-outlier scores
        4. Flag high uncertainty if spread is large

        Args:
            assessments: List of scorer assessments

        Returns:
            ConsensusResult or None if consensus impossible
        """
        # Validate inputs
        if len(assessments) < self.min_scorers:
            logger.warning("Insufficient scorers: %d < %d", len(assessments), self.min_scorers)
            return None

        # Extract scores and confidences
        scores = [a.score for a in assessments]
        confidences = [a.confidence for a in assessments]

        # Calculate median score
        median_score = statistics.median(scores)

        # Detect outliers (scores significantly different from median)
        outliers = []
        non_outlier_scores = []
        non_outlier_confidences = []

        for assessment in assessments:
            deviation = abs(assessment.score - median_score)

            if deviation > self.outlier_threshold:
                outliers.append(assessment.scorer_id)
                logger.info(
                    f"Outlier detected: {assessment.scorer_id} "
                    f"(score={assessment.score:.3f}, median={median_score:.3f}, "
                    f"deviation={deviation:.3f})"
                )
            else:
                non_outlier_scores.append(assessment.score)
                non_outlier_confidences.append(assessment.confidence)

        # Check if we still have enough scorers after removing outliers
        if len(non_outlier_scores) < self.min_scorers:
            logger.warning(
                f"Too many outliers: {len(outliers)} outliers, "
                f"{len(non_outlier_scores)} remaining"
            )
            # Fall back to using all scores
            non_outlier_scores = scores
            non_outlier_confidences = confidences
            outliers = []

        # Calculate consensus score (median of non-outliers)
        consensus_score = statistics.median(non_outlier_scores)

        # Calculate spread to detect high uncertainty
        if len(non_outlier_scores) > 1:
            score_spread = max(non_outlier_scores) - min(non_outlier_scores)
            high_uncertainty = score_spread > self.uncertainty_threshold
        else:
            score_spread = 0.0
            high_uncertainty = False

        # Calculate overall confidence (weighted average)
        if non_outlier_confidences:
            avg_confidence = statistics.mean(non_outlier_confidences)
        else:
            avg_confidence = 0.5

        # Reduce confidence if high uncertainty
        if high_uncertainty:
            avg_confidence *= 0.7  # Penalty for disagreement

        # Build result
        result = ConsensusResult(
            consensus_score=consensus_score,
            confidence=avg_confidence,
            high_uncertainty=high_uncertainty,
            votes=[a.to_dict() for a in assessments],
            outliers=outliers,
            method="median_bft",
            metadata={
                "num_scorers": len(assessments),
                "num_outliers": len(outliers),
                "score_spread": score_spread,
                "median_score": median_score,
                "min_score": min(scores),
                "max_score": max(scores),
            },
        )

        logger.info(
            f"Consensus achieved: score={consensus_score:.3f}, "
            f"confidence={avg_confidence:.3f}, "
            f"uncertainty={'HIGH' if high_uncertainty else 'LOW'}, "
            f"outliers={len(outliers)}"
        )

        return result

    def verify_assessments(
        self, assessments: List[ScorerAssessment], secret_keys: Dict[str, bytes]
    ) -> Tuple[List[ScorerAssessment], List[str]]:
        """
        Verify cryptographic signatures on assessments

        Args:
            assessments: List of assessments to verify
            secret_keys: Map of scorer_id -> secret_key

        Returns:
            Tuple of (valid_assessments, failed_scorer_ids)
        """
        valid = []
        failed = []

        for assessment in assessments:
            scorer_id = assessment.scorer_id

            if scorer_id not in secret_keys:
                logger.warning("No secret key for scorer: %s", scorer_id)
                failed.append(scorer_id)
                continue

            secret_key = secret_keys[scorer_id]

            if assessment.verify_signature(secret_key):
                valid.append(assessment)
            else:
                logger.error("Invalid signature from scorer: %s", scorer_id)
                failed.append(scorer_id)

        if failed:
            logger.warning("Failed signature verification: %s", failed)

        return valid, failed
