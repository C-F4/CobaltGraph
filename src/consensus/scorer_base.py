"""
Base classes for threat scorers
Defines the interface all scorers must implement
"""

import time
import hmac
import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Any


@dataclass
class ScorerAssessment:
    """
    A single scorer's threat assessment

    Attributes:
        scorer_id: Unique identifier for this scorer
        score: Threat score (0.0 = benign, 1.0 = malicious)
        confidence: Confidence in this assessment (0.0 - 1.0)
        reasoning: Human-readable explanation
        features: Feature values used for scoring
        timestamp: When assessment was made
        signature: HMAC-SHA256 signature for verification
    """
    scorer_id: str
    score: float
    confidence: float
    reasoning: str
    features: Dict[str, Any]
    timestamp: float
    signature: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    def verify_signature(self, secret_key: bytes) -> bool:
        """
        Verify HMAC-SHA256 signature

        Args:
            secret_key: Secret key used for signing

        Returns:
            True if signature is valid
        """
        # Recreate the message that was signed
        message = f"{self.scorer_id}:{self.score}:{self.confidence}:{self.timestamp}"
        expected_sig = hmac.new(
            secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(self.signature, expected_sig)


class ThreatScorer(ABC):
    """
    Abstract base class for threat scorers

    All scorers must:
    1. Implement assess() method
    2. Generate cryptographically signed assessments
    3. Track their own accuracy metrics
    """

    def __init__(self, scorer_id: str, secret_key: Optional[bytes] = None):
        """
        Initialize scorer

        Args:
            scorer_id: Unique identifier for this scorer
            secret_key: Secret key for HMAC signing (generated if None)
        """
        self.scorer_id = scorer_id
        self.secret_key = secret_key or secrets.token_bytes(32)

        # Performance tracking
        self.assessments_made = 0
        self.total_confidence = 0.0
        self.ground_truth_matches = 0
        self.ground_truth_total = 0

    @abstractmethod
    def assess(
        self,
        dst_ip: str,
        threat_intel: Dict,
        geo_data: Dict,
        connection_metadata: Dict
    ) -> ScorerAssessment:
        """
        Assess threat level for a connection

        Args:
            dst_ip: Destination IP address
            threat_intel: External threat intelligence data
                         (from VirusTotal, AbuseIPDB, etc.)
            geo_data: Geographic information
            connection_metadata: Additional context
                                (port, protocol, frequency, etc.)

        Returns:
            ScorerAssessment with signed threat score
        """
        pass

    def _sign_assessment(
        self,
        score: float,
        confidence: float,
        timestamp: float
    ) -> str:
        """
        Create HMAC-SHA256 signature for assessment

        Args:
            score: Threat score
            confidence: Confidence level
            timestamp: Assessment timestamp

        Returns:
            Hex-encoded HMAC signature
        """
        message = f"{self.scorer_id}:{score}:{confidence}:{timestamp}"
        signature = hmac.new(
            self.secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return signature

    def update_accuracy(self, predicted_score: float, actual_outcome: bool):
        """
        Update accuracy tracking when ground truth is known

        Args:
            predicted_score: The score this scorer predicted
            actual_outcome: True if threat was real, False if benign
        """
        self.ground_truth_total += 1

        # Simple threshold-based accuracy (0.5 cutoff)
        predicted_threat = predicted_score >= 0.5
        if predicted_threat == actual_outcome:
            self.ground_truth_matches += 1

    def get_accuracy(self) -> float:
        """
        Get current accuracy rate

        Returns:
            Accuracy (0.0 - 1.0) or 0.0 if no ground truth data yet
        """
        if self.ground_truth_total == 0:
            return 0.0
        return self.ground_truth_matches / self.ground_truth_total

    def get_avg_confidence(self) -> float:
        """
        Get average confidence across all assessments

        Returns:
            Average confidence level
        """
        if self.assessments_made == 0:
            return 0.0
        return self.total_confidence / self.assessments_made

    def _record_assessment(self, assessment: ScorerAssessment):
        """Track internal metrics"""
        self.assessments_made += 1
        self.total_confidence += assessment.confidence
