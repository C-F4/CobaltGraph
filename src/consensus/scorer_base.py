"""
Base classes for threat scorers
Defines the interface all scorers must implement

Enhanced with comprehensive metrics tracking:
- Confusion matrix (TP/FP/TN/FN)
- Precision, Recall, F1
- Latency percentiles
- Ground truth feedback integration
"""

import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

# Lazy import to avoid circular dependency
if TYPE_CHECKING:
    from .metrics import ClassificationMetrics, LatencyTracker


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
        expected_sig = hmac.new(secret_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

        return hmac.compare_digest(self.signature, expected_sig)


class ThreatScorer(ABC):
    """
    Abstract base class for threat scorers

    All scorers must:
    1. Implement assess() method
    2. Generate cryptographically signed assessments
    3. Track their own accuracy metrics

    Enhanced metrics tracking:
    - Confusion matrix with TP/FP/TN/FN
    - Precision, Recall, F1 score
    - Latency percentiles (p50, p95, p99)
    - Calibration metrics
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

        # Legacy performance tracking (kept for backward compatibility)
        self.assessments_made = 0
        self.total_confidence = 0.0
        self.ground_truth_matches = 0
        self.ground_truth_total = 0

        # Enhanced metrics (lazy-loaded to avoid circular import)
        self._classification_metrics: Optional["ClassificationMetrics"] = None
        self._latency_tracker: Optional["LatencyTracker"] = None
        self._metrics_initialized = False

        # Score history for drift detection integration
        self._recent_scores: List[float] = []
        self._max_recent_scores = 1000

        # Feedback callbacks
        self._feedback_callbacks: List[Callable[[float, bool], None]] = []

    @abstractmethod
    def assess(
        self, dst_ip: str, threat_intel: Dict, geo_data: Dict, connection_metadata: Dict
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

    def _sign_assessment(self, score: float, confidence: float, timestamp: float) -> str:
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
        signature = hmac.new(self.secret_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

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

        # Track score for drift detection
        if len(self._recent_scores) >= self._max_recent_scores:
            self._recent_scores.pop(0)
        self._recent_scores.append(assessment.score)

    def _init_metrics(self):
        """Lazy-initialize enhanced metrics (avoids circular import)"""
        if self._metrics_initialized:
            return

        try:
            from .metrics import ClassificationMetrics, LatencyTracker
            self._classification_metrics = ClassificationMetrics(scorer_id=self.scorer_id)
            self._latency_tracker = LatencyTracker()
            self._metrics_initialized = True
        except ImportError:
            pass  # Metrics module not available

    def record_latency(self, latency_ms: float):
        """
        Record assessment latency

        Args:
            latency_ms: Assessment latency in milliseconds
        """
        self._init_metrics()
        if self._latency_tracker:
            self._latency_tracker.record(latency_ms)

    def update_ground_truth(self, predicted_score: float, actual_malicious: bool, threshold: float = 0.5):
        """
        Update metrics with ground truth (enhanced version)

        Args:
            predicted_score: The score this scorer predicted
            actual_malicious: True if actually malicious
            threshold: Classification threshold
        """
        # Legacy tracking
        self.ground_truth_total += 1
        predicted_threat = predicted_score >= threshold
        if predicted_threat == actual_malicious:
            self.ground_truth_matches += 1

        # Enhanced metrics
        self._init_metrics()
        if self._classification_metrics:
            self._classification_metrics.update(predicted_score, actual_malicious, threshold)

        # Notify callbacks
        for callback in self._feedback_callbacks:
            try:
                callback(predicted_score, actual_malicious)
            except Exception:
                pass

    def register_feedback_callback(self, callback: Callable[[float, bool], None]):
        """Register callback for ground truth feedback"""
        self._feedback_callbacks.append(callback)

    def get_classification_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive classification metrics

        Returns:
            Dictionary with TP/FP/TN/FN, precision, recall, F1, etc.
        """
        self._init_metrics()
        if self._classification_metrics:
            return self._classification_metrics.to_dict()

        # Fallback to legacy metrics
        return {
            "accuracy": self.get_accuracy(),
            "total": self.ground_truth_total,
            "matches": self.ground_truth_matches,
        }

    def get_latency_metrics(self) -> Dict[str, Any]:
        """
        Get latency percentile metrics

        Returns:
            Dictionary with p50, p90, p95, p99, mean, etc.
        """
        self._init_metrics()
        if self._latency_tracker:
            return self._latency_tracker.to_dict()

        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "count": 0}

    def get_precision(self) -> float:
        """Get precision: TP / (TP + FP)"""
        self._init_metrics()
        if self._classification_metrics:
            return self._classification_metrics.confusion_matrix.precision
        return 0.0

    def get_recall(self) -> float:
        """Get recall: TP / (TP + FN)"""
        self._init_metrics()
        if self._classification_metrics:
            return self._classification_metrics.confusion_matrix.recall
        return 0.0

    def get_f1_score(self) -> float:
        """Get F1 score: harmonic mean of precision and recall"""
        self._init_metrics()
        if self._classification_metrics:
            return self._classification_metrics.confusion_matrix.f1_score
        return 0.0

    def get_confusion_matrix(self) -> Dict[str, int]:
        """
        Get confusion matrix counts

        Returns:
            Dictionary with true_positives, false_positives, true_negatives, false_negatives
        """
        self._init_metrics()
        if self._classification_metrics:
            cm = self._classification_metrics.confusion_matrix
            return {
                "true_positives": cm.true_positives,
                "false_positives": cm.false_positives,
                "true_negatives": cm.true_negatives,
                "false_negatives": cm.false_negatives,
            }
        return {
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
        }

    def get_recent_scores(self) -> List[float]:
        """Get recent score history for drift analysis"""
        return self._recent_scores.copy()

    def get_enhanced_stats(self) -> Dict[str, Any]:
        """
        Get all enhanced statistics

        Returns:
            Comprehensive stats including classification, latency, and legacy metrics
        """
        return {
            "scorer_id": self.scorer_id,
            "assessments_made": self.assessments_made,
            "avg_confidence": self.get_avg_confidence(),
            "classification": self.get_classification_metrics(),
            "latency": self.get_latency_metrics(),
            "legacy_accuracy": self.get_accuracy(),
        }
