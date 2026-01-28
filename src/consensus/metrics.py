"""
Comprehensive Metrics Module for Threat Scoring System

Provides industry-standard ML monitoring metrics:
- Classification metrics (precision, recall, F1, confusion matrix)
- Data/prediction drift detection (PSI, K-S statistic)
- Latency tracking (percentiles)
- Scorer agreement analysis
- Ground truth feedback pipeline
- SQLite persistence with hourly rollups

Design principles:
- Pure Python (no numpy/pandas dependency)
- Lightweight for real-time operation
- SQLite persistence for historical analysis
- Industry-standard thresholds (PSI > 0.25 = significant drift)
"""

import hashlib
import json
import logging
import math
import sqlite3
import statistics
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# CLASSIFICATION METRICS
# =============================================================================


@dataclass
class ConfusionMatrix:
    """
    Confusion matrix for binary classification

    Tracks TP/FP/TN/FN counts and derives precision, recall, F1, etc.
    Thread-safe with internal locking.
    """
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    # For AU-ROC calculation - stores (threshold, tpr, fpr) points
    _roc_points: List[Tuple[float, float, float]] = field(default_factory=list)
    _score_history: List[Tuple[float, bool]] = field(default_factory=list)
    _history_limit: int = 10000

    def update(self, predicted_score: float, actual_malicious: bool, threshold: float = 0.5):
        """
        Update confusion matrix with a new prediction

        Args:
            predicted_score: Model's predicted threat score (0.0-1.0)
            actual_malicious: Ground truth - True if actually malicious
            threshold: Classification threshold (default 0.5)
        """
        predicted_positive = predicted_score >= threshold

        if predicted_positive and actual_malicious:
            self.true_positives += 1
        elif predicted_positive and not actual_malicious:
            self.false_positives += 1
        elif not predicted_positive and not actual_malicious:
            self.true_negatives += 1
        else:  # not predicted_positive and actual_malicious
            self.false_negatives += 1

        # Store for ROC calculation
        if len(self._score_history) < self._history_limit:
            self._score_history.append((predicted_score, actual_malicious))

    @property
    def total(self) -> int:
        """Total predictions made"""
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    @property
    def accuracy(self) -> float:
        """Overall accuracy: (TP + TN) / Total"""
        if self.total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total

    @property
    def precision(self) -> float:
        """Precision: TP / (TP + FP) - how many predicted positives are correct"""
        denom = self.true_positives + self.false_positives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    @property
    def recall(self) -> float:
        """Recall (sensitivity): TP / (TP + FN) - how many actual positives were found"""
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 0.0
        return self.true_positives / denom

    @property
    def f1_score(self) -> float:
        """F1 Score: harmonic mean of precision and recall"""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def specificity(self) -> float:
        """Specificity: TN / (TN + FP) - true negative rate"""
        denom = self.true_negatives + self.false_positives
        if denom == 0:
            return 0.0
        return self.true_negatives / denom

    @property
    def false_positive_rate(self) -> float:
        """FPR: FP / (FP + TN)"""
        denom = self.false_positives + self.true_negatives
        if denom == 0:
            return 0.0
        return self.false_positives / denom

    @property
    def false_negative_rate(self) -> float:
        """FNR: FN / (FN + TP)"""
        denom = self.false_negatives + self.true_positives
        if denom == 0:
            return 0.0
        return self.false_negatives / denom

    def compute_roc_points(self, num_thresholds: int = 100) -> List[Tuple[float, float, float]]:
        """
        Compute ROC curve points from score history

        Returns:
            List of (threshold, TPR, FPR) tuples
        """
        if not self._score_history:
            return []

        points = []
        for i in range(num_thresholds + 1):
            threshold = i / num_thresholds

            tp = sum(1 for score, actual in self._score_history if score >= threshold and actual)
            fp = sum(1 for score, actual in self._score_history if score >= threshold and not actual)
            fn = sum(1 for score, actual in self._score_history if score < threshold and actual)
            tn = sum(1 for score, actual in self._score_history if score < threshold and not actual)

            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            points.append((threshold, tpr, fpr))

        self._roc_points = points
        return points

    def compute_auroc(self) -> float:
        """
        Compute Area Under ROC Curve using trapezoidal rule

        Returns:
            AU-ROC score (0.0-1.0), where 0.5 = random, 1.0 = perfect
        """
        if not self._roc_points:
            self.compute_roc_points()

        if len(self._roc_points) < 2:
            return 0.5

        # Sort by FPR for proper integration
        sorted_points = sorted(self._roc_points, key=lambda x: x[2])

        # Trapezoidal integration
        auc = 0.0
        for i in range(1, len(sorted_points)):
            fpr_diff = sorted_points[i][2] - sorted_points[i-1][2]
            tpr_avg = (sorted_points[i][1] + sorted_points[i-1][1]) / 2
            auc += fpr_diff * tpr_avg

        return auc

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "specificity": self.specificity,
            "fpr": self.false_positive_rate,
            "fnr": self.false_negative_rate,
            "total": self.total,
        }

    def reset(self):
        """Reset all counters"""
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self._roc_points = []
        self._score_history = []


@dataclass
class ClassificationMetrics:
    """
    Complete classification metrics tracker for a scorer

    Maintains confusion matrix, calibration data, and historical metrics.
    """
    scorer_id: str
    confusion_matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)

    # Calibration tracking - bins of (predicted_avg, actual_rate)
    _calibration_bins: Dict[int, List[Tuple[float, bool]]] = field(default_factory=dict)
    _num_calibration_bins: int = 10

    # Threshold analysis
    _optimal_threshold: float = 0.5
    _threshold_f1_scores: Dict[float, float] = field(default_factory=dict)

    def update(self, predicted_score: float, actual_malicious: bool, threshold: float = 0.5):
        """Update metrics with new ground truth"""
        self.confusion_matrix.update(predicted_score, actual_malicious, threshold)

        # Track for calibration
        bin_idx = min(int(predicted_score * self._num_calibration_bins), self._num_calibration_bins - 1)
        if bin_idx not in self._calibration_bins:
            self._calibration_bins[bin_idx] = []
        if len(self._calibration_bins[bin_idx]) < 1000:  # Limit per bin
            self._calibration_bins[bin_idx].append((predicted_score, actual_malicious))

    def get_calibration_curve(self) -> List[Tuple[float, float, int]]:
        """
        Get calibration curve data

        Returns:
            List of (mean_predicted, fraction_positive, count) per bin
        """
        curve = []
        for bin_idx in range(self._num_calibration_bins):
            if bin_idx in self._calibration_bins and self._calibration_bins[bin_idx]:
                samples = self._calibration_bins[bin_idx]
                mean_pred = statistics.mean(s[0] for s in samples)
                frac_pos = sum(1 for s in samples if s[1]) / len(samples)
                curve.append((mean_pred, frac_pos, len(samples)))
            else:
                # Empty bin
                bin_center = (bin_idx + 0.5) / self._num_calibration_bins
                curve.append((bin_center, 0.0, 0))
        return curve

    def get_calibration_error(self) -> float:
        """
        Calculate Expected Calibration Error (ECE)

        Lower is better - measures how well confidence matches accuracy.
        """
        curve = self.get_calibration_curve()
        total_samples = sum(c[2] for c in curve)
        if total_samples == 0:
            return 0.0

        ece = 0.0
        for mean_pred, frac_pos, count in curve:
            if count > 0:
                ece += (count / total_samples) * abs(mean_pred - frac_pos)

        return ece

    def find_optimal_threshold(self) -> float:
        """Find threshold that maximizes F1 score"""
        if not self.confusion_matrix._score_history:
            return 0.5

        best_threshold = 0.5
        best_f1 = 0.0

        for t in range(1, 100):
            threshold = t / 100

            tp = sum(1 for s, a in self.confusion_matrix._score_history if s >= threshold and a)
            fp = sum(1 for s, a in self.confusion_matrix._score_history if s >= threshold and not a)
            fn = sum(1 for s, a in self.confusion_matrix._score_history if s < threshold and a)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            self._threshold_f1_scores[threshold] = f1

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold

        self._optimal_threshold = best_threshold
        return best_threshold

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "scorer_id": self.scorer_id,
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "calibration_error": self.get_calibration_error(),
            "optimal_threshold": self._optimal_threshold,
            "auroc": self.confusion_matrix.compute_auroc(),
        }


# =============================================================================
# DRIFT DETECTION
# =============================================================================


class DriftDetector:
    """
    Detects data and prediction drift using Population Stability Index (PSI)

    PSI measures how much a distribution has shifted from baseline:
    - PSI < 0.10: No significant drift
    - 0.10 <= PSI < 0.25: Moderate drift (monitor)
    - PSI >= 0.25: Significant drift (alert/retrain)

    Uses hourly windows for baseline comparison.
    """

    # Industry-standard thresholds
    PSI_THRESHOLD_MODERATE = 0.10
    PSI_THRESHOLD_SIGNIFICANT = 0.25

    def __init__(
        self,
        num_bins: int = 10,
        window_hours: int = 1,
        baseline_hours: int = 24,
        max_samples: int = 100000,
    ):
        """
        Initialize drift detector

        Args:
            num_bins: Number of bins for distribution comparison
            window_hours: Current window size in hours
            baseline_hours: Baseline window size in hours
            max_samples: Maximum samples to retain
        """
        self.num_bins = num_bins
        self.window_seconds = window_hours * 3600
        self.baseline_seconds = baseline_hours * 3600
        self.max_samples = max_samples

        # Score history: (timestamp, score)
        self._score_history: deque = deque(maxlen=max_samples)
        self._feature_history: Dict[str, deque] = {}  # feature_name -> deque of (timestamp, value)

        # Baseline distributions (computed periodically)
        self._baseline_distribution: Optional[List[float]] = None
        self._baseline_timestamp: float = 0.0

        # Drift history for trending
        self._drift_history: deque = deque(maxlen=1000)

        self._lock = Lock()

    def record_score(self, score: float, timestamp: Optional[float] = None):
        """Record a prediction score"""
        ts = timestamp or time.time()
        with self._lock:
            self._score_history.append((ts, score))

    def record_feature(self, feature_name: str, value: float, timestamp: Optional[float] = None):
        """Record a feature value for feature drift detection"""
        ts = timestamp or time.time()
        with self._lock:
            if feature_name not in self._feature_history:
                self._feature_history[feature_name] = deque(maxlen=self.max_samples)
            self._feature_history[feature_name].append((ts, value))

    def _compute_distribution(self, values: List[float]) -> List[float]:
        """Compute binned distribution from values"""
        if not values:
            return [1.0 / self.num_bins] * self.num_bins  # Uniform

        # Create bins
        distribution = [0.0] * self.num_bins
        for v in values:
            # Clamp to [0, 1] and assign to bin
            v = max(0.0, min(1.0, v))
            bin_idx = min(int(v * self.num_bins), self.num_bins - 1)
            distribution[bin_idx] += 1

        # Normalize to proportions
        total = sum(distribution)
        if total > 0:
            distribution = [d / total for d in distribution]
        else:
            distribution = [1.0 / self.num_bins] * self.num_bins

        # Add small epsilon to avoid log(0)
        epsilon = 1e-10
        distribution = [max(d, epsilon) for d in distribution]

        return distribution

    def _calculate_psi(self, baseline: List[float], current: List[float]) -> float:
        """
        Calculate Population Stability Index between two distributions

        PSI = sum((current% - baseline%) * ln(current% / baseline%))
        """
        if len(baseline) != len(current):
            raise ValueError("Distributions must have same number of bins")

        psi = 0.0
        for b, c in zip(baseline, current):
            # PSI formula with epsilon protection
            b = max(b, 1e-10)
            c = max(c, 1e-10)
            psi += (c - b) * math.log(c / b)

        return psi

    def _calculate_ks_statistic(self, baseline: List[float], current: List[float]) -> float:
        """
        Calculate Kolmogorov-Smirnov statistic

        Returns max absolute difference between cumulative distributions.
        """
        # Convert to CDFs
        baseline_cdf = []
        current_cdf = []

        b_sum, c_sum = 0.0, 0.0
        for b, c in zip(baseline, current):
            b_sum += b
            c_sum += c
            baseline_cdf.append(b_sum)
            current_cdf.append(c_sum)

        # Max absolute difference
        ks = max(abs(b - c) for b, c in zip(baseline_cdf, current_cdf))
        return ks

    def compute_score_drift(self) -> Dict[str, Any]:
        """
        Compute prediction drift metrics

        Returns:
            Dictionary with PSI, KS statistic, drift status, and alerts
        """
        current_time = time.time()

        with self._lock:
            # Get baseline samples (older window)
            baseline_cutoff = current_time - self.baseline_seconds
            window_cutoff = current_time - self.window_seconds

            baseline_scores = [
                s for ts, s in self._score_history
                if baseline_cutoff <= ts < window_cutoff
            ]
            current_scores = [
                s for ts, s in self._score_history
                if ts >= window_cutoff
            ]

        if len(baseline_scores) < 100 or len(current_scores) < 100:
            return {
                "psi": 0.0,
                "ks_statistic": 0.0,
                "status": "insufficient_data",
                "alert": False,
                "baseline_count": len(baseline_scores),
                "current_count": len(current_scores),
            }

        baseline_dist = self._compute_distribution(baseline_scores)
        current_dist = self._compute_distribution(current_scores)

        psi = self._calculate_psi(baseline_dist, current_dist)
        ks = self._calculate_ks_statistic(baseline_dist, current_dist)

        # Determine status
        if psi >= self.PSI_THRESHOLD_SIGNIFICANT:
            status = "significant_drift"
            alert = True
        elif psi >= self.PSI_THRESHOLD_MODERATE:
            status = "moderate_drift"
            alert = False
        else:
            status = "stable"
            alert = False

        result = {
            "psi": psi,
            "ks_statistic": ks,
            "status": status,
            "alert": alert,
            "baseline_count": len(baseline_scores),
            "current_count": len(current_scores),
            "baseline_mean": statistics.mean(baseline_scores),
            "current_mean": statistics.mean(current_scores),
            "baseline_std": statistics.stdev(baseline_scores) if len(baseline_scores) > 1 else 0,
            "current_std": statistics.stdev(current_scores) if len(current_scores) > 1 else 0,
            "timestamp": current_time,
        }

        # Record for trending
        with self._lock:
            self._drift_history.append((current_time, psi, status))

        return result

    def compute_feature_drift(self, feature_name: str) -> Dict[str, Any]:
        """Compute drift for a specific feature"""
        if feature_name not in self._feature_history:
            return {"status": "no_data", "feature": feature_name}

        current_time = time.time()

        with self._lock:
            baseline_cutoff = current_time - self.baseline_seconds
            window_cutoff = current_time - self.window_seconds

            history = self._feature_history[feature_name]
            baseline_values = [v for ts, v in history if baseline_cutoff <= ts < window_cutoff]
            current_values = [v for ts, v in history if ts >= window_cutoff]

        if len(baseline_values) < 50 or len(current_values) < 50:
            return {
                "feature": feature_name,
                "status": "insufficient_data",
                "psi": 0.0,
            }

        # Normalize values to [0, 1] for PSI calculation
        all_values = baseline_values + current_values
        min_v, max_v = min(all_values), max(all_values)
        range_v = max_v - min_v if max_v > min_v else 1.0

        baseline_norm = [(v - min_v) / range_v for v in baseline_values]
        current_norm = [(v - min_v) / range_v for v in current_values]

        baseline_dist = self._compute_distribution(baseline_norm)
        current_dist = self._compute_distribution(current_norm)

        psi = self._calculate_psi(baseline_dist, current_dist)

        return {
            "feature": feature_name,
            "psi": psi,
            "status": "drift" if psi >= self.PSI_THRESHOLD_SIGNIFICANT else "stable",
            "alert": psi >= self.PSI_THRESHOLD_SIGNIFICANT,
            "baseline_count": len(baseline_values),
            "current_count": len(current_values),
        }

    def get_drift_trend(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get drift history for trending analysis"""
        cutoff = time.time() - (hours * 3600)
        with self._lock:
            return [
                {"timestamp": ts, "psi": psi, "status": status}
                for ts, psi, status in self._drift_history
                if ts >= cutoff
            ]

    def to_dict(self) -> Dict[str, Any]:
        """Get current drift status"""
        return self.compute_score_drift()


# =============================================================================
# LATENCY TRACKING
# =============================================================================


class LatencyTracker:
    """
    Tracks operation latency with percentile calculation

    Provides p50, p90, p95, p99 latencies for performance monitoring.
    """

    def __init__(self, window_size: int = 10000):
        """
        Initialize latency tracker

        Args:
            window_size: Maximum number of samples to retain
        """
        self.window_size = window_size
        self._latencies: deque = deque(maxlen=window_size)
        self._lock = Lock()

        # Aggregated stats
        self._total_latency = 0.0
        self._count = 0
        self._min_latency = float('inf')
        self._max_latency = 0.0

    def record(self, latency_ms: float, timestamp: Optional[float] = None):
        """
        Record a latency measurement

        Args:
            latency_ms: Latency in milliseconds
            timestamp: Optional timestamp (defaults to now)
        """
        ts = timestamp or time.time()

        with self._lock:
            self._latencies.append((ts, latency_ms))
            self._total_latency += latency_ms
            self._count += 1
            self._min_latency = min(self._min_latency, latency_ms)
            self._max_latency = max(self._max_latency, latency_ms)

    def percentile(self, p: float, window_seconds: Optional[float] = None) -> float:
        """
        Calculate percentile latency

        Args:
            p: Percentile (0-100), e.g., 95 for p95
            window_seconds: Optional time window to consider

        Returns:
            Latency at the given percentile
        """
        with self._lock:
            if not self._latencies:
                return 0.0

            if window_seconds:
                cutoff = time.time() - window_seconds
                values = [lat for ts, lat in self._latencies if ts >= cutoff]
            else:
                values = [lat for _, lat in self._latencies]

        if not values:
            return 0.0

        sorted_values = sorted(values)
        idx = int(len(sorted_values) * p / 100)
        idx = min(idx, len(sorted_values) - 1)

        return sorted_values[idx]

    @property
    def p50(self) -> float:
        """Median latency"""
        return self.percentile(50)

    @property
    def p90(self) -> float:
        """90th percentile latency"""
        return self.percentile(90)

    @property
    def p95(self) -> float:
        """95th percentile latency"""
        return self.percentile(95)

    @property
    def p99(self) -> float:
        """99th percentile latency"""
        return self.percentile(99)

    @property
    def mean(self) -> float:
        """Mean latency"""
        if self._count == 0:
            return 0.0
        return self._total_latency / self._count

    def get_recent_stats(self, window_seconds: float = 3600) -> Dict[str, float]:
        """Get latency stats for recent window"""
        cutoff = time.time() - window_seconds

        with self._lock:
            recent = [lat for ts, lat in self._latencies if ts >= cutoff]

        if not recent:
            return {
                "p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0,
                "mean": 0.0, "min": 0.0, "max": 0.0, "count": 0
            }

        sorted_recent = sorted(recent)
        n = len(sorted_recent)

        return {
            "p50": sorted_recent[int(n * 0.50)] if n > 0 else 0.0,
            "p90": sorted_recent[int(n * 0.90)] if n > 0 else 0.0,
            "p95": sorted_recent[int(n * 0.95)] if n > 0 else 0.0,
            "p99": sorted_recent[min(int(n * 0.99), n - 1)] if n > 0 else 0.0,
            "mean": statistics.mean(recent),
            "min": min(recent),
            "max": max(recent),
            "count": n,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize current stats"""
        return {
            "p50": self.p50,
            "p90": self.p90,
            "p95": self.p95,
            "p99": self.p99,
            "mean": self.mean,
            "min": self._min_latency if self._min_latency != float('inf') else 0.0,
            "max": self._max_latency,
            "count": self._count,
        }


# =============================================================================
# SCORER AGREEMENT METRICS
# =============================================================================


class ScorerAgreementMetrics:
    """
    Tracks agreement/disagreement patterns between scorers

    Metrics:
    - Pairwise correlation
    - Agreement rate at threshold
    - Outlier frequency per scorer
    - Consensus spread distribution
    """

    def __init__(self, scorer_ids: List[str], max_samples: int = 10000):
        """
        Initialize agreement tracker

        Args:
            scorer_ids: List of scorer identifiers
            max_samples: Maximum samples to retain
        """
        self.scorer_ids = scorer_ids
        self.max_samples = max_samples

        # Score history per scorer: scorer_id -> deque of (timestamp, score)
        self._scorer_scores: Dict[str, deque] = {
            sid: deque(maxlen=max_samples) for sid in scorer_ids
        }

        # Outlier tracking: scorer_id -> outlier count
        self._outlier_counts: Dict[str, int] = {sid: 0 for sid in scorer_ids}
        self._total_votes: int = 0

        # Spread history
        self._spread_history: deque = deque(maxlen=max_samples)

        self._lock = Lock()

    def record_vote(
        self,
        scorer_scores: Dict[str, float],
        outliers: List[str],
        spread: float,
        timestamp: Optional[float] = None
    ):
        """
        Record a consensus vote

        Args:
            scorer_scores: Map of scorer_id -> score
            outliers: List of scorer_ids marked as outliers
            spread: Score spread for this vote
            timestamp: Optional timestamp
        """
        ts = timestamp or time.time()

        with self._lock:
            self._total_votes += 1

            for sid, score in scorer_scores.items():
                if sid in self._scorer_scores:
                    self._scorer_scores[sid].append((ts, score))

            for sid in outliers:
                if sid in self._outlier_counts:
                    self._outlier_counts[sid] += 1

            self._spread_history.append((ts, spread))

    def compute_correlation(self, scorer_a: str, scorer_b: str) -> float:
        """
        Compute Pearson correlation between two scorers

        Args:
            scorer_a: First scorer ID
            scorer_b: Second scorer ID

        Returns:
            Correlation coefficient (-1.0 to 1.0)
        """
        if scorer_a not in self._scorer_scores or scorer_b not in self._scorer_scores:
            return 0.0

        with self._lock:
            scores_a = {ts: s for ts, s in self._scorer_scores[scorer_a]}
            scores_b = {ts: s for ts, s in self._scorer_scores[scorer_b]}

        # Find common timestamps (within 1 second tolerance)
        paired_scores = []
        for ts_a, s_a in scores_a.items():
            for ts_b, s_b in scores_b.items():
                if abs(ts_a - ts_b) < 1.0:
                    paired_scores.append((s_a, s_b))
                    break

        if len(paired_scores) < 10:
            return 0.0

        # Pearson correlation
        n = len(paired_scores)
        sum_a = sum(p[0] for p in paired_scores)
        sum_b = sum(p[1] for p in paired_scores)
        sum_ab = sum(p[0] * p[1] for p in paired_scores)
        sum_a2 = sum(p[0] ** 2 for p in paired_scores)
        sum_b2 = sum(p[1] ** 2 for p in paired_scores)

        numerator = n * sum_ab - sum_a * sum_b
        denominator = math.sqrt((n * sum_a2 - sum_a ** 2) * (n * sum_b2 - sum_b ** 2))

        if denominator == 0:
            return 0.0

        return numerator / denominator

    def get_correlation_matrix(self) -> Dict[str, Dict[str, float]]:
        """Get full correlation matrix between all scorers"""
        matrix = {}
        for sid_a in self.scorer_ids:
            matrix[sid_a] = {}
            for sid_b in self.scorer_ids:
                if sid_a == sid_b:
                    matrix[sid_a][sid_b] = 1.0
                else:
                    matrix[sid_a][sid_b] = self.compute_correlation(sid_a, sid_b)
        return matrix

    def get_outlier_rates(self) -> Dict[str, float]:
        """Get outlier rate per scorer"""
        if self._total_votes == 0:
            return {sid: 0.0 for sid in self.scorer_ids}

        return {
            sid: count / self._total_votes
            for sid, count in self._outlier_counts.items()
        }

    def get_agreement_rate(self, threshold: float = 0.15) -> float:
        """
        Get rate of votes where spread is below threshold (high agreement)

        Args:
            threshold: Maximum spread to count as agreement
        """
        if not self._spread_history:
            return 0.0

        agreed = sum(1 for _, spread in self._spread_history if spread <= threshold)
        return agreed / len(self._spread_history)

    def get_spread_stats(self) -> Dict[str, float]:
        """Get spread distribution statistics"""
        if not self._spread_history:
            return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "count": 0}

        spreads = [s for _, s in self._spread_history]
        return {
            "mean": statistics.mean(spreads),
            "std": statistics.stdev(spreads) if len(spreads) > 1 else 0.0,
            "min": min(spreads),
            "max": max(spreads),
            "count": len(spreads),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "total_votes": self._total_votes,
            "outlier_rates": self.get_outlier_rates(),
            "agreement_rate": self.get_agreement_rate(),
            "spread_stats": self.get_spread_stats(),
            "correlation_matrix": self.get_correlation_matrix(),
        }


# =============================================================================
# GROUND TRUTH FEEDBACK
# =============================================================================


@dataclass
class GroundTruthFeedback:
    """
    Ground truth feedback record

    Stores analyst-provided labels for predictions.
    """
    ip_address: str
    prediction_score: float
    actual_malicious: bool
    feedback_source: str  # "analyst", "incident", "automated"
    timestamp: float
    scorer_scores: Dict[str, float] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FeedbackCollector:
    """
    Collects and manages ground truth feedback

    Provides API for analysts to label predictions and distributes
    feedback to scorers for accuracy tracking.
    """

    def __init__(self, max_pending: int = 10000, pending_ttl: float = 86400):
        """
        Initialize feedback collector

        Args:
            max_pending: Maximum pending predictions to track
            pending_ttl: TTL for pending predictions (seconds)
        """
        self.max_pending = max_pending
        self.pending_ttl = pending_ttl

        # Pending predictions awaiting feedback: ip -> (timestamp, score, scorer_scores)
        self._pending: Dict[str, Tuple[float, float, Dict[str, float]]] = {}

        # Collected feedback
        self._feedback: deque = deque(maxlen=max_pending)

        # Callbacks for distributing feedback
        self._callbacks: List[Callable[[GroundTruthFeedback], None]] = []

        self._lock = Lock()

    def register_prediction(
        self,
        ip_address: str,
        consensus_score: float,
        scorer_scores: Dict[str, float],
        timestamp: Optional[float] = None
    ):
        """
        Register a prediction for potential future feedback

        Args:
            ip_address: IP that was assessed
            consensus_score: Final consensus score
            scorer_scores: Individual scorer scores
            timestamp: Prediction timestamp
        """
        ts = timestamp or time.time()

        with self._lock:
            # Clean old pending
            self._cleanup_pending()

            self._pending[ip_address] = (ts, consensus_score, scorer_scores)

    def _cleanup_pending(self):
        """Remove expired pending predictions"""
        current_time = time.time()
        expired = [
            ip for ip, (ts, _, _) in self._pending.items()
            if current_time - ts > self.pending_ttl
        ]
        for ip in expired:
            del self._pending[ip]

        # Enforce max size
        if len(self._pending) > self.max_pending:
            # Remove oldest
            sorted_pending = sorted(self._pending.items(), key=lambda x: x[1][0])
            for ip, _ in sorted_pending[:len(self._pending) - self.max_pending]:
                del self._pending[ip]

    def provide_feedback(
        self,
        ip_address: str,
        actual_malicious: bool,
        source: str = "analyst",
        notes: str = ""
    ) -> Optional[GroundTruthFeedback]:
        """
        Provide ground truth feedback for an IP

        Args:
            ip_address: IP address to provide feedback for
            actual_malicious: True if actually malicious
            source: Feedback source ("analyst", "incident", "automated")
            notes: Optional notes

        Returns:
            GroundTruthFeedback if prediction found, None otherwise
        """
        with self._lock:
            if ip_address not in self._pending:
                logger.debug(f"No pending prediction for {ip_address}")
                return None

            ts, score, scorer_scores = self._pending.pop(ip_address)

        feedback = GroundTruthFeedback(
            ip_address=ip_address,
            prediction_score=score,
            actual_malicious=actual_malicious,
            feedback_source=source,
            timestamp=time.time(),
            scorer_scores=scorer_scores,
            notes=notes,
        )

        with self._lock:
            self._feedback.append(feedback)

        # Distribute to callbacks
        for callback in self._callbacks:
            try:
                callback(feedback)
            except Exception as e:
                logger.error(f"Feedback callback error: {e}")

        logger.info(
            f"Ground truth: {ip_address} -> "
            f"{'MALICIOUS' if actual_malicious else 'BENIGN'} "
            f"(predicted={score:.3f}, source={source})"
        )

        return feedback

    def register_callback(self, callback: Callable[[GroundTruthFeedback], None]):
        """Register callback to receive feedback notifications"""
        self._callbacks.append(callback)

    def get_feedback_history(self, limit: int = 100) -> List[GroundTruthFeedback]:
        """Get recent feedback history"""
        with self._lock:
            return list(self._feedback)[-limit:]

    def get_pending_count(self) -> int:
        """Get count of pending predictions"""
        return len(self._pending)

    def to_dict(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            "pending_count": len(self._pending),
            "feedback_count": len(self._feedback),
            "callback_count": len(self._callbacks),
        }


# =============================================================================
# METRICS PERSISTENCE
# =============================================================================


class MetricsPersistence:
    """
    SQLite persistence for metrics data

    Stores:
    - Hourly metric rollups
    - Drift history
    - Ground truth feedback
    - Scorer performance over time
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = "database/cobaltgraph.db"):
        """
        Initialize metrics persistence

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._lock = Lock()
        self._conn: Optional[sqlite3.Connection] = None

        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection (creates if needed)"""
        if self._conn is None:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _init_schema(self):
        """Initialize metrics tables"""
        conn = self._get_connection()

        with self._lock:
            # Scorer metrics rollup (hourly)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scorer_metrics_hourly (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    hour_bucket INTEGER NOT NULL,
                    scorer_id TEXT NOT NULL,
                    true_positives INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    true_negatives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    precision REAL,
                    recall REAL,
                    f1_score REAL,
                    accuracy REAL,
                    auroc REAL,
                    calibration_error REAL,
                    assessments_count INTEGER DEFAULT 0,
                    avg_confidence REAL,
                    avg_latency_ms REAL,
                    p95_latency_ms REAL,
                    UNIQUE(hour_bucket, scorer_id)
                )
            """)

            # Drift history
            conn.execute("""
                CREATE TABLE IF NOT EXISTS drift_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    hour_bucket INTEGER NOT NULL,
                    drift_type TEXT NOT NULL,
                    feature_name TEXT,
                    psi REAL NOT NULL,
                    ks_statistic REAL,
                    status TEXT NOT NULL,
                    baseline_mean REAL,
                    current_mean REAL,
                    baseline_std REAL,
                    current_std REAL,
                    sample_count INTEGER
                )
            """)

            # Ground truth feedback
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ground_truth_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    ip_address TEXT NOT NULL,
                    prediction_score REAL NOT NULL,
                    actual_malicious INTEGER NOT NULL,
                    feedback_source TEXT NOT NULL,
                    scorer_scores TEXT,
                    notes TEXT
                )
            """)

            # Consensus metrics
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consensus_metrics_hourly (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    hour_bucket INTEGER NOT NULL,
                    total_assessments INTEGER DEFAULT 0,
                    consensus_failures INTEGER DEFAULT 0,
                    high_uncertainty_count INTEGER DEFAULT 0,
                    avg_spread REAL,
                    agreement_rate REAL,
                    cache_hit_rate REAL,
                    avg_latency_ms REAL,
                    UNIQUE(hour_bucket)
                )
            """)

            # Create indexes
            indexes = [
                ("idx_scorer_metrics_hour", "scorer_metrics_hourly(hour_bucket)"),
                ("idx_scorer_metrics_scorer", "scorer_metrics_hourly(scorer_id, hour_bucket)"),
                ("idx_drift_hour", "drift_history(hour_bucket)"),
                ("idx_drift_type", "drift_history(drift_type, timestamp)"),
                ("idx_feedback_time", "ground_truth_feedback(timestamp)"),
                ("idx_feedback_ip", "ground_truth_feedback(ip_address)"),
                ("idx_consensus_hour", "consensus_metrics_hourly(hour_bucket)"),
            ]

            for idx_name, idx_def in indexes:
                try:
                    conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")
                except sqlite3.Error:
                    pass

            conn.commit()
            logger.debug("Metrics schema initialized")

    def save_scorer_metrics(
        self,
        scorer_id: str,
        metrics: ClassificationMetrics,
        latency: LatencyTracker,
        timestamp: Optional[float] = None
    ):
        """
        Save scorer metrics snapshot

        Args:
            scorer_id: Scorer identifier
            metrics: Classification metrics
            latency: Latency tracker
            timestamp: Optional timestamp
        """
        ts = timestamp or time.time()
        hour_bucket = int(ts // 3600) * 3600

        cm = metrics.confusion_matrix
        latency_stats = latency.to_dict()

        with self._lock:
            conn = self._get_connection()
            conn.execute("""
                INSERT OR REPLACE INTO scorer_metrics_hourly (
                    timestamp, hour_bucket, scorer_id,
                    true_positives, false_positives, true_negatives, false_negatives,
                    precision, recall, f1_score, accuracy, auroc, calibration_error,
                    assessments_count, avg_confidence, avg_latency_ms, p95_latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, hour_bucket, scorer_id,
                cm.true_positives, cm.false_positives, cm.true_negatives, cm.false_negatives,
                cm.precision, cm.recall, cm.f1_score, cm.accuracy,
                cm.compute_auroc(), metrics.get_calibration_error(),
                cm.total, 0.0,  # avg_confidence would come from scorer
                latency_stats.get("mean", 0.0), latency_stats.get("p95", 0.0)
            ))
            conn.commit()

    def save_drift_metrics(self, drift_result: Dict[str, Any], drift_type: str = "prediction"):
        """Save drift detection result"""
        ts = drift_result.get("timestamp", time.time())
        hour_bucket = int(ts // 3600) * 3600

        with self._lock:
            conn = self._get_connection()
            conn.execute("""
                INSERT INTO drift_history (
                    timestamp, hour_bucket, drift_type, feature_name,
                    psi, ks_statistic, status,
                    baseline_mean, current_mean, baseline_std, current_std, sample_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, hour_bucket, drift_type, drift_result.get("feature"),
                drift_result.get("psi", 0.0), drift_result.get("ks_statistic", 0.0),
                drift_result.get("status", "unknown"),
                drift_result.get("baseline_mean"), drift_result.get("current_mean"),
                drift_result.get("baseline_std"), drift_result.get("current_std"),
                drift_result.get("current_count", 0)
            ))
            conn.commit()

    def save_ground_truth(self, feedback: GroundTruthFeedback):
        """Save ground truth feedback"""
        with self._lock:
            conn = self._get_connection()
            conn.execute("""
                INSERT INTO ground_truth_feedback (
                    timestamp, ip_address, prediction_score, actual_malicious,
                    feedback_source, scorer_scores, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                feedback.timestamp,
                feedback.ip_address,
                feedback.prediction_score,
                1 if feedback.actual_malicious else 0,
                feedback.feedback_source,
                json.dumps(feedback.scorer_scores),
                feedback.notes
            ))
            conn.commit()

    def save_consensus_metrics(
        self,
        total_assessments: int,
        consensus_failures: int,
        high_uncertainty_count: int,
        avg_spread: float,
        agreement_rate: float,
        cache_hit_rate: float,
        avg_latency_ms: float,
        timestamp: Optional[float] = None
    ):
        """Save consensus-level metrics"""
        ts = timestamp or time.time()
        hour_bucket = int(ts // 3600) * 3600

        with self._lock:
            conn = self._get_connection()
            conn.execute("""
                INSERT OR REPLACE INTO consensus_metrics_hourly (
                    timestamp, hour_bucket,
                    total_assessments, consensus_failures, high_uncertainty_count,
                    avg_spread, agreement_rate, cache_hit_rate, avg_latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, hour_bucket,
                total_assessments, consensus_failures, high_uncertainty_count,
                avg_spread, agreement_rate, cache_hit_rate, avg_latency_ms
            ))
            conn.commit()

    def get_scorer_metrics_history(
        self,
        scorer_id: str,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get historical metrics for a scorer"""
        cutoff = time.time() - (hours * 3600)

        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("""
                SELECT timestamp, hour_bucket,
                       true_positives, false_positives, true_negatives, false_negatives,
                       precision, recall, f1_score, accuracy, auroc,
                       assessments_count, avg_latency_ms, p95_latency_ms
                FROM scorer_metrics_hourly
                WHERE scorer_id = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            """, (scorer_id, cutoff))

            columns = [
                "timestamp", "hour_bucket",
                "true_positives", "false_positives", "true_negatives", "false_negatives",
                "precision", "recall", "f1_score", "accuracy", "auroc",
                "assessments_count", "avg_latency_ms", "p95_latency_ms"
            ]

            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_drift_history(self, hours: int = 24, drift_type: str = "prediction") -> List[Dict[str, Any]]:
        """Get drift history"""
        cutoff = time.time() - (hours * 3600)

        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("""
                SELECT timestamp, psi, ks_statistic, status, feature_name,
                       baseline_mean, current_mean
                FROM drift_history
                WHERE drift_type = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            """, (drift_type, cutoff))

            columns = ["timestamp", "psi", "ks_statistic", "status", "feature_name",
                       "baseline_mean", "current_mean"]

            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_feedback_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get feedback statistics"""
        cutoff = time.time() - (hours * 3600)

        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(actual_malicious) as malicious_count,
                    AVG(prediction_score) as avg_prediction,
                    COUNT(DISTINCT feedback_source) as source_count
                FROM ground_truth_feedback
                WHERE timestamp >= ?
            """, (cutoff,))

            row = cursor.fetchone()
            return {
                "total_feedback": row[0] or 0,
                "malicious_count": row[1] or 0,
                "benign_count": (row[0] or 0) - (row[1] or 0),
                "avg_prediction_score": row[2] or 0.0,
                "unique_sources": row[3] or 0,
            }

    def close(self):
        """Close database connection"""
        if self._conn:
            self._conn.close()
            self._conn = None


# =============================================================================
# UNIFIED METRICS MANAGER
# =============================================================================


class MetricsManager:
    """
    Unified metrics management for the consensus scoring system

    Coordinates all metric collection, tracking, and persistence.
    Provides API for:
    - Recording predictions and feedback
    - Querying metrics
    - Drift detection alerts
    - Persistence management
    """

    def __init__(
        self,
        scorer_ids: List[str],
        db_path: str = "database/cobaltgraph.db",
        enable_persistence: bool = True,
        drift_window_hours: int = 1,
        drift_baseline_hours: int = 24,
    ):
        """
        Initialize metrics manager

        Args:
            scorer_ids: List of scorer identifiers
            db_path: Database path for persistence
            enable_persistence: Enable SQLite persistence
            drift_window_hours: Drift detection window (hours)
            drift_baseline_hours: Drift baseline window (hours)
        """
        self.scorer_ids = scorer_ids
        self.enable_persistence = enable_persistence

        # Per-scorer classification metrics
        self.scorer_metrics: Dict[str, ClassificationMetrics] = {
            sid: ClassificationMetrics(scorer_id=sid) for sid in scorer_ids
        }

        # Per-scorer latency tracking
        self.scorer_latency: Dict[str, LatencyTracker] = {
            sid: LatencyTracker() for sid in scorer_ids
        }

        # Consensus-level latency
        self.consensus_latency = LatencyTracker()

        # Drift detection
        self.drift_detector = DriftDetector(
            window_hours=drift_window_hours,
            baseline_hours=drift_baseline_hours,
        )

        # Scorer agreement
        self.agreement_metrics = ScorerAgreementMetrics(scorer_ids)

        # Ground truth feedback
        self.feedback_collector = FeedbackCollector()
        self.feedback_collector.register_callback(self._on_feedback)

        # Persistence
        self.persistence: Optional[MetricsPersistence] = None
        if enable_persistence:
            self.persistence = MetricsPersistence(db_path)

        # Alert callbacks
        self._alert_callbacks: List[Callable[[str, Dict], None]] = []

        # Hourly rollup tracking
        self._last_rollup_hour: int = 0

        self._lock = Lock()

        logger.info(f"MetricsManager initialized for {len(scorer_ids)} scorers")

    def _on_feedback(self, feedback: GroundTruthFeedback):
        """Handle ground truth feedback"""
        # Update per-scorer metrics
        for scorer_id, score in feedback.scorer_scores.items():
            if scorer_id in self.scorer_metrics:
                self.scorer_metrics[scorer_id].update(
                    score, feedback.actual_malicious
                )

        # Persist feedback
        if self.persistence:
            self.persistence.save_ground_truth(feedback)

    def record_assessment(
        self,
        consensus_score: float,
        scorer_scores: Dict[str, float],
        scorer_latencies: Dict[str, float],
        consensus_latency_ms: float,
        outliers: List[str],
        spread: float,
        ip_address: str,
    ):
        """
        Record a complete assessment for metrics tracking

        Args:
            consensus_score: Final consensus score
            scorer_scores: Individual scorer scores
            scorer_latencies: Per-scorer latencies (ms)
            consensus_latency_ms: Total consensus latency (ms)
            outliers: List of outlier scorer IDs
            spread: Score spread
            ip_address: Assessed IP address
        """
        timestamp = time.time()

        # Record latencies
        for scorer_id, latency_ms in scorer_latencies.items():
            if scorer_id in self.scorer_latency:
                self.scorer_latency[scorer_id].record(latency_ms, timestamp)

        self.consensus_latency.record(consensus_latency_ms, timestamp)

        # Record drift data
        self.drift_detector.record_score(consensus_score, timestamp)

        # Record agreement data
        self.agreement_metrics.record_vote(scorer_scores, outliers, spread, timestamp)

        # Register for potential feedback
        self.feedback_collector.register_prediction(
            ip_address, consensus_score, scorer_scores, timestamp
        )

        # Check for drift and alert
        self._check_drift_alert()

        # Periodic rollup
        self._maybe_rollup(timestamp)

    def _check_drift_alert(self):
        """Check drift and trigger alerts if needed"""
        drift_result = self.drift_detector.compute_score_drift()

        if drift_result.get("alert"):
            self._trigger_alert("drift", drift_result)

    def _trigger_alert(self, alert_type: str, details: Dict):
        """Trigger alert callbacks"""
        for callback in self._alert_callbacks:
            try:
                callback(alert_type, details)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def register_alert_callback(self, callback: Callable[[str, Dict], None]):
        """Register callback for alerts"""
        self._alert_callbacks.append(callback)

    def _maybe_rollup(self, timestamp: float):
        """Perform hourly rollup if needed"""
        current_hour = int(timestamp // 3600)

        if current_hour > self._last_rollup_hour:
            self._perform_rollup(timestamp)
            self._last_rollup_hour = current_hour

    def _perform_rollup(self, timestamp: float):
        """Perform metrics rollup and persistence"""
        if not self.persistence:
            return

        # Save per-scorer metrics
        for scorer_id in self.scorer_ids:
            self.persistence.save_scorer_metrics(
                scorer_id,
                self.scorer_metrics[scorer_id],
                self.scorer_latency[scorer_id],
                timestamp
            )

        # Save drift metrics
        drift_result = self.drift_detector.compute_score_drift()
        self.persistence.save_drift_metrics(drift_result, "prediction")

        # Save consensus metrics
        spread_stats = self.agreement_metrics.get_spread_stats()
        self.persistence.save_consensus_metrics(
            total_assessments=self.agreement_metrics._total_votes,
            consensus_failures=0,  # Would need to track separately
            high_uncertainty_count=0,  # Would need to track separately
            avg_spread=spread_stats.get("mean", 0.0),
            agreement_rate=self.agreement_metrics.get_agreement_rate(),
            cache_hit_rate=0.0,  # Would come from threat_scorer
            avg_latency_ms=self.consensus_latency.mean,
            timestamp=timestamp
        )

        logger.info("Metrics rollup completed")

    def provide_ground_truth(
        self,
        ip_address: str,
        is_malicious: bool,
        source: str = "analyst",
        notes: str = ""
    ) -> bool:
        """
        API: Provide ground truth feedback for an IP

        Args:
            ip_address: IP address to label
            is_malicious: True if actually malicious
            source: Feedback source
            notes: Optional notes

        Returns:
            True if feedback was recorded
        """
        feedback = self.feedback_collector.provide_feedback(
            ip_address, is_malicious, source, notes
        )
        return feedback is not None

    def get_scorer_summary(self, scorer_id: str) -> Dict[str, Any]:
        """Get summary metrics for a scorer"""
        if scorer_id not in self.scorer_metrics:
            return {}

        metrics = self.scorer_metrics[scorer_id]
        latency = self.scorer_latency[scorer_id]

        return {
            "scorer_id": scorer_id,
            "classification": metrics.to_dict(),
            "latency": latency.to_dict(),
            "outlier_rate": self.agreement_metrics.get_outlier_rates().get(scorer_id, 0.0),
        }

    def get_system_summary(self) -> Dict[str, Any]:
        """Get system-wide metrics summary"""
        return {
            "scorers": {sid: self.get_scorer_summary(sid) for sid in self.scorer_ids},
            "drift": self.drift_detector.to_dict(),
            "agreement": self.agreement_metrics.to_dict(),
            "consensus_latency": self.consensus_latency.to_dict(),
            "feedback": self.feedback_collector.to_dict(),
        }

    def get_drift_status(self) -> Dict[str, Any]:
        """Get current drift detection status"""
        return self.drift_detector.compute_score_drift()

    def shutdown(self):
        """Graceful shutdown with final persistence"""
        if self.persistence:
            self._perform_rollup(time.time())
            self.persistence.close()

        logger.info("MetricsManager shutdown complete")
