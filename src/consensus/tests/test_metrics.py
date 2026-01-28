"""
Comprehensive Tests for Metrics Module

Tests:
- ConfusionMatrix and classification metrics
- DriftDetector with PSI calculations
- LatencyTracker with percentiles
- ScorerAgreementMetrics
- FeedbackCollector and ground truth pipeline
- MetricsPersistence SQLite integration
- MetricsManager unified coordination
- Integration with scorer_base and threat_scorer
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.consensus.metrics import (
    ConfusionMatrix,
    ClassificationMetrics,
    DriftDetector,
    LatencyTracker,
    ScorerAgreementMetrics,
    FeedbackCollector,
    GroundTruthFeedback,
    MetricsPersistence,
    MetricsManager,
)
from src.consensus.scorer_base import ThreatScorer, ScorerAssessment


# =============================================================================
# TEST: ConfusionMatrix
# =============================================================================


class TestConfusionMatrix(unittest.TestCase):
    """Tests for ConfusionMatrix class"""

    def setUp(self):
        self.cm = ConfusionMatrix()

    def test_initial_state(self):
        """Test initial confusion matrix is all zeros"""
        self.assertEqual(self.cm.true_positives, 0)
        self.assertEqual(self.cm.false_positives, 0)
        self.assertEqual(self.cm.true_negatives, 0)
        self.assertEqual(self.cm.false_negatives, 0)
        self.assertEqual(self.cm.total, 0)

    def test_true_positive(self):
        """Test true positive counting"""
        self.cm.update(predicted_score=0.8, actual_malicious=True)
        self.assertEqual(self.cm.true_positives, 1)
        self.assertEqual(self.cm.total, 1)

    def test_false_positive(self):
        """Test false positive counting"""
        self.cm.update(predicted_score=0.8, actual_malicious=False)
        self.assertEqual(self.cm.false_positives, 1)

    def test_true_negative(self):
        """Test true negative counting"""
        self.cm.update(predicted_score=0.2, actual_malicious=False)
        self.assertEqual(self.cm.true_negatives, 1)

    def test_false_negative(self):
        """Test false negative counting"""
        self.cm.update(predicted_score=0.2, actual_malicious=True)
        self.assertEqual(self.cm.false_negatives, 1)

    def test_custom_threshold(self):
        """Test custom classification threshold"""
        # With threshold 0.7, score 0.6 should be negative
        self.cm.update(predicted_score=0.6, actual_malicious=True, threshold=0.7)
        self.assertEqual(self.cm.false_negatives, 1)

        # With threshold 0.3, score 0.4 should be positive
        self.cm.update(predicted_score=0.4, actual_malicious=False, threshold=0.3)
        self.assertEqual(self.cm.false_positives, 1)

    def test_accuracy(self):
        """Test accuracy calculation"""
        # 2 correct, 2 incorrect
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.2, False)  # TN
        self.cm.update(0.8, False)  # FP
        self.cm.update(0.2, True)   # FN

        self.assertEqual(self.cm.accuracy, 0.5)

    def test_precision(self):
        """Test precision: TP / (TP + FP)"""
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.8, False)  # FP

        # Precision = 2 / (2 + 1) = 0.667
        self.assertAlmostEqual(self.cm.precision, 2/3, places=3)

    def test_recall(self):
        """Test recall: TP / (TP + FN)"""
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.2, True)   # FN

        # Recall = 2 / (2 + 1) = 0.667
        self.assertAlmostEqual(self.cm.recall, 2/3, places=3)

    def test_f1_score(self):
        """Test F1 score calculation"""
        # Create a balanced scenario
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.2, False)  # TN
        self.cm.update(0.8, False)  # FP
        self.cm.update(0.2, True)   # FN

        # Precision = 2/3, Recall = 2/3, F1 = 2 * (2/3 * 2/3) / (2/3 + 2/3) = 2/3
        self.assertAlmostEqual(self.cm.f1_score, 2/3, places=3)

    def test_specificity(self):
        """Test specificity: TN / (TN + FP)"""
        self.cm.update(0.2, False)  # TN
        self.cm.update(0.2, False)  # TN
        self.cm.update(0.8, False)  # FP

        self.assertAlmostEqual(self.cm.specificity, 2/3, places=3)

    def test_false_positive_rate(self):
        """Test FPR: FP / (FP + TN)"""
        self.cm.update(0.8, False)  # FP
        self.cm.update(0.2, False)  # TN
        self.cm.update(0.2, False)  # TN

        self.assertAlmostEqual(self.cm.false_positive_rate, 1/3, places=3)

    def test_false_negative_rate(self):
        """Test FNR: FN / (FN + TP)"""
        self.cm.update(0.2, True)   # FN
        self.cm.update(0.8, True)   # TP
        self.cm.update(0.8, True)   # TP

        self.assertAlmostEqual(self.cm.false_negative_rate, 1/3, places=3)

    def test_zero_division_protection(self):
        """Test that zero division is handled gracefully"""
        # Empty matrix
        self.assertEqual(self.cm.precision, 0.0)
        self.assertEqual(self.cm.recall, 0.0)
        self.assertEqual(self.cm.f1_score, 0.0)
        self.assertEqual(self.cm.accuracy, 0.0)

    def test_to_dict(self):
        """Test serialization to dictionary"""
        self.cm.update(0.8, True)
        self.cm.update(0.2, False)

        d = self.cm.to_dict()
        self.assertIn("true_positives", d)
        self.assertIn("precision", d)
        self.assertIn("recall", d)
        self.assertIn("f1_score", d)
        self.assertEqual(d["total"], 2)

    def test_reset(self):
        """Test matrix reset"""
        self.cm.update(0.8, True)
        self.cm.update(0.8, True)
        self.assertEqual(self.cm.total, 2)

        self.cm.reset()
        self.assertEqual(self.cm.total, 0)
        self.assertEqual(self.cm.true_positives, 0)

    def test_roc_points_computation(self):
        """Test ROC curve point computation"""
        # Add diverse samples
        for i in range(10):
            self.cm.update(i/10, i % 2 == 0)

        points = self.cm.compute_roc_points(num_thresholds=10)
        self.assertGreater(len(points), 0)
        self.assertEqual(len(points[0]), 3)  # (threshold, tpr, fpr)

    def test_auroc_computation(self):
        """Test AU-ROC calculation"""
        # Create a good but not perfect classifier
        # Malicious samples get higher scores
        import random
        random.seed(42)

        for _ in range(50):
            # Malicious: scores between 0.6-0.95
            self.cm.update(0.6 + random.random() * 0.35, True)
            # Benign: scores between 0.05-0.4
            self.cm.update(0.05 + random.random() * 0.35, False)

        auroc = self.cm.compute_auroc()
        # With this separation, AUROC should be high
        self.assertGreater(auroc, 0.85)  # Should be close to 1.0


# =============================================================================
# TEST: ClassificationMetrics
# =============================================================================


class TestClassificationMetrics(unittest.TestCase):
    """Tests for ClassificationMetrics class"""

    def setUp(self):
        self.metrics = ClassificationMetrics(scorer_id="test_scorer")

    def test_initialization(self):
        """Test proper initialization"""
        self.assertEqual(self.metrics.scorer_id, "test_scorer")
        self.assertIsNotNone(self.metrics.confusion_matrix)

    def test_update_flows_to_confusion_matrix(self):
        """Test that updates flow to confusion matrix"""
        self.metrics.update(0.8, True)
        self.assertEqual(self.metrics.confusion_matrix.true_positives, 1)

    def test_calibration_bins(self):
        """Test calibration binning"""
        # Add samples at different predicted probabilities
        self.metrics.update(0.1, False)
        self.metrics.update(0.9, True)

        curve = self.metrics.get_calibration_curve()
        self.assertEqual(len(curve), 10)  # 10 bins

    def test_calibration_error(self):
        """Test Expected Calibration Error"""
        # Well-calibrated: 90% predictions correct at 90% confidence
        for _ in range(9):
            self.metrics.update(0.9, True)
        self.metrics.update(0.9, False)

        ece = self.metrics.get_calibration_error()
        self.assertLess(ece, 0.2)  # Should be low for well-calibrated

    def test_optimal_threshold_finding(self):
        """Test optimal threshold search"""
        # Add data where threshold 0.3 would be better
        for _ in range(10):
            self.metrics.update(0.4, True)
            self.metrics.update(0.2, False)

        threshold = self.metrics.find_optimal_threshold()
        self.assertGreater(threshold, 0.0)
        self.assertLess(threshold, 1.0)

    def test_to_dict(self):
        """Test serialization"""
        self.metrics.update(0.8, True)
        d = self.metrics.to_dict()

        self.assertIn("scorer_id", d)
        self.assertIn("confusion_matrix", d)
        self.assertIn("calibration_error", d)


# =============================================================================
# TEST: DriftDetector
# =============================================================================


class TestDriftDetector(unittest.TestCase):
    """Tests for DriftDetector class"""

    def setUp(self):
        self.detector = DriftDetector(
            num_bins=10,
            window_hours=1,
            baseline_hours=24,
        )

    def test_record_score(self):
        """Test score recording"""
        self.detector.record_score(0.5)
        self.assertEqual(len(self.detector._score_history), 1)

    def test_record_feature(self):
        """Test feature recording"""
        self.detector.record_feature("port_risk", 0.8)
        self.assertIn("port_risk", self.detector._feature_history)

    def test_distribution_computation(self):
        """Test binned distribution computation"""
        values = [0.1, 0.2, 0.3, 0.5, 0.5, 0.9]
        dist = self.detector._compute_distribution(values)

        self.assertEqual(len(dist), 10)
        self.assertAlmostEqual(sum(dist), 1.0, places=5)

    def test_psi_calculation_no_drift(self):
        """Test PSI calculation with identical distributions"""
        baseline = [0.1] * 10
        current = [0.1] * 10

        psi = self.detector._calculate_psi(baseline, current)
        self.assertAlmostEqual(psi, 0.0, places=5)

    def test_psi_calculation_with_drift(self):
        """Test PSI calculation with different distributions"""
        baseline = [0.2, 0.2, 0.2, 0.1, 0.1, 0.05, 0.05, 0.05, 0.025, 0.025]
        current = [0.05, 0.05, 0.1, 0.1, 0.2, 0.2, 0.1, 0.1, 0.05, 0.05]

        psi = self.detector._calculate_psi(baseline, current)
        self.assertGreater(psi, 0.0)

    def test_ks_statistic(self):
        """Test Kolmogorov-Smirnov statistic"""
        baseline = [0.1] * 10
        current = [0.2, 0.2, 0.1, 0.1, 0.1, 0.1, 0.05, 0.05, 0.05, 0.05]

        ks = self.detector._calculate_ks_statistic(baseline, current)
        self.assertGreaterEqual(ks, 0.0)
        self.assertLessEqual(ks, 1.0)

    def test_drift_status_insufficient_data(self):
        """Test drift detection with insufficient data"""
        # Add only a few samples
        for i in range(10):
            self.detector.record_score(0.5)

        result = self.detector.compute_score_drift()
        self.assertEqual(result["status"], "insufficient_data")

    def test_drift_thresholds(self):
        """Test drift threshold constants"""
        self.assertEqual(self.detector.PSI_THRESHOLD_MODERATE, 0.10)
        self.assertEqual(self.detector.PSI_THRESHOLD_SIGNIFICANT, 0.25)

    def test_drift_trend(self):
        """Test drift trend history"""
        # Record some drift results
        self.detector._drift_history.append((time.time(), 0.15, "moderate_drift"))
        self.detector._drift_history.append((time.time(), 0.30, "significant_drift"))

        trend = self.detector.get_drift_trend(hours=24)
        self.assertEqual(len(trend), 2)


# =============================================================================
# TEST: LatencyTracker
# =============================================================================


class TestLatencyTracker(unittest.TestCase):
    """Tests for LatencyTracker class"""

    def setUp(self):
        self.tracker = LatencyTracker(window_size=1000)

    def test_record_latency(self):
        """Test latency recording"""
        self.tracker.record(10.5)
        self.tracker.record(20.3)
        self.assertEqual(len(self.tracker._latencies), 2)

    def test_percentile_calculation(self):
        """Test percentile calculation"""
        # Add known latencies
        for i in range(100):
            self.tracker.record(float(i))

        # p50 should be around 49-50
        self.assertGreaterEqual(self.tracker.p50, 48)
        self.assertLessEqual(self.tracker.p50, 51)

        # p99 should be close to 99
        self.assertGreaterEqual(self.tracker.p99, 97)

    def test_mean_calculation(self):
        """Test mean latency"""
        self.tracker.record(10.0)
        self.tracker.record(20.0)
        self.tracker.record(30.0)

        self.assertAlmostEqual(self.tracker.mean, 20.0, places=1)

    def test_min_max_tracking(self):
        """Test min/max tracking"""
        self.tracker.record(5.0)
        self.tracker.record(100.0)
        self.tracker.record(50.0)

        self.assertEqual(self.tracker._min_latency, 5.0)
        self.assertEqual(self.tracker._max_latency, 100.0)

    def test_empty_tracker(self):
        """Test behavior with no data"""
        self.assertEqual(self.tracker.p50, 0.0)
        self.assertEqual(self.tracker.mean, 0.0)

    def test_recent_stats(self):
        """Test recent stats with time window"""
        self.tracker.record(10.0)
        self.tracker.record(20.0)

        stats = self.tracker.get_recent_stats(window_seconds=3600)
        self.assertIn("p50", stats)
        self.assertIn("p95", stats)
        self.assertIn("mean", stats)
        self.assertEqual(stats["count"], 2)

    def test_to_dict(self):
        """Test serialization"""
        self.tracker.record(10.0)
        d = self.tracker.to_dict()

        self.assertIn("p50", d)
        self.assertIn("p90", d)
        self.assertIn("p95", d)
        self.assertIn("p99", d)
        self.assertIn("mean", d)


# =============================================================================
# TEST: ScorerAgreementMetrics
# =============================================================================


class TestScorerAgreementMetrics(unittest.TestCase):
    """Tests for ScorerAgreementMetrics class"""

    def setUp(self):
        self.scorer_ids = ["statistical", "rule_based", "heuristic"]
        self.agreement = ScorerAgreementMetrics(self.scorer_ids)

    def test_initialization(self):
        """Test proper initialization"""
        self.assertEqual(len(self.agreement.scorer_ids), 3)
        self.assertEqual(self.agreement._total_votes, 0)

    def test_record_vote(self):
        """Test vote recording"""
        scores = {"statistical": 0.7, "rule_based": 0.8, "heuristic": 0.75}
        self.agreement.record_vote(scores, outliers=[], spread=0.1)

        self.assertEqual(self.agreement._total_votes, 1)

    def test_outlier_tracking(self):
        """Test outlier counting"""
        scores = {"statistical": 0.7, "rule_based": 0.3, "heuristic": 0.75}
        self.agreement.record_vote(scores, outliers=["rule_based"], spread=0.45)

        rates = self.agreement.get_outlier_rates()
        self.assertEqual(rates["rule_based"], 1.0)
        self.assertEqual(rates["statistical"], 0.0)

    def test_agreement_rate(self):
        """Test agreement rate calculation"""
        # High agreement votes (low spread)
        for _ in range(8):
            self.agreement.record_vote(
                {"statistical": 0.7, "rule_based": 0.72, "heuristic": 0.71},
                outliers=[],
                spread=0.02
            )

        # Low agreement votes (high spread)
        for _ in range(2):
            self.agreement.record_vote(
                {"statistical": 0.9, "rule_based": 0.3, "heuristic": 0.6},
                outliers=["rule_based"],
                spread=0.6
            )

        rate = self.agreement.get_agreement_rate(threshold=0.15)
        self.assertGreaterEqual(rate, 0.7)

    def test_spread_stats(self):
        """Test spread statistics"""
        self.agreement.record_vote({}, [], spread=0.1)
        self.agreement.record_vote({}, [], spread=0.2)
        self.agreement.record_vote({}, [], spread=0.3)

        stats = self.agreement.get_spread_stats()
        self.assertAlmostEqual(stats["mean"], 0.2, places=2)
        self.assertEqual(stats["min"], 0.1)
        self.assertEqual(stats["max"], 0.3)

    def test_correlation_insufficient_data(self):
        """Test correlation with insufficient data"""
        corr = self.agreement.compute_correlation("statistical", "rule_based")
        self.assertEqual(corr, 0.0)

    def test_to_dict(self):
        """Test serialization"""
        self.agreement.record_vote(
            {"statistical": 0.7, "rule_based": 0.8, "heuristic": 0.75},
            outliers=[],
            spread=0.1
        )

        d = self.agreement.to_dict()
        self.assertIn("total_votes", d)
        self.assertIn("outlier_rates", d)
        self.assertIn("agreement_rate", d)


# =============================================================================
# TEST: FeedbackCollector
# =============================================================================


class TestFeedbackCollector(unittest.TestCase):
    """Tests for FeedbackCollector class"""

    def setUp(self):
        self.collector = FeedbackCollector(max_pending=100, pending_ttl=3600)

    def test_register_prediction(self):
        """Test prediction registration"""
        self.collector.register_prediction(
            ip_address="192.168.1.100",
            consensus_score=0.7,
            scorer_scores={"statistical": 0.8, "rule_based": 0.6}
        )

        self.assertEqual(self.collector.get_pending_count(), 1)

    def test_provide_feedback(self):
        """Test feedback provision"""
        # Register prediction
        self.collector.register_prediction(
            ip_address="192.168.1.100",
            consensus_score=0.7,
            scorer_scores={"statistical": 0.8}
        )

        # Provide feedback
        feedback = self.collector.provide_feedback(
            ip_address="192.168.1.100",
            actual_malicious=True,
            source="analyst"
        )

        self.assertIsNotNone(feedback)
        self.assertEqual(feedback.ip_address, "192.168.1.100")
        self.assertTrue(feedback.actual_malicious)
        self.assertEqual(feedback.feedback_source, "analyst")

        # Pending should be cleared
        self.assertEqual(self.collector.get_pending_count(), 0)

    def test_feedback_for_unknown_ip(self):
        """Test feedback for unregistered IP"""
        feedback = self.collector.provide_feedback(
            ip_address="10.0.0.1",
            actual_malicious=False
        )

        self.assertIsNone(feedback)

    def test_callback_notification(self):
        """Test callback notification on feedback"""
        received_feedback = []

        def callback(fb):
            received_feedback.append(fb)

        self.collector.register_callback(callback)

        self.collector.register_prediction("192.168.1.1", 0.5, {})
        self.collector.provide_feedback("192.168.1.1", True)

        self.assertEqual(len(received_feedback), 1)

    def test_feedback_history(self):
        """Test feedback history retrieval"""
        self.collector.register_prediction("192.168.1.1", 0.5, {})
        self.collector.provide_feedback("192.168.1.1", True)

        self.collector.register_prediction("192.168.1.2", 0.3, {})
        self.collector.provide_feedback("192.168.1.2", False)

        history = self.collector.get_feedback_history(limit=10)
        self.assertEqual(len(history), 2)


# =============================================================================
# TEST: MetricsPersistence
# =============================================================================


class TestMetricsPersistence(unittest.TestCase):
    """Tests for MetricsPersistence SQLite integration"""

    def setUp(self):
        # Use temporary file for testing
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_metrics.db")
        self.persistence = MetricsPersistence(db_path=self.db_path)

    def tearDown(self):
        self.persistence.close()
        # Cleanup temp files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_creation(self):
        """Test database schema is created"""
        conn = self.persistence._get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}

        self.assertIn("scorer_metrics_hourly", tables)
        self.assertIn("drift_history", tables)
        self.assertIn("ground_truth_feedback", tables)
        self.assertIn("consensus_metrics_hourly", tables)

    def test_save_scorer_metrics(self):
        """Test saving scorer metrics"""
        metrics = ClassificationMetrics(scorer_id="test")
        metrics.update(0.8, True)
        metrics.update(0.2, False)

        latency = LatencyTracker()
        latency.record(10.0)

        self.persistence.save_scorer_metrics("test", metrics, latency)

        # Verify saved
        history = self.persistence.get_scorer_metrics_history("test", hours=24)
        self.assertGreater(len(history), 0)

    def test_save_drift_metrics(self):
        """Test saving drift metrics"""
        drift_result = {
            "psi": 0.15,
            "ks_statistic": 0.12,
            "status": "moderate_drift",
            "timestamp": time.time(),
        }

        self.persistence.save_drift_metrics(drift_result, "prediction")

        history = self.persistence.get_drift_history(hours=24)
        self.assertGreater(len(history), 0)

    def test_save_ground_truth(self):
        """Test saving ground truth feedback"""
        feedback = GroundTruthFeedback(
            ip_address="192.168.1.100",
            prediction_score=0.7,
            actual_malicious=True,
            feedback_source="analyst",
            timestamp=time.time(),
            scorer_scores={"test": 0.7},
        )

        self.persistence.save_ground_truth(feedback)

        stats = self.persistence.get_feedback_stats(hours=24)
        self.assertEqual(stats["total_feedback"], 1)
        self.assertEqual(stats["malicious_count"], 1)


# =============================================================================
# TEST: MetricsManager Integration
# =============================================================================


class TestMetricsManager(unittest.TestCase):
    """Integration tests for MetricsManager"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_metrics.db")
        self.scorer_ids = ["statistical", "rule_based", "heuristic"]
        self.manager = MetricsManager(
            scorer_ids=self.scorer_ids,
            db_path=self.db_path,
            enable_persistence=True,
            drift_window_hours=1,
            drift_baseline_hours=24,
        )

    def tearDown(self):
        self.manager.shutdown()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test proper initialization"""
        self.assertEqual(len(self.manager.scorer_ids), 3)
        self.assertIsNotNone(self.manager.drift_detector)
        self.assertIsNotNone(self.manager.feedback_collector)

    def test_record_assessment(self):
        """Test assessment recording"""
        self.manager.record_assessment(
            consensus_score=0.7,
            scorer_scores={"statistical": 0.8, "rule_based": 0.6, "heuristic": 0.7},
            scorer_latencies={"statistical": 10.0, "rule_based": 15.0, "heuristic": 12.0},
            consensus_latency_ms=20.0,
            outliers=[],
            spread=0.2,
            ip_address="192.168.1.100",
        )

        # Check latency was recorded
        latency = self.manager.consensus_latency.to_dict()
        self.assertEqual(latency["count"], 1)

    def test_ground_truth_api(self):
        """Test ground truth feedback API"""
        # Register prediction
        self.manager.record_assessment(
            consensus_score=0.7,
            scorer_scores={"statistical": 0.8, "rule_based": 0.6, "heuristic": 0.7},
            scorer_latencies={},
            consensus_latency_ms=10.0,
            outliers=[],
            spread=0.2,
            ip_address="192.168.1.100",
        )

        # Provide feedback
        result = self.manager.provide_ground_truth(
            ip_address="192.168.1.100",
            is_malicious=True,
            source="analyst"
        )

        self.assertTrue(result)

    def test_get_scorer_summary(self):
        """Test per-scorer summary"""
        summary = self.manager.get_scorer_summary("statistical")

        self.assertIn("scorer_id", summary)
        self.assertIn("classification", summary)
        self.assertIn("latency", summary)

    def test_get_system_summary(self):
        """Test full system summary"""
        summary = self.manager.get_system_summary()

        self.assertIn("scorers", summary)
        self.assertIn("drift", summary)
        self.assertIn("agreement", summary)
        self.assertIn("feedback", summary)

    def test_alert_callback(self):
        """Test alert callback registration"""
        alerts_received = []

        def alert_handler(alert_type, details):
            alerts_received.append((alert_type, details))

        self.manager.register_alert_callback(alert_handler)
        self.assertEqual(len(self.manager._alert_callbacks), 1)


# =============================================================================
# TEST: Scorer Base Integration
# =============================================================================


class ConcreteScorer(ThreatScorer):
    """Concrete implementation for testing"""

    def assess(self, dst_ip, threat_intel, geo_data, connection_metadata):
        score = 0.5
        confidence = 0.8

        signature = self._sign_assessment(score, confidence, time.time())

        assessment = ScorerAssessment(
            scorer_id=self.scorer_id,
            score=score,
            confidence=confidence,
            reasoning="Test assessment",
            features={"test": 1.0},
            timestamp=time.time(),
            signature=signature,
        )

        self._record_assessment(assessment)
        return assessment


class TestScorerBaseIntegration(unittest.TestCase):
    """Test scorer_base.py integration with metrics"""

    def setUp(self):
        self.scorer = ConcreteScorer(scorer_id="test_scorer")

    def test_metrics_lazy_initialization(self):
        """Test lazy metrics initialization"""
        self.assertFalse(self.scorer._metrics_initialized)

        # Trigger initialization
        self.scorer._init_metrics()

        self.assertTrue(self.scorer._metrics_initialized)
        self.assertIsNotNone(self.scorer._classification_metrics)
        self.assertIsNotNone(self.scorer._latency_tracker)

    def test_record_latency(self):
        """Test latency recording"""
        self.scorer.record_latency(15.5)

        latency_metrics = self.scorer.get_latency_metrics()
        self.assertEqual(latency_metrics["count"], 1)

    def test_update_ground_truth(self):
        """Test ground truth update"""
        self.scorer.update_ground_truth(0.8, True)
        self.scorer.update_ground_truth(0.2, False)
        self.scorer.update_ground_truth(0.8, False)  # FP

        cm = self.scorer.get_confusion_matrix()
        self.assertEqual(cm["true_positives"], 1)
        self.assertEqual(cm["true_negatives"], 1)
        self.assertEqual(cm["false_positives"], 1)

    def test_get_classification_metrics(self):
        """Test classification metrics retrieval"""
        self.scorer.update_ground_truth(0.8, True)

        metrics = self.scorer.get_classification_metrics()
        self.assertIn("confusion_matrix", metrics)
        self.assertIn("calibration_error", metrics)

    def test_get_precision_recall_f1(self):
        """Test individual metric accessors"""
        self.scorer.update_ground_truth(0.8, True)   # TP
        self.scorer.update_ground_truth(0.8, True)   # TP
        self.scorer.update_ground_truth(0.8, False)  # FP

        precision = self.scorer.get_precision()
        self.assertAlmostEqual(precision, 2/3, places=2)

    def test_recent_scores_tracking(self):
        """Test score history tracking"""
        # Make some assessments
        for i in range(5):
            self.scorer.assess("192.168.1.1", {}, {}, {})

        scores = self.scorer.get_recent_scores()
        self.assertEqual(len(scores), 5)

    def test_get_enhanced_stats(self):
        """Test enhanced statistics"""
        self.scorer.assess("192.168.1.1", {}, {}, {})
        self.scorer.record_latency(10.0)
        self.scorer.update_ground_truth(0.5, True)

        stats = self.scorer.get_enhanced_stats()

        self.assertIn("scorer_id", stats)
        self.assertIn("assessments_made", stats)
        self.assertIn("classification", stats)
        self.assertIn("latency", stats)

    def test_feedback_callback(self):
        """Test feedback callback mechanism"""
        received = []

        def callback(score, actual):
            received.append((score, actual))

        self.scorer.register_feedback_callback(callback)
        self.scorer.update_ground_truth(0.8, True)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0], (0.8, True))


# =============================================================================
# TEST: Full Pipeline Integration
# =============================================================================


class TestFullPipelineIntegration(unittest.TestCase):
    """End-to-end integration tests"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_metrics.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_workflow(self):
        """Test complete assessment -> feedback -> metrics workflow"""
        # Create metrics manager
        manager = MetricsManager(
            scorer_ids=["test"],
            db_path=self.db_path,
            enable_persistence=True,
        )

        try:
            # Simulate multiple assessments
            for i in range(10):
                manager.record_assessment(
                    consensus_score=0.3 + (i * 0.05),
                    scorer_scores={"test": 0.3 + (i * 0.05)},
                    scorer_latencies={"test": 10.0 + i},
                    consensus_latency_ms=15.0 + i,
                    outliers=[],
                    spread=0.1,
                    ip_address=f"192.168.1.{i}",
                )

            # Provide feedback for some
            for i in range(5):
                manager.provide_ground_truth(
                    ip_address=f"192.168.1.{i}",
                    is_malicious=i % 2 == 0,
                    source="test"
                )

            # Get metrics
            summary = manager.get_system_summary()

            self.assertIn("scorers", summary)
            self.assertIn("drift", summary)
            self.assertIn("feedback", summary)

            # Check latency tracking
            self.assertEqual(summary["consensus_latency"]["count"], 10)

        finally:
            manager.shutdown()

    def test_drift_detection_simulation(self):
        """Test drift detection with simulated data"""
        detector = DriftDetector(window_hours=1, baseline_hours=24)

        # Add baseline data (older timestamps)
        baseline_time = time.time() - 7200  # 2 hours ago
        for i in range(200):
            detector.record_score(0.3 + (i % 10) * 0.02, timestamp=baseline_time + i)

        # Add current data with different distribution
        current_time = time.time() - 1800  # 30 min ago
        for i in range(200):
            detector.record_score(0.6 + (i % 10) * 0.02, timestamp=current_time + i)

        result = detector.compute_score_drift()

        # Should detect drift since distributions are different
        self.assertIn("psi", result)
        self.assertIn("status", result)


# =============================================================================
# RUN TESTS
# =============================================================================


if __name__ == "__main__":
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestConfusionMatrix))
    suite.addTests(loader.loadTestsFromTestCase(TestClassificationMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestDriftDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestLatencyTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestScorerAgreementMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestFeedbackCollector))
    suite.addTests(loader.loadTestsFromTestCase(TestMetricsPersistence))
    suite.addTests(loader.loadTestsFromTestCase(TestMetricsManager))
    suite.addTests(loader.loadTestsFromTestCase(TestScorerBaseIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestFullPipelineIntegration))

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
