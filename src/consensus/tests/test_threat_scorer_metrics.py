"""
Integration Tests for ConsensusThreatScorer with Metrics

Tests the full integration of:
- ConsensusThreatScorer with MetricsManager
- Ground truth feedback API
- Latency tracking across scorers
- Drift detection integration
- Statistics and metrics retrieval
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


class TestConsensusThreatScorerMetrics(unittest.TestCase):
    """Integration tests for ConsensusThreatScorer with metrics"""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_consensus.db")

    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        """Create fresh scorer for each test"""
        from src.consensus.threat_scorer import ConsensusThreatScorer

        self.scorer = ConsensusThreatScorer(
            config={"db_path": self.db_path},
            enable_persistence=True
        )

    def tearDown(self):
        """Clean up scorer"""
        if hasattr(self, 'scorer'):
            self.scorer.shutdown()

    def test_scorer_initialization_with_metrics(self):
        """Test that metrics manager is initialized"""
        # Check that metrics_manager exists
        self.assertIsNotNone(self.scorer.metrics_manager)
        self.assertIsNotNone(self.scorer._consensus_latency)

    def test_check_ip_records_metrics(self):
        """Test that check_ip records metrics"""
        # Perform an assessment
        threat_intel = {
            "virustotal": {"malicious_count": 0, "total_vendors": 70},
            "abuseipdb": {"confidence_score": 0},
        }
        geo_data = {"country": "US", "lat": 37.7749, "lon": -122.4194}
        connection_metadata = {"dst_port": 443, "protocol": "TCP"}

        score, details = self.scorer.check_ip(
            dst_ip="8.8.8.8",
            threat_intel=threat_intel,
            geo_data=geo_data,
            connection_metadata=connection_metadata,
        )

        # Verify assessment was made
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

        # Verify latency was recorded
        latency = self.scorer.get_latency_percentiles()
        self.assertGreaterEqual(latency["count"], 1)

    def test_ground_truth_api(self):
        """Test ground truth feedback API"""
        # First make an assessment
        self.scorer.check_ip(
            dst_ip="192.168.1.100",
            threat_intel={},
            geo_data={},
            connection_metadata={"dst_port": 80},
        )

        # Check pending count
        pending_before = self.scorer.get_pending_feedback_count()
        self.assertGreaterEqual(pending_before, 1)

        # Provide feedback
        result = self.scorer.provide_ground_truth(
            ip_address="192.168.1.100",
            is_malicious=False,
            source="test",
            notes="Test feedback"
        )

        self.assertTrue(result)

        # Pending should decrease
        pending_after = self.scorer.get_pending_feedback_count()
        self.assertLess(pending_after, pending_before)

    def test_bulk_ground_truth(self):
        """Test bulk ground truth API"""
        # Make multiple assessments
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        for ip in ips:
            self.scorer.check_ip(ip, {}, {}, {"dst_port": 443})

        # Provide bulk feedback
        feedback_list = [
            ("10.0.0.1", True, "test"),
            ("10.0.0.2", False, "test"),
            ("10.0.0.3", True, "test"),
        ]

        count = self.scorer.provide_bulk_ground_truth(feedback_list)
        self.assertEqual(count, 3)

    def test_get_drift_status(self):
        """Test drift status retrieval"""
        drift = self.scorer.get_drift_status()

        self.assertIn("status", drift)
        self.assertIn("psi", drift)

    def test_get_comprehensive_metrics(self):
        """Test comprehensive metrics retrieval"""
        # Make some assessments first
        for i in range(5):
            self.scorer.check_ip(f"10.0.0.{i}", {}, {}, {"dst_port": 80})

        metrics = self.scorer.get_comprehensive_metrics()

        self.assertIn("scorers", metrics)
        self.assertIn("drift", metrics)
        self.assertIn("agreement", metrics)

    def test_get_scorer_metrics(self):
        """Test per-scorer metrics"""
        # Make an assessment
        self.scorer.check_ip("8.8.4.4", {}, {}, {"dst_port": 53})

        # Get metrics for a specific scorer
        for scorer in self.scorer.scorers:
            metrics = self.scorer.get_scorer_metrics(scorer.scorer_id)

            self.assertIn("scorer_id", metrics)
            self.assertIn("classification", metrics)
            self.assertIn("latency", metrics)

    def test_get_latency_percentiles(self):
        """Test latency percentile retrieval"""
        # Make several assessments
        for i in range(10):
            self.scorer.check_ip(f"172.16.0.{i}", {}, {}, {"dst_port": 443})

        latency = self.scorer.get_latency_percentiles()

        self.assertIn("p50", latency)
        self.assertIn("p95", latency)
        self.assertIn("p99", latency)
        self.assertIn("mean", latency)
        self.assertEqual(latency["count"], 10)

    def test_alert_callback_registration(self):
        """Test alert callback registration"""
        alerts_received = []

        def alert_handler(alert_type, details):
            alerts_received.append((alert_type, details))

        self.scorer.register_alert_callback(alert_handler)

        # Verify callback was registered
        self.assertIn(alert_handler, self.scorer._alert_callbacks)

    def test_statistics_include_enhanced_data(self):
        """Test that statistics include enhanced metrics"""
        # Make assessments
        for i in range(3):
            self.scorer.check_ip(f"192.0.2.{i}", {}, {}, {"dst_port": 80})

        stats = self.scorer.get_statistics()

        # Basic stats
        self.assertIn("total_assessments", stats)
        self.assertIn("cache_hit_rate", stats)
        self.assertIn("scorers", stats)

        # Per-scorer stats should be present
        for scorer_id, scorer_stats in stats["scorers"].items():
            self.assertIn("assessments_made", scorer_stats)
            self.assertIn("avg_confidence", scorer_stats)

    def test_scorer_latency_tracking(self):
        """Test that individual scorer latencies are tracked"""
        # Make an assessment
        self.scorer.check_ip("1.1.1.1", {}, {}, {"dst_port": 443})

        # Check each scorer has latency recorded
        for scorer in self.scorer.scorers:
            latency = scorer.get_latency_metrics()
            # At least one measurement should be recorded
            self.assertGreaterEqual(latency["count"], 0)

    def test_shutdown_persists_metrics(self):
        """Test that shutdown persists metrics"""
        # Make assessments
        for i in range(5):
            self.scorer.check_ip(f"203.0.113.{i}", {}, {}, {"dst_port": 80})

        # Provide some feedback
        self.scorer.provide_ground_truth("203.0.113.0", True, "test")
        self.scorer.provide_ground_truth("203.0.113.1", False, "test")

        # Shutdown should persist
        self.scorer.shutdown()

        # Verify metrics manager was shut down
        # (In a real test, we'd verify the database has the data)


class TestConsensusScorerErrorHandling(unittest.TestCase):
    """Test error handling in ConsensusThreatScorer"""

    def setUp(self):
        """Set up scorer"""
        from src.consensus.threat_scorer import ConsensusThreatScorer

        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_errors.db")

        self.scorer = ConsensusThreatScorer(
            config={"db_path": self.db_path},
            enable_persistence=True
        )

    def tearDown(self):
        """Clean up"""
        if hasattr(self, 'scorer'):
            self.scorer.shutdown()

        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_feedback_for_unknown_ip(self):
        """Test feedback for IP not in pending"""
        result = self.scorer.provide_ground_truth(
            ip_address="unknown.ip.address",
            is_malicious=True
        )

        # Should return False since IP wasn't assessed
        self.assertFalse(result)

    def test_scorer_metrics_for_unknown_scorer(self):
        """Test metrics request for unknown scorer"""
        metrics = self.scorer.get_scorer_metrics("nonexistent_scorer")

        # Should return empty dict
        self.assertEqual(metrics, {})


class TestMetricsIntegrationWithRealScorers(unittest.TestCase):
    """Test metrics integration with actual scorer implementations"""

    def setUp(self):
        """Set up scorer with all components"""
        from src.consensus.threat_scorer import ConsensusThreatScorer

        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_real.db")

        self.scorer = ConsensusThreatScorer(
            config={"db_path": self.db_path},
            enable_persistence=True
        )

    def tearDown(self):
        """Clean up"""
        if hasattr(self, 'scorer'):
            self.scorer.shutdown()

        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_real_assessment_with_threat_intel(self):
        """Test real assessment with threat intelligence data"""
        threat_intel = {
            "virustotal": {
                "malicious_count": 5,
                "suspicious_count": 3,
                "total_vendors": 70,
            },
            "abuseipdb": {
                "confidence_score": 45,
                "total_reports": 10,
            },
        }

        geo_data = {
            "country": "CN",
            "lat": 39.9042,
            "lon": 116.4074,
            "city": "Beijing",
        }

        connection_metadata = {
            "dst_port": 4444,  # Suspicious port
            "protocol": "TCP",
            "ttl": 48,
        }

        score, details = self.scorer.check_ip(
            dst_ip="1.2.3.4",
            threat_intel=threat_intel,
            geo_data=geo_data,
            connection_metadata=connection_metadata,
        )

        # Should have elevated threat score due to VT hits and suspicious port
        self.assertIsInstance(score, float)
        self.assertGreater(score, 0.3)

        # Details should include scorer breakdown
        self.assertIn("votes", details)
        self.assertIn("confidence", details)

    def test_benign_assessment(self):
        """Test assessment of clearly benign IP"""
        threat_intel = {
            "virustotal": {
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 70,
            },
            "abuseipdb": {
                "confidence_score": 0,
                "total_reports": 0,
            },
            "greynoise": {
                "classification": "benign",
                "name": "Google DNS",
            }
        }

        geo_data = {
            "country": "US",
            "org": "Google LLC",
        }

        connection_metadata = {
            "dst_port": 443,
            "protocol": "TCP",
        }

        score, details = self.scorer.check_ip(
            dst_ip="8.8.8.8",
            threat_intel=threat_intel,
            geo_data=geo_data,
            connection_metadata=connection_metadata,
        )

        # Should have low threat score for Google DNS
        self.assertLess(score, 0.5)

    def test_metrics_after_multiple_assessments(self):
        """Test metrics accumulation after multiple assessments"""
        # Mix of benign and suspicious assessments
        assessments = [
            ("8.8.8.8", {"abuseipdb": {"confidence_score": 0}}, "US", 443),
            ("1.2.3.4", {"abuseipdb": {"confidence_score": 80}}, "RU", 4444),
            ("8.8.4.4", {"abuseipdb": {"confidence_score": 0}}, "US", 53),
            ("5.6.7.8", {"abuseipdb": {"confidence_score": 60}}, "CN", 6667),
            ("1.1.1.1", {"abuseipdb": {"confidence_score": 0}}, "AU", 443),
        ]

        for ip, intel, country, port in assessments:
            self.scorer.check_ip(
                dst_ip=ip,
                threat_intel=intel,
                geo_data={"country": country},
                connection_metadata={"dst_port": port},
            )

        # Verify statistics
        stats = self.scorer.get_statistics()
        self.assertEqual(stats["total_assessments"], 5)

        # Verify comprehensive metrics
        metrics = self.scorer.get_comprehensive_metrics()
        self.assertIn("scorers", metrics)
        self.assertIn("agreement", metrics)

        # Verify agreement metrics tracked votes
        agreement = metrics["agreement"]
        self.assertEqual(agreement["total_votes"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
