#!/usr/bin/env python3
"""
Unit Tests: BFT Consensus Algorithm
Tests Byzantine fault tolerant voting and consensus
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.consensus.bft_consensus import BFTConsensus
from src.consensus.scorer_base import ScorerAssessment


class TestBFTConsensus(unittest.TestCase):
    """Test cases for Byzantine Fault Tolerant consensus"""

    def setUp(self):
        """Set up test fixtures"""
        self.consensus = BFTConsensus(
            min_scorers=2,
            outlier_threshold=0.3,
            uncertainty_threshold=0.25
        )

    def create_assessment(self, scorer_id, score, confidence):
        """Helper to create test assessment"""
        return ScorerAssessment(
            scorer_id=scorer_id,
            score=score,
            confidence=confidence,
            reasoning=f"Test assessment from {scorer_id}",
            features={},
            timestamp=0.0,
            signature="test_signature"
        )

    def test_perfect_agreement(self):
        """Test consensus when all scorers agree"""
        assessments = [
            self.create_assessment('scorer_1', 0.75, 0.9),
            self.create_assessment('scorer_2', 0.75, 0.9),
            self.create_assessment('scorer_3', 0.75, 0.9),
        ]

        result = self.consensus.achieve_consensus(assessments)

        self.assertIsNotNone(result)
        self.assertEqual(result.consensus_score, 0.75)
        self.assertEqual(len(result.outliers), 0)
        self.assertFalse(result.high_uncertainty)

    def test_median_calculation(self):
        """Test median-based consensus"""
        assessments = [
            self.create_assessment('scorer_1', 0.3, 0.8),
            self.create_assessment('scorer_2', 0.5, 0.8),
            self.create_assessment('scorer_3', 0.7, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Median of [0.3, 0.5, 0.7] is 0.5
        self.assertEqual(result.consensus_score, 0.5)
        self.assertEqual(result.method, 'median_bft')

    def test_outlier_detection(self):
        """Test detection of outlier scorers"""
        assessments = [
            self.create_assessment('scorer_1', 0.2, 0.8),
            self.create_assessment('scorer_2', 0.25, 0.8),
            self.create_assessment('scorer_3', 0.9, 0.8),  # Outlier
        ]

        result = self.consensus.achieve_consensus(assessments)

        self.assertIn('scorer_3', result.outliers)
        self.assertEqual(len(result.outliers), 1)
        # Consensus should use median of non-outliers
        self.assertLess(result.consensus_score, 0.5)

    def test_high_uncertainty_detection(self):
        """Test detection of high uncertainty (large spread)"""
        assessments = [
            self.create_assessment('scorer_1', 0.1, 0.8),
            self.create_assessment('scorer_2', 0.5, 0.8),
            self.create_assessment('scorer_3', 0.9, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Spread = 0.9 - 0.1 = 0.8 > 0.25 threshold
        self.assertTrue(result.high_uncertainty)
        self.assertGreater(result.metadata['score_spread'], 0.25)

    def test_low_uncertainty_detection(self):
        """Test detection of low uncertainty (small spread)"""
        assessments = [
            self.create_assessment('scorer_1', 0.48, 0.8),
            self.create_assessment('scorer_2', 0.50, 0.8),
            self.create_assessment('scorer_3', 0.52, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Spread = 0.52 - 0.48 = 0.04 < 0.25 threshold
        self.assertFalse(result.high_uncertainty)

    def test_insufficient_scorers(self):
        """Test handling of insufficient scorers"""
        assessments = [
            self.create_assessment('scorer_1', 0.5, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Should fail (requires min_scorers=2)
        self.assertIsNone(result)

    def test_byzantine_fault_tolerance(self):
        """Test BFT with 1 faulty scorer (n=3, f=1)"""
        assessments = [
            self.create_assessment('honest_1', 0.3, 0.9),
            self.create_assessment('honest_2', 0.35, 0.9),
            self.create_assessment('faulty', 0.99, 0.9),  # Byzantine fault
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Should detect and exclude faulty scorer
        self.assertIn('faulty', result.outliers)
        # Consensus should be median of honest scorers
        self.assertLess(result.consensus_score, 0.5)

    def test_two_byzantine_faults_fail(self):
        """Test that 2 faulty scorers (>n/3) causes high uncertainty"""
        assessments = [
            self.create_assessment('honest', 0.3, 0.9),
            self.create_assessment('faulty_1', 0.95, 0.9),
            self.create_assessment('faulty_2', 0.98, 0.9),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Cannot achieve consensus with >n/3 faults
        # But should still return result (median)
        self.assertIsNotNone(result)
        # Should flag high uncertainty
        self.assertTrue(result.high_uncertainty or len(result.outliers) > 0)

    def test_confidence_aggregation(self):
        """Test confidence aggregation across scorers"""
        assessments = [
            self.create_assessment('scorer_1', 0.5, 0.7),
            self.create_assessment('scorer_2', 0.5, 0.8),
            self.create_assessment('scorer_3', 0.5, 0.9),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Confidence should be average
        expected_confidence = (0.7 + 0.8 + 0.9) / 3
        self.assertAlmostEqual(result.confidence, expected_confidence, places=2)

    def test_metadata_completeness(self):
        """Test that all metadata fields are populated"""
        assessments = [
            self.create_assessment('scorer_1', 0.4, 0.8),
            self.create_assessment('scorer_2', 0.5, 0.8),
            self.create_assessment('scorer_3', 0.6, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # Check all expected metadata
        self.assertIn('num_scorers', result.metadata)
        self.assertIn('num_outliers', result.metadata)
        self.assertIn('score_spread', result.metadata)
        self.assertIn('median_score', result.metadata)
        self.assertIn('min_score', result.metadata)
        self.assertIn('max_score', result.metadata)

        self.assertEqual(result.metadata['num_scorers'], 3)
        self.assertEqual(result.metadata['min_score'], 0.4)
        self.assertEqual(result.metadata['max_score'], 0.6)

    def test_vote_preservation(self):
        """Test that all votes are preserved in result"""
        assessments = [
            self.create_assessment('scorer_1', 0.3, 0.8),
            self.create_assessment('scorer_2', 0.5, 0.8),
            self.create_assessment('scorer_3', 0.7, 0.8),
        ]

        result = self.consensus.achieve_consensus(assessments)

        # All votes should be in result
        self.assertEqual(len(result.votes), 3)
        scorer_ids = [v['scorer_id'] for v in result.votes]
        self.assertIn('scorer_1', scorer_ids)
        self.assertIn('scorer_2', scorer_ids)
        self.assertIn('scorer_3', scorer_ids)


if __name__ == '__main__':
    unittest.main(verbosity=2)
