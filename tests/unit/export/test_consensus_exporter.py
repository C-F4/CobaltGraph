#!/usr/bin/env python3
"""
Unit Tests: Consensus Exporter
Tests hybrid JSON+CSV export system
"""

import sys
import os
import json
import csv
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.export.consensus_exporter import ConsensusExporter


class TestConsensusExporter(unittest.TestCase):
    """Test cases for ConsensusExporter"""

    def setUp(self):
        """Set up test fixtures with temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.exporter = ConsensusExporter(
            export_dir=self.temp_dir,
            csv_max_size_mb=1,  # Small for testing
            buffer_size=2  # Small buffer for testing
        )

    def tearDown(self):
        """Clean up temp files"""
        self.exporter.close()
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test exporter initializes correctly"""
        self.assertTrue(Path(self.temp_dir).exists())
        self.assertEqual(self.exporter.buffer_size, 2)
        self.assertEqual(self.exporter.total_exported, 0)

    def test_json_export(self):
        """Test JSON Lines export"""
        test_consensus = {
            'consensus_score': 0.75,
            'confidence': 0.85,
            'high_uncertainty': False,
            'method': 'median_bft',
            'votes': [],
            'metadata': {}
        }

        self.exporter.export_assessment(
            dst_ip="192.0.2.1",
            consensus_result=test_consensus,
            connection_metadata={'dst_port': 443, 'protocol': 'TCP'}
        )

        # Force flush
        self.exporter.force_flush()

        # Check JSON file created
        json_files = list(Path(self.temp_dir).glob("consensus_detailed_*.jsonl"))
        self.assertEqual(len(json_files), 1)

        # Read and verify content
        with open(json_files[0], 'r') as f:
            line = f.readline()
            data = json.loads(line)

            self.assertEqual(data['dst_ip'], "192.0.2.1")
            self.assertEqual(data['dst_port'], 443)
            self.assertEqual(data['consensus']['consensus_score'], 0.75)

    def test_csv_export(self):
        """Test CSV export"""
        test_consensus = {
            'consensus_score': 0.65,
            'confidence': 0.80,
            'high_uncertainty': True,
            'method': 'median_bft',
            'votes': [],
            'metadata': {'num_scorers': 3, 'num_outliers': 1},
            'is_malicious': True
        }

        self.exporter.export_assessment(
            dst_ip="198.51.100.1",
            consensus_result=test_consensus,
            connection_metadata={'dst_port': 8080}
        )

        self.exporter.force_flush()

        # Check CSV file created
        csv_file = Path(self.temp_dir) / "consensus_summary.csv"
        self.assertTrue(csv_file.exists())

        # Read and verify content
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['dst_ip'], "198.51.100.1")
            self.assertEqual(rows[0]['dst_port'], "8080")
            self.assertEqual(rows[0]['consensus_score'], "0.650")
            self.assertEqual(rows[0]['high_uncertainty'], "True")

    def test_buffering(self):
        """Test buffering before flush"""
        # Export 2 assessments (buffer_size=2)
        for i in range(2):
            self.exporter.export_assessment(
                dst_ip=f"192.0.2.{i}",
                consensus_result={'consensus_score': 0.5},
                connection_metadata={}
            )

        # Should be in buffer, not flushed yet
        self.assertEqual(len(self.exporter.assessment_buffer), 2)
        self.assertEqual(self.exporter.total_exported, 0)

        # Third export should trigger flush
        self.exporter.export_assessment(
            dst_ip="192.0.2.3",
            consensus_result={'consensus_score': 0.5},
            connection_metadata={}
        )

        # Buffer should be partially cleared
        self.assertLess(len(self.exporter.assessment_buffer), 2)
        self.assertGreater(self.exporter.total_exported, 0)

    def test_force_flush(self):
        """Test manual flush"""
        self.exporter.export_assessment(
            dst_ip="192.0.2.1",
            consensus_result={'consensus_score': 0.5},
            connection_metadata={}
        )

        self.assertEqual(self.exporter.total_exported, 0)

        # Force flush
        self.exporter.force_flush()

        self.assertEqual(self.exporter.total_exported, 1)
        self.assertEqual(len(self.exporter.assessment_buffer), 0)

    def test_statistics(self):
        """Test statistics reporting"""
        # Export several assessments
        for i in range(5):
            self.exporter.export_assessment(
                dst_ip=f"192.0.2.{i}",
                consensus_result={'consensus_score': 0.5},
                connection_metadata={}
            )

        self.exporter.force_flush()

        stats = self.exporter.get_statistics()

        self.assertEqual(stats['total_exported'], 5)
        self.assertEqual(stats['json_exports'], 5)
        self.assertEqual(stats['csv_exports'], 5)
        self.assertEqual(stats['export_dir'], self.temp_dir)

    def test_concurrent_exports(self):
        """Test thread-safe concurrent exports"""
        import threading

        def export_batch(start_id):
            for i in range(10):
                self.exporter.export_assessment(
                    dst_ip=f"192.0.2.{start_id + i}",
                    consensus_result={'consensus_score': 0.5},
                    connection_metadata={}
                )

        # Create multiple threads
        threads = [
            threading.Thread(target=export_batch, args=(i * 10,))
            for i in range(3)
        ]

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        self.exporter.force_flush()

        # Should have 30 total exports
        self.assertEqual(self.exporter.total_exported, 30)


if __name__ == '__main__':
    unittest.main(verbosity=2)
