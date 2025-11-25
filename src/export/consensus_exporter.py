"""
Consensus Assessment Exporter
Lightweight hybrid export system (JSON + CSV)

Design:
- Streaming JSON Lines for detailed data
- Rolling CSV for quick analysis
- Automatic file rotation
- Async-safe buffering
"""

import csv
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class ConsensusExporter:
    """
    Hybrid exporter for consensus threat assessments

    Exports to:
    1. JSON Lines: exports/consensus_detailed_YYYYMMDD.jsonl
    2. CSV Summary: exports/consensus_summary.csv

    Features:
    - Automatic daily rotation (JSON)
    - File size limits (CSV: 10MB)
    - Thread-safe buffering
    - Minimal memory overhead
    """

    def __init__(
        self, export_dir: str = "exports", csv_max_size_mb: int = 10, buffer_size: int = 100
    ):
        """
        Initialize exporter

        Args:
            export_dir: Directory for export files
            csv_max_size_mb: Max CSV size before rotation
            buffer_size: Number of assessments to buffer before flush
        """
        self.export_dir = Path(export_dir)
        self.csv_max_size = csv_max_size_mb * 1024 * 1024
        self.buffer_size = buffer_size

        # Create export directory
        self.export_dir.mkdir(parents=True, exist_ok=True)

        # File handles
        self.json_file = None
        self.csv_file = None
        self.csv_writer = None
        self.current_date = None

        # Buffering
        self.assessment_buffer = []
        self.buffer_lock = Lock()

        # Statistics
        self.total_exported = 0
        self.json_exports = 0
        self.csv_exports = 0

        logger.info("📤 ConsensusExporter initialized: %s", self.export_dir)

    def _get_json_filename(self) -> Path:
        """Get current JSON filename with date"""
        date_str = datetime.now().strftime("%Y%m%d")
        return self.export_dir / f"consensus_detailed_{date_str}.jsonl"

    def _get_csv_filename(self) -> Path:
        """Get current CSV filename"""
        return self.export_dir / "consensus_summary.csv"

    def _rotate_csv_if_needed(self):
        """Rotate CSV if it exceeds size limit"""
        csv_path = self._get_csv_filename()

        if not csv_path.exists():
            return

        file_size = csv_path.stat().st_size

        if file_size >= self.csv_max_size:
            # Rotate: consensus_summary.csv → consensus_summary_YYYYMMDD_HHMMSS.csv
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = self.export_dir / f"consensus_summary_{timestamp}.csv"

            csv_path.rename(rotated_name)
            logger.info("📁 Rotated CSV: %s", rotated_name.name)

            # Close and reopen
            if self.csv_file:
                self.csv_file.close()
            self.csv_file = None
            self.csv_writer = None

    def _open_files(self):
        """Open/reopen export files"""
        today = datetime.now().strftime("%Y%m%d")

        # Check if date changed (daily rotation for JSON)
        if self.current_date != today:
            if self.json_file:
                self.json_file.close()
            self.current_date = today

        # Open JSON file (append mode)
        if self.json_file is None or self.json_file.closed:
            json_path = self._get_json_filename()
            self.json_file = open(json_path, "a", encoding="utf-8")
            logger.debug("📝 Opened JSON: %s", json_path.name)

        # Check CSV rotation
        self._rotate_csv_if_needed()

        # Open CSV file
        if self.csv_file is None or self.csv_file.closed:
            csv_path = self._get_csv_filename()
            is_new_file = not csv_path.exists()

            self.csv_file = open(csv_path, "a", newline="", encoding="utf-8")
            self.csv_writer = csv.DictWriter(
                self.csv_file,
                fieldnames=[
                    "timestamp",
                    "iso_time",
                    "dst_ip",
                    "dst_port",
                    "consensus_score",
                    "confidence",
                    "high_uncertainty",
                    "num_scorers",
                    "num_outliers",
                    "method",
                    "is_malicious",
                ],
            )

            # Write header if new file
            if is_new_file:
                self.csv_writer.writeheader()
                logger.debug("📊 Created CSV: %s", csv_path.name)

    def export_assessment(
        self, dst_ip: str, consensus_result: Dict, connection_metadata: Optional[Dict] = None
    ):
        """
        Export a single consensus assessment

        Args:
            dst_ip: Destination IP address
            consensus_result: Full consensus result dict
            connection_metadata: Additional connection context
        """
        with self.buffer_lock:
            self.assessment_buffer.append(
                {
                    "dst_ip": dst_ip,
                    "consensus": consensus_result,
                    "metadata": connection_metadata or {},
                    "export_timestamp": time.time(),
                }
            )

            # Flush if buffer full
            if len(self.assessment_buffer) >= self.buffer_size:
                self._flush_buffer()

    def _flush_buffer(self):
        """Flush buffered assessments to disk (must hold buffer_lock)"""
        if not self.assessment_buffer:
            return

        self._open_files()

        for assessment in self.assessment_buffer:
            try:
                # Extract data
                dst_ip = assessment["dst_ip"]
                consensus = assessment["consensus"]
                metadata = assessment["metadata"]
                export_ts = assessment["export_timestamp"]

                # Write detailed JSON line
                json_record = {
                    "timestamp": export_ts,
                    "iso_time": datetime.fromtimestamp(export_ts).isoformat(),
                    "dst_ip": dst_ip,
                    "dst_port": metadata.get("dst_port"),
                    "protocol": metadata.get("protocol"),
                    "consensus": consensus,
                }

                self.json_file.write(json.dumps(json_record) + "\n")
                self.json_exports += 1

                # Write summary CSV row
                csv_record = {
                    "timestamp": export_ts,
                    "iso_time": datetime.fromtimestamp(export_ts).isoformat(),
                    "dst_ip": dst_ip,
                    "dst_port": metadata.get("dst_port", ""),
                    "consensus_score": f"{consensus.get('consensus_score', 0):.3f}",
                    "confidence": f"{consensus.get('confidence', 0):.3f}",
                    "high_uncertainty": consensus.get("high_uncertainty", False),
                    "num_scorers": consensus.get("metadata", {}).get("num_scorers", 0),
                    "num_outliers": consensus.get("metadata", {}).get("num_outliers", 0),
                    "method": consensus.get("method", ""),
                    "is_malicious": consensus.get("is_malicious", False),
                }

                self.csv_writer.writerow(csv_record)
                self.csv_exports += 1

            except Exception as e:
                logger.error("Export error for {dst_ip}: %s", e)

        # Flush to disk
        self.json_file.flush()
        self.csv_file.flush()

        self.total_exported += len(self.assessment_buffer)
        logger.debug(
            f"📤 Exported {len(self.assessment_buffer)} assessments "
            f"(total: {self.total_exported})"
        )

        # Clear buffer
        self.assessment_buffer.clear()

    def force_flush(self):
        """Force flush buffered data to disk"""
        with self.buffer_lock:
            self._flush_buffer()

    def get_statistics(self) -> Dict:
        """Get export statistics"""
        return {
            "total_exported": self.total_exported,
            "json_exports": self.json_exports,
            "csv_exports": self.csv_exports,
            "buffer_size": len(self.assessment_buffer),
            "export_dir": str(self.export_dir),
        }

    def close(self):
        """Close export files gracefully"""
        with self.buffer_lock:
            # Flush remaining data
            self._flush_buffer()

            # Close files
            if self.json_file and not self.json_file.closed:
                self.json_file.close()
                logger.info("📁 Closed JSON export file")

            if self.csv_file and not self.csv_file.closed:
                self.csv_file.close()
                logger.info("📊 Closed CSV export file")

        logger.info("📤 ConsensusExporter shutdown: %s total exports", self.total_exported)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
