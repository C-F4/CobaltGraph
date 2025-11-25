#!/usr/bin/env python3
"""
CobaltGraph Main - PURE TERMINAL VERSION
Revolutionary Blue-Team Network Intelligence

NO WEB SERVER. NO HTTP. NO PORTS.
Pure CLI/TUI for maximum security and minimal attack surface.

This gives defenders a real cyber chance against foreign actors.
"""

import logging
import signal
import sys
import threading
import time
from typing import Dict, Optional

# Core CobaltGraph imports
from src.capture.device_monitor import DeviceMonitor
from src.core.config import Config
from src.services.geo_lookup import GeoLookup
from src.services.ip_reputation import IPReputation
from src.storage.database import Database

# Observatory Mode: Multi-agent consensus
try:
    from src.consensus import ConsensusThreatScorer
    from src.export import ConsensusExporter

    CONSENSUS_AVAILABLE = True
except ImportError:
    CONSENSUS_AVAILABLE = False

logger = logging.getLogger(__name__)


class CobaltGraphPure:
    """
    PURE TERMINAL Blue-Team Network Monitor

    Revolutionary design principles:
    1. NO web server - no attack surface
    2. NO HTTP ports - no remote exploitation
    3. Terminal-only - runs anywhere, even air-gapped
    4. Minimal dependencies - only what's needed for network analysis
    5. Maximum security - cryptographic consensus, zero trust

    This is the defender's advantage.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize pure terminal CobaltGraph"""
        self.config = Config(config_path)
        self.running = False
        self.shutdown_event = threading.Event()

        # Core components (NO web server!)
        self.database = None
        self.device_monitor = None
        self.ip_reputation = None
        self.geo_lookup = None

        # Observatory Mode: Multi-agent consensus
        self.consensus_scorer = None
        self.consensus_exporter = None
        self.consensus_enabled = False

        # Statistics
        self.stats = {
            "total_connections": 0,
            "consensus_assessments": 0,
            "high_uncertainty_count": 0,
            "consensus_failures": 0,
            "legacy_fallbacks": 0,
            "start_time": time.time(),
        }
        self.stats_lock = threading.Lock()

        # Terminal UI state
        self.recent_assessments = []
        self.max_recent = 50

        logger.info("=" * 80)
        logger.info("COBALTGRAPH PURE TERMINAL - Blue-Team Defense System")
        logger.info("=" * 80)
        logger.info("NO web server | NO HTTP ports | Terminal-only")
        logger.info("Cryptographic consensus | Byzantine fault tolerant")
        logger.info("Giving defenders a cyber chance against foreign actors")
        logger.info("=" * 80)

    def initialize_components(self):
        """Initialize core monitoring components"""
        logger.info("🔧 Initializing components...")

        # Database
        db_path = self.config.get("database_path", "data/cobaltgraph.db")
        self.database = Database(db_path)
        logger.info("✅ Database: %s", db_path)

        # Threat intelligence
        self.ip_reputation = IPReputation(self.config)
        self.geo_lookup = GeoLookup(self.config)
        logger.info("✅ Threat intelligence: VirusTotal + AbuseIPDB + Geo")

        # Observatory Mode: Multi-agent consensus
        if CONSENSUS_AVAILABLE and self.config.get("consensus_enabled", True):
            try:
                self.consensus_scorer = ConsensusThreatScorer(self.config)
                self.consensus_exporter = ConsensusExporter(
                    export_dir=self.config.get("export_directory", "exports"),
                    buffer_size=self.config.get("export_buffer_size", 100),
                    csv_max_size_mb=self.config.get("csv_max_size_mb", 10),
                )
                self.consensus_enabled = True
                logger.info("🔬 Observatory Mode ENABLED - Multi-agent consensus active")
                logger.info("   ├─ Statistical Scorer: Confidence intervals")
                logger.info("   ├─ Rule-Based Scorer: Expert heuristics")
                logger.info("   ├─ ML-Based Scorer: Trained weights")
                logger.info("   └─ BFT Consensus: Byzantine fault tolerant voting")
            except Exception as e:
                logger.warning("⚠️  Consensus system unavailable: %s", e)
                logger.info("   Falling back to legacy scoring")
                self.consensus_enabled = False
        else:
            logger.info("📊 Legacy Mode - Single scorer (backward compatible)")

    def process_connection(self, connection: Dict) -> Optional[Dict]:
        """
        Process single network connection with consensus scoring

        This is the revolutionary core: multi-agent threat analysis
        with cryptographic verification, all in a terminal.
        """
        dst_ip = connection.get("dst_ip")
        dst_port = connection.get("dst_port")
        protocol = connection.get("protocol", "TCP")

        if not dst_ip:
            return None

        # Gather threat intelligence
        threat_intel = self.ip_reputation.check_ip(dst_ip) if self.ip_reputation else {}
        geo_data = self.geo_lookup.lookup(dst_ip) if self.geo_lookup else {}

        # Connection metadata for consensus scorers
        connection_metadata = {
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": connection.get("timestamp", time.time()),
        }

        # Multi-agent consensus scoring (Observatory Mode)
        threat_score = 0.2  # Default fallback
        scoring_method = "static_fallback"
        consensus_details = None

        if self.consensus_enabled and self.consensus_scorer:
            try:
                # Revolutionary: 3 independent scorers vote via Byzantine consensus
                threat_score, consensus_details = self.consensus_scorer.check_ip(
                    dst_ip=dst_ip,
                    threat_intel=threat_intel,
                    geo_data=geo_data,
                    connection_metadata=connection_metadata,
                )
                scoring_method = "consensus"

                # Track statistics
                with self.stats_lock:
                    self.stats["consensus_assessments"] += 1
                    if consensus_details.get("high_uncertainty"):
                        self.stats["high_uncertainty_count"] += 1

                # Export consensus assessment for research/analysis
                if self.consensus_exporter:
                    self.consensus_exporter.export_assessment(
                        dst_ip=dst_ip,
                        consensus_result=consensus_details,
                        connection_metadata=connection_metadata,
                    )

                # Terminal logging (no web UI needed!)
                uncertainty_flag = "⚠️ HIGH" if consensus_details.get("high_uncertainty") else "LOW"
                logger.info(
                    f"🤝 Consensus: {dst_ip}:{dst_port} "
                    f"score={threat_score:.3f}, "
                    f"confidence={consensus_details.get('confidence', 0):.3f}, "
                    f"uncertainty={uncertainty_flag}"
                )

            except Exception as e:
                logger.error("❌ Consensus failed for {dst_ip}: %s", e)
                # Fallback to legacy
                threat_score = threat_intel.get("threat_score", 0.2)
                scoring_method = "legacy_fallback"
                with self.stats_lock:
                    self.stats["consensus_failures"] += 1
                    self.stats["legacy_fallbacks"] += 1
        else:
            # Legacy single-scorer mode
            threat_score = threat_intel.get("threat_score", 0.2)
            scoring_method = "legacy"

        # Store in database
        if self.database:
            self.database.log_connection(
                timestamp=connection_metadata["timestamp"],
                src_ip=connection.get("src_ip"),
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                threat_score=threat_score,
                geo_country=geo_data.get("country"),
                geo_city=geo_data.get("city"),
                abuse_confidence=threat_intel.get("abuse_confidence_score", 0),
                vt_detections=threat_intel.get("vt_positives", 0),
            )

        # Add to recent assessments for terminal display
        assessment = {
            "timestamp": time.strftime("%H:%M:%S"),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "score": threat_score,
            "confidence": consensus_details.get("confidence", 0.5) if consensus_details else 0.5,
            "uncertainty": (
                "HIGH"
                if (consensus_details and consensus_details.get("high_uncertainty"))
                else "LOW"
            ),
            "method": scoring_method,
            "country": geo_data.get("country", "Unknown"),
        }

        self.recent_assessments.append(assessment)
        if len(self.recent_assessments) > self.max_recent:
            self.recent_assessments.pop(0)

        with self.stats_lock:
            self.stats["total_connections"] += 1

        # Terminal output (clean, concise, actionable)
        logger.info(
            f"✅ Processed: {connection.get('src_ip', 'local')} → {dst_ip}:{dst_port} "
            f"(score={threat_score:.2f}, method={scoring_method})"
        )

        return assessment

    def start_capture(self, mode: str = "device"):
        """Start network capture (device mode only - no root needed!)"""
        if mode == "device":
            logger.info("📡 Starting device-level network capture (NO ROOT REQUIRED)")
            self.device_monitor = DeviceMonitor(self.config)

            # Callback for each connection
            def connection_callback(connection):
                if self.running:
                    self.process_connection(connection)

            self.device_monitor.set_callback(connection_callback)
            self.device_monitor.start()
            logger.info("✅ Device monitor active - capturing established connections")
        else:
            logger.error("❌ Only 'device' mode supported in pure terminal version")
            sys.exit(1)

    def print_status(self):
        """Print status to terminal (called periodically)"""
        with self.stats_lock:
            uptime = time.time() - self.stats["start_time"]
            uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime))

            # Calculate rates
            cps = self.stats["total_connections"] / uptime if uptime > 0 else 0
            uncertainty_rate = (
                self.stats["high_uncertainty_count"] / self.stats["consensus_assessments"] * 100
                if self.stats["consensus_assessments"] > 0
                else 0
            )

            print("\n" + "=" * 80)
            print(f"🔬 COBALTGRAPH OBSERVATORY - {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)
            print(
                f"Uptime: {uptime_str} | Connections: {self.stats['total_connections']} | Rate: {cps:.2f}/sec"
            )

            if self.consensus_enabled:
                print(
                    f"Consensus: {self.stats['consensus_assessments']} | "
                    f"High Uncertainty: {self.stats['high_uncertainty_count']} ({uncertainty_rate:.1f}%) | "
                    f"Failures: {self.stats['consensus_failures']}"
                )

            # Recent assessments table
            if self.recent_assessments:
                print("\nRECENT ASSESSMENTS (Last 10):")
                print(
                    f"{'Time':<10} {'Destination':<18} {'Port':<6} {'Score':<7} {'Confidence':<11} {'Uncertainty':<12} {'Country':<10}"
                )
                print("-" * 80)
                for a in self.recent_assessments[-10:]:
                    uncertainty_mark = "⚠️ " if a["uncertainty"] == "HIGH" else "  "
                    print(
                        f"{a['timestamp']:<10} {a['dst_ip']:<18} {a['dst_port']:<6} "
                        f"{a['score']:<7.3f} {a['confidence']:<11.3f} "
                        f"{uncertainty_mark}{a['uncertainty']:<10} {a['country']:<10}"
                    )

            print("=" * 80)
            print("Press Ctrl+C to stop")
            print("=" * 80 + "\n")

    def status_printer_thread(self):
        """Background thread to print status every 30 seconds"""
        while self.running and not self.shutdown_event.is_set():
            self.shutdown_event.wait(30)  # Wait 30 seconds or until shutdown
            if self.running:
                self.print_status()

    def run(self, mode: str = "device"):
        """
        Main run loop - PURE TERMINAL

        No web server. No HTTP. Just terminal output and file exports.
        Revolutionary simplicity for revolutionary defense.
        """
        self.running = True

        # Setup signal handlers
        def signal_handler(sig, frame):
            logger.info("\n🛑 Shutdown signal received...")
            self.stop()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Initialize
        self.initialize_components()

        # Start capture
        self.start_capture(mode=mode)

        # Start status printer thread
        status_thread = threading.Thread(target=self.status_printer_thread, daemon=True)
        status_thread.start()

        # Initial status
        self.print_status()

        logger.info("✅ CobaltGraph Pure Terminal is running")
        logger.info("   Data exports: exports/consensus_*.jsonl and *.csv")
        logger.info("   Database: data/cobaltgraph.db")
        logger.info("   Terminal output only - NO web interface")
        logger.info("   Press Ctrl+C to stop gracefully")

        # Main loop - just keep alive
        try:
            while self.running:
                self.shutdown_event.wait(1)
        except KeyboardInterrupt:
            logger.info("\n🛑 Keyboard interrupt...")
            self.stop()

    def stop(self):
        """Graceful shutdown"""
        if not self.running:
            return

        self.running = False
        self.shutdown_event.set()

        logger.info("🛑 Stopping CobaltGraph...")

        # Stop capture
        if self.device_monitor:
            try:
                self.device_monitor.stop()
                logger.info("✅ Device monitor stopped")
            except Exception as e:
                logger.error("Error stopping device monitor: %s", e)

        # Flush exports
        if self.consensus_exporter:
            try:
                self.consensus_exporter.force_flush()
                stats = self.consensus_exporter.get_statistics()
                logger.info(f"✅ Exports flushed: {stats['total_exported']} assessments")
            except Exception as e:
                logger.error("Error flushing exports: %s", e)

        # Close database
        if self.database:
            try:
                self.database.close()
                logger.info("✅ Database closed")
            except Exception as e:
                logger.error("Error closing database: %s", e)

        # Final statistics
        with self.stats_lock:
            logger.info("\n" + "=" * 80)
            logger.info("FINAL STATISTICS")
            logger.info("=" * 80)
            logger.info(f"Total Connections: {self.stats['total_connections']}")
            if self.consensus_enabled:
                logger.info(f"Consensus Assessments: {self.stats['consensus_assessments']}")
                logger.info(f"High Uncertainty: {self.stats['high_uncertainty_count']}")
                logger.info(f"Consensus Failures: {self.stats['consensus_failures']}")
                logger.info(f"Legacy Fallbacks: {self.stats['legacy_fallbacks']}")
            logger.info("=" * 80)

        logger.info("✅ CobaltGraph stopped gracefully")


def main():
    """Entry point for pure terminal CobaltGraph"""
    import argparse

    parser = argparse.ArgumentParser(
        description="CobaltGraph Pure Terminal - Revolutionary Blue-Team Defense"
    )
    parser.add_argument("--config", help="Path to config file", default=None)
    parser.add_argument(
        "--mode", help="Capture mode (device only)", choices=["device"], default="device"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/cobaltgraph.log", mode="a"),
        ],
    )

    # Run
    cobaltgraph = CobaltGraphPure(config_path=args.config)
    cobaltgraph.run(mode=args.mode)


if __name__ == "__main__":
    main()
