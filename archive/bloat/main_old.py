#!/usr/bin/env python3
"""
CobaltGraph Main - Full Observatory Architecture
Multi-Agent Consensus Threat Intelligence Platform

This is the next-generation CobaltGraph orchestrator with:
1. Consensus-based threat scoring (3 scorers + BFT)
2. Real-time observatory monitoring
3. Lightweight hybrid export (JSON + CSV)
4. Ground truth tracking hooks
5. Graceful degradation to legacy scoring

Architecture:
    Capture → Main → Consensus Observatory → Database + Export
                ↓
            Dashboard ← Enhanced API
"""

import os
import sys
import json
import time
import signal
import ssl
import logging
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional
from queue import Queue, Empty, Full
from http.server import HTTPServer

# Import modular components
from src.storage.database import Database
from src.storage.models import Connection
from src.intelligence.geo_enrichment import GeoEnrichment
from src.utils.heartbeat import Heartbeat
from src.utils.errors import DatabaseError, ConfigurationError
from src.utils.platform import get_platform_info, is_wsl, is_root
from src.core.config import load_config

# Import consensus system (with graceful degradation)
try:
    from src.consensus import ConsensusThreatScorer
    from src.export import ConsensusExporter
    CONSENSUS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Consensus module unavailable: {e}")
    CONSENSUS_AVAILABLE = False
    ConsensusThreatScorer = None
    ConsensusExporter = None

# Fallback to legacy scoring if consensus unavailable
try:
    from src.intelligence.ip_reputation import IPReputationManager
    LEGACY_SCORING_AVAILABLE = True
except ImportError:
    LEGACY_SCORING_AVAILABLE = False
    IPReputationManager = None

# Dashboard imports
try:
    from src.dashboard.server import DashboardHandler
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False

logger = logging.getLogger(__name__)


class CobaltGraphMain:
    """
    CobaltGraph Main Observatory

    Full-featured network intelligence platform with:
    - Multi-scorer consensus threat assessment
    - Real-time monitoring and observability
    - Hybrid export system
    - Ground truth tracking
    - Graceful fallback to legacy scoring
    """

    def __init__(self, mode='device', config=None):
        """
        Initialize CobaltGraph Main

        Args:
            mode: 'network' or 'device'
            config: Configuration dict (or None to load)
        """
        self.mode = mode
        self.config = config or self._load_config()
        self.running = False
        self.start_time = time.time()

        # Component references
        self.db = None
        self.geo = None
        self.consensus_scorer = None  # NEW: Consensus system
        self.consensus_exporter = None  # NEW: Export system
        self.ip_reputation = None  # Fallback only
        self.heartbeat = None
        self.dashboard_server = None
        self.dashboard_integration = None
        self.capture_process = None

        # Data pipeline
        self.connection_queue = Queue(maxsize=1000)
        self.connection_buffer = []  # Recent connections for dashboard
        self.buffer_lock = threading.Lock()

        # Observatory metrics (NEW)
        self.observatory_metrics = {
            'consensus_assessments': 0,
            'legacy_fallbacks': 0,
            'high_uncertainty_count': 0,
            'export_count': 0,
            'ground_truth_labels': 0,
        }
        self.metrics_lock = threading.Lock()

        logger.info(f"🎯 Initializing CobaltGraph Main (mode: {mode})")
        logger.info(f"🔬 Observatory Mode: {'ENABLED' if CONSENSUS_AVAILABLE else 'LEGACY FALLBACK'}")

        # Detect platform
        self.platform_info = get_platform_info()
        logger.info(f"🖥️  Platform: {self.platform_info['os']}")
        if self.platform_info['is_wsl']:
            logger.info("🔷 WSL environment detected")
        if self.platform_info['is_root']:
            logger.info("🔐 Running with root privileges")

        # Initialize components
        self._init_components()

    def _load_config(self) -> Dict:
        """Load configuration"""
        try:
            return load_config(verbose=False)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}, using defaults")
            return {}

    def _init_components(self):
        """Initialize all system components"""

        # 1. Database (mode-specific)
        logger.info("📁 Initializing database...")
        try:
            db_path = self.config.get('database_path', f'data/{self.mode}.db')
            self.db = Database(db_path)
            logger.info(f"✅ Database ready: {db_path}")
        except DatabaseError as e:
            logger.error(f"❌ Database init failed: {e}")
            raise

        # 2. Heartbeat system
        logger.info("💓 Initializing heartbeat...")
        self.heartbeat = Heartbeat()
        logger.info("✅ Heartbeat ready")

        # 3. Geo enrichment
        logger.info("🌍 Initializing geo enrichment...")
        try:
            self.geo = GeoEnrichment(max_workers=4)
            logger.info("✅ Geo enrichment ready")
        except Exception as e:
            logger.error(f"❌ Geo enrichment failed: {e}")
            raise

        # 4. Consensus Threat Scoring (NEW - with graceful degradation)
        logger.info("🤝 Initializing consensus threat scoring...")
        if CONSENSUS_AVAILABLE:
            try:
                consensus_config = self.config.get('consensus', {})
                self.consensus_scorer = ConsensusThreatScorer(
                    config=consensus_config,
                    enable_persistence=False  # Using export instead
                )
                logger.info("✅ Consensus threat scoring ENABLED")
                logger.info(f"   Scorers: {[s.scorer_id for s in self.consensus_scorer.scorers]}")

                # Initialize export system
                if ConsensusExporter:
                    export_dir = self.config.get('export_directory', 'exports')
                    self.consensus_exporter = ConsensusExporter(export_dir=export_dir)
                    logger.info(f"✅ Consensus exporter ready: {export_dir}")

            except Exception as e:
                logger.warning(f"⚠️  Consensus scorer failed, falling back to legacy: {e}")
                self.consensus_scorer = None
                self.consensus_exporter = None

        # 5. Legacy IP Reputation (Fallback)
        if not self.consensus_scorer and LEGACY_SCORING_AVAILABLE:
            logger.info("🔍 Initializing legacy threat intelligence (fallback)...")
            try:
                self.ip_reputation = IPReputationManager(self.config)
                logger.info("✅ Legacy threat intelligence ready")
            except Exception as e:
                logger.warning(f"⚠️  Legacy threat intelligence unavailable: {e}")
                self.ip_reputation = None

        # 6. Verify we have SOME scoring method
        if not self.consensus_scorer and not self.ip_reputation:
            logger.error("❌ No threat scoring available (neither consensus nor legacy)")
            logger.error("❌ System will use static fallback scores")

    def start_capture(self):
        """Start capture pipeline (unchanged from orchestrator.py)"""
        logger.info(f"📡 Starting capture pipeline ({self.mode} mode)...")

        # Check platform capabilities
        if self.platform_info['os'] not in ['linux']:
            logger.warning(f"⚠️  Network capture on {self.platform_info['os']} not yet supported")

        if self.mode == 'network':
            if not self.platform_info['is_root']:
                logger.error("❌ Network mode requires root privileges!")
                raise PermissionError("Network mode requires root (sudo)")

            if not self.platform_info['has_raw_sockets']:
                logger.error("❌ Raw socket creation not available!")
                raise PermissionError("Cannot create raw sockets")

            # Use grey_man.py for network mode
            capture_script = Path(__file__).parent.parent.parent / 'tools' / 'grey_man.py'
            if not capture_script.exists():
                capture_script = Path(__file__).parent.parent / 'capture' / 'network_monitor.py'
                cmd = [sys.executable, str(capture_script), '--mode', 'network']
            else:
                cmd = [sys.executable, str(capture_script)]

        elif self.mode == 'device':
            capture_script = Path(__file__).parent.parent.parent / 'tools' / 'network_capture.py'
            if not capture_script.exists():
                capture_script = Path(__file__).parent.parent / 'capture' / 'network_monitor.py'
                cmd = [sys.executable, str(capture_script), '--mode', 'device']
            else:
                cmd = [sys.executable, str(capture_script)]
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

        logger.info(f"📡 Starting: {' '.join(cmd)}")

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            logger.info(f"✅ Capture started (PID: {self.capture_process.pid})")

            # Start threads to read capture output
            threading.Thread(target=self._capture_reader_thread, daemon=True).start()
            threading.Thread(target=self._capture_stderr_thread, daemon=True).start()

        except Exception as e:
            logger.error(f"❌ Failed to start capture: {e}")
            raise

    def _capture_reader_thread(self):
        """Thread to read JSON from capture stdout"""
        logger.info("📥 Capture reader thread started")

        line_count = 0
        connection_count = 0

        while self.running and self.capture_process:
            try:
                line = self.capture_process.stdout.readline()
                if not line:
                    logger.warning("📥 Capture stdout closed")
                    break

                line_count += 1

                # Parse JSON
                try:
                    data = json.loads(line.strip())

                    if data.get('type') == 'connection':
                        self.connection_queue.put(data, block=False)
                        connection_count += 1
                        self.heartbeat.beat('capture')

                except json.JSONDecodeError:
                    pass
                except Full:
                    logger.warning("⚠️  Connection queue full, dropping packet")

            except Exception as e:
                logger.error(f"💥 Capture reader error: {e}", exc_info=True)
                break

        logger.info(f"📥 Capture reader stopped ({connection_count} connections)")

    def _capture_stderr_thread(self):
        """Thread to monitor capture stderr"""
        while self.running and self.capture_process:
            try:
                line = self.capture_process.stderr.readline()
                if not line:
                    break
                logger.info(f"[Capture] {line.strip()}")
            except Exception as e:
                logger.error(f"💥 Capture stderr error: {e}", exc_info=True)
                break

    def start_processing(self):
        """Start connection processing thread"""
        logger.info("⚙️  Starting connection processor...")

        processor_thread = threading.Thread(
            target=self._connection_processor_thread,
            daemon=True
        )
        processor_thread.start()

        logger.info("✅ Connection processor started")

    def _connection_processor_thread(self):
        """
        Process connections from queue

        THIS IS THE CRITICAL METHOD - Enhanced with consensus scoring
        """
        logger.info("⚙️  Connection processor thread started")

        while self.running:
            try:
                # Get connection from queue
                conn_data = self.connection_queue.get(timeout=1)

                # Extract fields
                src_ip = conn_data.get('src_ip')
                dst_ip = conn_data.get('dst_ip')
                dst_port = conn_data.get('dst_port')
                protocol = conn_data.get('protocol', 'TCP')

                if not (src_ip and dst_ip and dst_port):
                    logger.warning(f"⚠️  Incomplete connection data")
                    continue

                logger.info(f"🔄 Processing: {src_ip} → {dst_ip}:{dst_port}")

                # Enrich with geo data
                geo_data = self.geo.lookup_ip(dst_ip) if self.geo else {}
                if geo_data is None:
                    geo_data = {}

                # ═══════════════════════════════════════════════════════════
                # CRITICAL: Consensus-based threat scoring
                # ═══════════════════════════════════════════════════════════

                threat_score = 0.0
                threat_details = {}
                scoring_method = 'none'

                # Try consensus scoring first
                if self.consensus_scorer:
                    try:
                        threat_score, threat_details = self.consensus_scorer.check_ip(
                            dst_ip=dst_ip,
                            threat_intel={},  # Scorers fetch their own data
                            geo_data=geo_data,
                            connection_metadata={
                                'dst_port': dst_port,
                                'protocol': protocol,
                                'src_ip': src_ip,
                            }
                        )
                        scoring_method = 'consensus'

                        # Update observatory metrics
                        with self.metrics_lock:
                            self.observatory_metrics['consensus_assessments'] += 1
                            if threat_details.get('high_uncertainty', False):
                                self.observatory_metrics['high_uncertainty_count'] += 1

                        # Export consensus assessment
                        if self.consensus_exporter:
                            self.consensus_exporter.export_assessment(
                                dst_ip=dst_ip,
                                consensus_result=threat_details,
                                connection_metadata={
                                    'dst_port': dst_port,
                                    'protocol': protocol,
                                    'src_ip': src_ip,
                                }
                            )
                            with self.metrics_lock:
                                self.observatory_metrics['export_count'] += 1

                        logger.debug(
                            f"🤝 Consensus: {dst_ip} score={threat_score:.3f}, "
                            f"confidence={threat_details.get('confidence', 0):.3f}, "
                            f"uncertainty={'HIGH' if threat_details.get('high_uncertainty') else 'LOW'}"
                        )

                    except Exception as e:
                        logger.error(f"❌ Consensus scoring failed for {dst_ip}: {e}")
                        # Fall through to legacy

                # Fallback to legacy IP reputation
                if scoring_method == 'none' and self.ip_reputation:
                    try:
                        threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)
                        scoring_method = 'legacy'

                        with self.metrics_lock:
                            self.observatory_metrics['legacy_fallbacks'] += 1

                        logger.debug(f"🔍 Legacy: {dst_ip} score={threat_score:.3f}")

                    except Exception as e:
                        logger.error(f"❌ Legacy scoring failed for {dst_ip}: {e}")

                # Ultimate fallback: static score
                if scoring_method == 'none':
                    threat_score = 0.2
                    threat_details = {'source': 'static_fallback'}
                    scoring_method = 'fallback'
                    logger.debug(f"⚠️  Static fallback for {dst_ip}")

                # ═══════════════════════════════════════════════════════════

                # Build enriched connection
                connection = Connection(
                    timestamp=time.time(),
                    src_mac=conn_data.get('src_mac', ''),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    dst_country=geo_data.get('country'),
                    dst_lat=geo_data.get('lat'),
                    dst_lon=geo_data.get('lon'),
                    dst_org=geo_data.get('org'),
                    dst_hostname=None,
                    threat_score=threat_score,
                    device_vendor=conn_data.get('device_vendor'),
                    protocol=protocol
                )

                # Store in database
                enriched = connection.to_dict()
                enriched['threat_details'] = json.dumps(threat_details)
                enriched['scoring_method'] = scoring_method  # Track which method was used
                enriched['process'] = conn_data.get('process', '')
                enriched['metadata'] = json.dumps(conn_data.get('metadata', {}))

                self.db.add_connection(enriched)

                # Add to buffer for dashboard
                with self.buffer_lock:
                    self.connection_buffer.append(enriched)
                    if len(self.connection_buffer) > 100:
                        self.connection_buffer.pop(0)

                self.heartbeat.beat('processor')
                logger.info(
                    f"✅ Processed: {src_ip} → {dst_ip}:{dst_port} "
                    f"(score={threat_score:.2f}, method={scoring_method})"
                )

            except Empty:
                continue
            except Exception as e:
                logger.error(f"💥 Connection processing error: {e}", exc_info=True)

        logger.info("⚙️  Connection processor thread stopped")

    def start_dashboard(self, port=8080):
        """Start dashboard (unchanged from orchestrator.py)"""
        dashboard_type = self.config.get('dashboard_type', 'flask-socketio')

        logger.info(f"🌐 Starting dashboard ({dashboard_type}) on port {port}...")

        # Try Flask-SocketIO dashboard
        if dashboard_type == 'flask-socketio':
            try:
                from src.core.dashboard_integration import create_dashboard_integration

                self.dashboard_integration = create_dashboard_integration(
                    orchestrator=self,
                    port=port,
                    debug=self.config.get('debug', False)
                )

                if self.dashboard_integration and self.dashboard_integration.start():
                    logger.info(f"✅ Dashboard started on port {port}")
                    return
                else:
                    dashboard_type = 'legacy'

            except ImportError as e:
                logger.warning(f"⚠️  Flask-SocketIO unavailable: {e}")
                dashboard_type = 'legacy'

        # Fallback to legacy HTTP dashboard
        if dashboard_type == 'legacy' and DASHBOARD_AVAILABLE:
            try:
                self.dashboard_server = HTTPServer(('0.0.0.0', port), DashboardHandler)
                self.dashboard_server.watchfloor = self

                dashboard_thread = threading.Thread(
                    target=self.dashboard_server.serve_forever,
                    daemon=True
                )
                dashboard_thread.start()

                logger.info(f"✅ Legacy dashboard ready: http://localhost:{port}")

            except Exception as e:
                logger.error(f"❌ Dashboard start failed: {e}")

    def get_recent_connections(self, limit=50) -> List[Dict]:
        """Get recent connections for dashboard"""
        with self.buffer_lock:
            return self.connection_buffer[-limit:]

    def get_metrics(self) -> Dict:
        """
        Get system metrics (ENHANCED with observatory metrics)
        """
        base_metrics = {
            'total_connections': self.db.get_connection_count() if self.db else 0,
            'buffer_size': len(self.connection_buffer),
            'uptime_seconds': int(time.time() - self.start_time),
            'mode': self.mode,
        }

        # Add observatory metrics
        with self.metrics_lock:
            base_metrics['observatory'] = dict(self.observatory_metrics)

        # Add consensus scorer stats
        if self.consensus_scorer:
            base_metrics['consensus'] = self.consensus_scorer.get_statistics()

        # Add export stats
        if self.consensus_exporter:
            base_metrics['export'] = self.consensus_exporter.get_statistics()

        return base_metrics

    def run(self):
        """Main run loop"""
        self.running = True

        logger.info("🚀 Starting CobaltGraph Main...")

        # Start all subsystems
        self.start_capture()
        self.start_processing()

        dashboard_port = self.config.get('dashboard_port',
                                        self.config.get('api_port',
                                        self.config.get('web_port', 5000)))

        self.start_dashboard(port=dashboard_port)

        logger.info("✅ CobaltGraph Main ACTIVE")
        logger.info("🔬 Observatory Mode ENABLED" if self.consensus_scorer else "⚠️  Legacy Mode (no consensus)")
        logger.info("👁️  All systems operational")
        logger.info("Press Ctrl+C to stop")

        # Main loop
        try:
            while self.running:
                time.sleep(5)

                # Health check
                if self.capture_process and self.capture_process.poll() is not None:
                    logger.error("❌ Capture process died!")
                    break

                self.heartbeat.beat('main')

        except KeyboardInterrupt:
            logger.info("⏹️  Shutdown requested")
            self.shutdown()

    def shutdown(self):
        """Graceful shutdown"""
        if not self.running:
            return

        logger.info("🛑 Shutting down CobaltGraph Main...")
        self.running = False

        # Stop capture
        if self.capture_process:
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=5)
                logger.info("✅ Capture stopped")
            except:
                self.capture_process.kill()
                logger.warning("⚠️  Capture force-killed")

        # Flush and close export
        if self.consensus_exporter:
            try:
                self.consensus_exporter.close()
                logger.info("✅ Consensus exporter closed")
            except Exception as e:
                logger.warning(f"⚠️  Export close error: {e}")

        # Stop consensus scorer
        if self.consensus_scorer:
            try:
                self.consensus_scorer.shutdown()
                logger.info("✅ Consensus scorer stopped")
            except Exception as e:
                logger.warning(f"⚠️  Consensus shutdown error: {e}")

        # Stop dashboard
        if self.dashboard_integration:
            try:
                self.dashboard_integration.stop()
                logger.info("✅ Dashboard stopped")
            except:
                pass

        if self.dashboard_server:
            try:
                self.dashboard_server.shutdown()
                logger.info("✅ Legacy dashboard stopped")
            except:
                pass

        # Print final statistics
        logger.info("=" * 70)
        logger.info("🔬 OBSERVATORY FINAL STATISTICS")
        logger.info("=" * 70)
        metrics = self.get_metrics()
        logger.info(f"Total Connections: {metrics['total_connections']}")
        logger.info(f"Consensus Assessments: {metrics['observatory']['consensus_assessments']}")
        logger.info(f"Legacy Fallbacks: {metrics['observatory']['legacy_fallbacks']}")
        logger.info(f"High Uncertainty: {metrics['observatory']['high_uncertainty_count']}")
        logger.info(f"Exports: {metrics['observatory']['export_count']}")
        logger.info(f"Uptime: {metrics['uptime_seconds']}s")
        logger.info("=" * 70)

        logger.info("👋 CobaltGraph Main shut down")


def main():
    """Entry point for main.py"""
    import argparse

    parser = argparse.ArgumentParser(description='CobaltGraph Main - Full Observatory')
    parser.add_argument('--mode', choices=['network', 'device'], default='device',
                        help='Capture mode')
    parser.add_argument('--port', type=int, default=8080,
                        help='Dashboard port')

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s :: %(message)s',
        datefmt='%H:%M:%S'
    )

    # Create and run main
    main_instance = CobaltGraphMain(mode=args.mode)

    # Signal handlers
    def signal_handler(sig, frame):
        print()
        main_instance.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main_instance.run()


if __name__ == '__main__':
    main()
