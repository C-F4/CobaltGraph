#!/usr/bin/env python3
"""
CobaltGraph System Orchestrator
Full-fledged system coordinator that manages all components

This is the REAL system (not minimal) that:
1. Starts capture pipeline (network_monitor or tools/grey_man)
2. Feeds data to connection processing
3. Enriches with geo/threat intelligence
4. Stores in database
5. Serves via dashboard API
6. Optional: Terminal UI

Architecture:
    Capture → Orchestrator → Database
                ↓
            Dashboard ← API
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
from src.intelligence.ip_reputation import IPReputationManager
from src.intelligence.geo_enrichment import GeoEnrichment
from src.dashboard.server import DashboardHandler
from src.utils.heartbeat import Heartbeat
from src.utils.errors import DatabaseError, ConfigurationError
from src.utils.platform import get_platform_info, is_wsl, is_root
from src.core.config import load_config

logger = logging.getLogger(__name__)


class CobaltGraphOrchestrator:
    """
    Full system orchestrator

    Manages the entire CobaltGraph system with proper component isolation
    and data flow orchestration
    """

    def __init__(self, mode='device', config=None):
        """
        Initialize orchestrator

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
        self.ip_reputation = None
        self.heartbeat = None
        self.dashboard_server = None
        self.dashboard_integration = None  # New Flask-SocketIO dashboard
        self.capture_process = None

        # Data pipeline
        self.connection_queue = Queue(maxsize=1000)
        self.connection_buffer = []  # Recent connections for dashboard
        self.buffer_lock = threading.Lock()

        logger.info(f"🎯 Initializing CobaltGraph Orchestrator (mode: {mode})")

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

        # 1. Database (mode-specific to avoid sudo/user permission conflicts)
        logger.info("📁 Initializing database...")
        try:
            # Use separate database for each mode
            db_path = self.config.get('database_path', f'data/{self.mode}.db')
            self.db = Database(db_path)
            logger.info(f"✅ Database ready: {db_path} (mode: {self.mode})")
        except DatabaseError as e:
            logger.error(f"❌ Database init failed: {e}")
            raise

        # 2. Heartbeat system
        logger.info("💓 Initializing heartbeat...")
        self.heartbeat = Heartbeat()
        logger.info("✅ Heartbeat ready")

        # 3. IP Reputation
        logger.info("🔍 Initializing threat intelligence...")
        try:
            self.ip_reputation = IPReputationManager(self.config)
            logger.info("✅ Threat intelligence ready")
        except Exception as e:
            logger.warning(f"⚠️  Threat intelligence unavailable: {e}")
            self.ip_reputation = None

        # 4. Geo enrichment
        logger.info("🌍 Initializing geo enrichment...")
        try:
            self.geo = GeoEnrichment(max_workers=4)
            logger.info("✅ Geo enrichment ready")
        except Exception as e:
            logger.error(f"❌ Geo enrichment failed: {e}")
            raise

    def start_capture(self):
        """Start capture pipeline based on mode"""
        logger.info(f"📡 Starting capture pipeline ({self.mode} mode)...")

        # Check platform capabilities
        if self.platform_info['os'] not in ['linux']:
            logger.warning(f"⚠️  Network capture on {self.platform_info['os']} not yet supported")
            logger.warning(f"⚠️  Current tools require Linux (AF_PACKET sockets)")
            logger.warning(f"⚠️  Continuing anyway, but capture may fail...")

        if self.mode == 'network':
            # Network mode requires root privileges
            if not self.platform_info['is_root']:
                logger.error("❌ Network mode requires root privileges!")
                logger.error("❌ Please run with: sudo python3 start.py --mode network")
                raise PermissionError("Network mode requires root (sudo)")

            # Check if raw sockets are available
            if not self.platform_info['has_raw_sockets']:
                logger.error("❌ Raw socket creation not available!")
                logger.error("❌ Network mode requires CAP_NET_RAW capability")
                raise PermissionError("Cannot create raw sockets")

            # Try grey_man.py for full network capture (requires root)
            capture_script = Path(__file__).parent.parent.parent / 'tools' / 'grey_man.py'
            if not capture_script.exists():
                # Fallback to network_monitor
                capture_script = Path(__file__).parent.parent / 'capture' / 'network_monitor.py'
                cmd = [sys.executable, str(capture_script), '--mode', 'network']
                logger.info(f"📡 Using network_monitor.py (fallback)")
            else:
                cmd = [sys.executable, str(capture_script)]
                logger.info(f"📡 Using grey_man.py (raw packet capture)")

        elif self.mode == 'device':
            # Use network_capture.py for device-only mode
            capture_script = Path(__file__).parent.parent.parent / 'tools' / 'network_capture.py'
            if not capture_script.exists():
                # Fallback to network_monitor
                capture_script = Path(__file__).parent.parent / 'capture' / 'network_monitor.py'
                cmd = [sys.executable, str(capture_script), '--mode', 'device']
                logger.info(f"📡 Using network_monitor.py (device mode)")
            else:
                cmd = [sys.executable, str(capture_script)]
                logger.info(f"📡 Using network_capture.py (ss-based)")
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

        logger.info(f"📡 Starting: {' '.join(cmd)}")

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            logger.info(f"✅ Capture started (PID: {self.capture_process.pid})")

            # Start thread to read capture output
            capture_thread = threading.Thread(
                target=self._capture_reader_thread,
                daemon=True
            )
            capture_thread.start()

            # Start thread to read capture stderr
            stderr_thread = threading.Thread(
                target=self._capture_stderr_thread,
                daemon=True
            )
            stderr_thread.start()

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
                    logger.warning("📥 Capture stdout closed (no more data)")
                    break

                line_count += 1
                logger.debug(f"📥 Raw line #{line_count}: {line[:100]}")

                # Parse JSON
                try:
                    data = json.loads(line.strip())
                    logger.debug(f"📥 Parsed JSON: {data}")

                    if data.get('type') == 'connection':
                        # Queue for processing
                        self.connection_queue.put(data, block=False)
                        connection_count += 1
                        self.heartbeat.beat('capture')
                        logger.info(f"📥 Queued connection #{connection_count}: {data.get('src_ip')} → {data.get('dst_ip')}:{data.get('dst_port')}")
                    else:
                        logger.debug(f"📥 Non-connection data type: {data.get('type')}")

                except json.JSONDecodeError as e:
                    logger.debug(f"⚠️  Non-JSON line: {line[:100]}")
                    logger.debug(f"⚠️  JSON error: {e}")
                except Full:
                    logger.warning("⚠️  Connection queue full, dropping packet")

            except Exception as e:
                logger.error(f"💥 Capture reader error: {e}", exc_info=True)
                break

        logger.info(f"📥 Capture reader thread stopped (read {line_count} lines, {connection_count} connections)")

    def _capture_stderr_thread(self):
        """Thread to monitor capture stderr"""
        while self.running and self.capture_process:
            try:
                line = self.capture_process.stderr.readline()
                if not line:
                    break
                # Log capture tool messages
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
        """Process connections from queue"""
        logger.info("⚙️  Connection processor thread started")

        while self.running:
            try:
                # Get connection from queue (blocking with timeout)
                conn_data = self.connection_queue.get(timeout=1)

                # Debug logging
                logger.debug(f"📥 Processing connection data: {conn_data}")

                # Extract fields
                src_ip = conn_data.get('src_ip')
                dst_ip = conn_data.get('dst_ip')
                dst_port = conn_data.get('dst_port')

                if not (src_ip and dst_ip and dst_port):
                    logger.warning(f"⚠️  Incomplete connection data: {conn_data}")
                    continue

                logger.info(f"🔄 Processing: {src_ip} → {dst_ip}:{dst_port}")

                # Enrich with geo data
                geo_data = self.geo.lookup_ip(dst_ip) if self.geo else None

                # Handle None response from geo lookup
                if geo_data is None:
                    logger.debug(f"⚠️  Geo lookup failed for {dst_ip}, using defaults")
                    geo_data = {}

                # Calculate threat score
                threat_score = 0.0
                threat_details = {}
                if self.ip_reputation:
                    threat_score, threat_details = self.ip_reputation.check_ip(dst_ip)

                # Build enriched connection using Connection model
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
                    dst_hostname=None,  # Could add reverse DNS here
                    threat_score=threat_score,
                    device_vendor=None,  # Could add MAC vendor lookup
                    protocol=conn_data.get('protocol', 'TCP')
                )

                # Convert to dict for legacy compatibility
                enriched = connection.to_dict()
                enriched['threat_details'] = json.dumps(threat_details)
                enriched['process'] = conn_data.get('process', '')
                enriched['metadata'] = json.dumps(conn_data.get('metadata', {}))

                # Store in database (pass enriched dict directly - it has correct field names)
                self.db.add_connection(enriched)

                # Add to buffer for real-time dashboard
                with self.buffer_lock:
                    self.connection_buffer.append(enriched)
                    # Keep only last 100 connections
                    if len(self.connection_buffer) > 100:
                        self.connection_buffer.pop(0)

                self.heartbeat.beat('processor')
                logger.info(f"✅ Processed connection: {src_ip} → {dst_ip}:{dst_port} (threat: {threat_score:.2f})")

            except Empty:
                continue
            except Exception as e:
                logger.error(f"💥 Connection processing error: {e}", exc_info=True)
                logger.error(f"💥 Failed connection data: {conn_data if 'conn_data' in locals() else 'N/A'}")

        logger.info("⚙️  Connection processor thread stopped")

    def start_dashboard(self, port=8080):
        """Start dashboard (Flask-SocketIO or legacy HTTP)"""
        dashboard_type = self.config.get('dashboard_type', 'flask-socketio')

        logger.info(f"🌐 Starting dashboard ({dashboard_type}) on port {port}...")

        # Try new Flask-SocketIO dashboard first
        if dashboard_type == 'flask-socketio':
            try:
                from src.core.dashboard_integration import create_dashboard_integration

                self.dashboard_integration = create_dashboard_integration(
                    orchestrator=self,
                    port=port,
                    debug=self.config.get('debug', False)
                )

                if self.dashboard_integration and self.dashboard_integration.start():
                    logger.info(f"✅ Flask-SocketIO dashboard started on port {port}")
                    logger.info(f"   Dashboard: http://localhost:{port}")
                    logger.info(f"   Device List: http://localhost:{port}/devices")
                    logger.info(f"   API: http://localhost:{port}/api/devices")
                    return  # Success!
                else:
                    logger.warning("⚠️  Flask-SocketIO dashboard failed, falling back to legacy")
                    dashboard_type = 'legacy'

            except ImportError as e:
                logger.warning(f"⚠️  Flask-SocketIO dashboard not available: {e}")
                logger.warning("⚠️  Falling back to legacy HTTP dashboard")
                dashboard_type = 'legacy'

        # Fallback to legacy HTTP dashboard
        if dashboard_type == 'legacy':
            try:
                self.dashboard_server = HTTPServer(('0.0.0.0', port), DashboardHandler)
                self.dashboard_server.watchfloor = self

                # [SEC-008 PATCH] Setup HTTPS if enabled
                enable_https = self.config.get('enable_https', False)
                if enable_https:
                    try:
                        cert_file = self.config.get('https_cert_file', 'config/server.crt')
                        key_file = self.config.get('https_key_file', 'config/server.key')

                        if not Path(cert_file).exists() or not Path(key_file).exists():
                            logger.warning("[SEC-008] HTTPS certificates not found, using HTTP")
                            enable_https = False
                        else:
                            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            ssl_context.load_cert_chain(cert_file, key_file)
                            self.dashboard_server.socket = ssl_context.wrap_socket(
                                self.dashboard_server.socket,
                                server_side=True
                            )
                            logger.info("[SEC-008] HTTPS enabled")

                    except Exception as e:
                        logger.warning(f"[SEC-008] HTTPS setup failed: {e}")
                        enable_https = False

                # Start server in thread
                dashboard_thread = threading.Thread(
                    target=self.dashboard_server.serve_forever,
                    daemon=True
                )
                dashboard_thread.start()

                protocol = 'https' if enable_https else 'http'
                logger.info(f"✅ Legacy dashboard ready: {protocol}://localhost:{port}")

            except Exception as e:
                logger.error(f"❌ Dashboard start failed: {e}")
                raise

    def get_recent_connections(self, limit=50) -> List[Dict]:
        """Get recent connections for dashboard API"""
        with self.buffer_lock:
            return self.connection_buffer[-limit:]

    def get_metrics(self) -> Dict:
        """Get system metrics"""
        return {
            'total_connections': self.db.get_connection_count() if self.db else 0,
            'buffer_size': len(self.connection_buffer),
            'uptime_seconds': int(time.time() - self.start_time),
            'mode': self.mode,
        }

    def run(self):
        """Main run loop"""
        self.running = True

        logger.info("🚀 Starting CobaltGraph orchestrator...")

        # Start all subsystems
        self.start_capture()
        self.start_processing()

        # Dashboard port (prefer dashboard_port, then api_port, then web_port)
        dashboard_port = self.config.get('dashboard_port',
                                        self.config.get('api_port',
                                        self.config.get('web_port', 5000)))

        self.start_dashboard(port=dashboard_port)

        logger.info("✅ CobaltGraph Orchestrator ACTIVE")
        logger.info("👁️  All systems operational")
        logger.info("Press Ctrl+C to stop")

        # Main loop - just keep alive and monitor health
        try:
            while self.running:
                time.sleep(5)

                # Health check
                if self.capture_process and self.capture_process.poll() is not None:
                    logger.error("❌ Capture process died!")
                    break

                # Heartbeat
                self.heartbeat.beat('orchestrator')

        except KeyboardInterrupt:
            logger.info("⏹️  Shutdown requested")
            self.shutdown()

    def shutdown(self):
        """Graceful shutdown"""
        if not self.running:
            return

        logger.info("🛑 Shutting down orchestrator...")
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

        # Stop dashboard (new or legacy)
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

        logger.info("👋 CobaltGraph Orchestrator shut down")


def main():
    """Entry point for orchestrator"""
    import argparse

    parser = argparse.ArgumentParser(description='CobaltGraph Full System Orchestrator')
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

    # Create and run orchestrator
    orchestrator = CobaltGraphOrchestrator(mode=args.mode)

    # Signal handlers
    def signal_handler(sig, frame):
        print()
        orchestrator.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    orchestrator.run()


if __name__ == '__main__':
    main()
