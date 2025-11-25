"""
CobaltGraph Dashboard Integration Module
Handles integration of Flask-SocketIO dashboard with the orchestrator

This module provides a clean interface between the orchestrator and
the new real-time dashboard (Task 0.6)
"""

import logging
import threading
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class DashboardIntegration:
    """
    Manages Flask-SocketIO dashboard integration with CobaltGraph orchestrator

    Features:
    - Start/stop Flask-SocketIO dashboard in separate thread
    - Connect Device Discovery Service with WebSocket events
    - Provide real-time updates to dashboard clients
    - Handle graceful shutdown
    """

    def __init__(self, orchestrator, port=5000, debug=False):
        """
        Initialize dashboard integration

        Args:
            orchestrator: CobaltGraphOrchestrator instance
            port: Dashboard port (default: 5000)
            debug: Debug mode
        """
        self.orchestrator = orchestrator
        self.port = port
        self.debug = debug

        self.app = None
        self.socketio = None
        self.dashboard_thread = None
        self.running = False

    def initialize(self) -> bool:
        """
        Initialize Flask-SocketIO dashboard

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"🌐 Initializing Flask-SocketIO dashboard on port {self.port}...")

            # Import dashboard modules
            from src.services.dashboard import create_app, socketio

            # Create Flask app
            self.app = create_app({'debug': self.debug, 'port': self.port})
            self.socketio = socketio

            logger.info("✅ Dashboard initialized successfully")
            return True

        except ImportError as e:
            logger.error(f"❌ Dashboard modules not available: {e}")
            logger.error("   Install: pip3 install flask flask-cors flask-socketio")
            return False

        except Exception as e:
            logger.error(f"❌ Dashboard initialization failed: {e}")
            return False

    def start(self) -> bool:
        """
        Start dashboard server in background thread

        Returns:
            bool: True if started successfully
        """
        if not self.app or not self.socketio:
            logger.error("❌ Dashboard not initialized, call initialize() first")
            return False

        try:
            logger.info(f"🚀 Starting dashboard server on port {self.port}...")

            # Start SocketIO server in thread
            self.dashboard_thread = threading.Thread(
                target=self._run_dashboard,
                daemon=True
            )
            self.dashboard_thread.start()

            self.running = True

            logger.info(f"✅ Dashboard started: http://localhost:{self.port}")
            logger.info(f"   Device List: http://localhost:{self.port}/devices")
            logger.info(f"   API: http://localhost:{self.port}/api/devices")

            return True

        except Exception as e:
            logger.error(f"❌ Failed to start dashboard: {e}")
            return False

    def _run_dashboard(self):
        """Run SocketIO server (runs in thread)"""
        try:
            self.socketio.run(
                self.app,
                host='0.0.0.0',
                port=self.port,
                debug=self.debug,
                allow_unsafe_werkzeug=True,
                use_reloader=False  # Important: disable reloader in thread
            )
        except Exception as e:
            logger.error(f"❌ Dashboard server error: {e}")
            self.running = False

    def connect_device_discovery(self, device_discovery_service):
        """
        Connect Device Discovery Service to emit WebSocket events

        Args:
            device_discovery_service: DeviceDiscoveryService instance
        """
        if not self.socketio:
            logger.warning("⚠️  Cannot connect device discovery - dashboard not initialized")
            return

        try:
            # Pass socketio to device discovery service
            device_discovery_service.socketio = self.socketio

            logger.info("✅ Device Discovery Service connected to dashboard WebSocket")

        except Exception as e:
            logger.error(f"❌ Failed to connect device discovery: {e}")

    def stop(self):
        """Stop dashboard server"""
        if not self.running:
            return

        try:
            logger.info("🛑 Stopping dashboard...")

            # SocketIO will stop when thread terminates
            self.running = False

            logger.info("✅ Dashboard stopped")

        except Exception as e:
            logger.error(f"⚠️  Error stopping dashboard: {e}")

    def get_status(self) -> Dict:
        """
        Get dashboard status

        Returns:
            dict: Dashboard status information
        """
        return {
            'running': self.running,
            'port': self.port,
            'url': f'http://localhost:{self.port}' if self.running else None,
            'type': 'flask-socketio',
            'websocket_enabled': True
        }


def create_dashboard_integration(orchestrator, port=5000, debug=False) -> Optional[DashboardIntegration]:
    """
    Create and initialize dashboard integration

    Args:
        orchestrator: CobaltGraphOrchestrator instance
        port: Dashboard port
        debug: Debug mode

    Returns:
        DashboardIntegration instance or None if failed
    """
    integration = DashboardIntegration(orchestrator, port=port, debug=debug)

    if integration.initialize():
        return integration
    else:
        return None
