"""
CobaltGraph Dashboard Server
HTTP server and request handler for web dashboard

Extracted from watchfloor.py MinimalDashboardHandler class

Features:
- HTTP Basic Authentication support
- REST API endpoints (/api/data, /api/health)
- Dashboard HTML serving
- Real-time connection data
- System health metrics
- Threat intelligence integration
"""

import logging
import json
import time
import base64
import re
import ssl
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class DashboardHandler(BaseHTTPRequestHandler):
    """
    Dashboard request handler

    Serves:
    - Web dashboard UI (/)
    - Connection data API (/api/data)
    - Health check API (/api/health)

    Features:
    - HTTP Basic Authentication
    - JSON API responses
    - Signal stack integration (database, geo, heartbeat)
    """

    def log_request(self, code='-', size='-'):
        """Override to use custom logger (sanitized for security - SEC-002 PATCH)"""
        # [SEC-002 PATCH] Sanitize authorization headers from logs
        sanitized_line = self.requestline

        # Check for Authorization header and sanitize
        if 'Authorization' in str(self.headers):
            auth_header = self.headers.get('Authorization', '')
            if auth_header:
                # Replace the actual auth value with placeholder
                sanitized_line = re.sub(
                    r'(Authorization:\s+)[^\s]+.*$',
                    r'\1[REDACTED]',
                    sanitized_line,
                    flags=re.IGNORECASE
                )

        logger.debug(f'"{sanitized_line}" {code} {size}')

    def log_error(self, format, *args):
        """Override to use custom logger"""
        logger.error(f'{self.address_string()} - {format % args}')

    def enforce_https(self) -> bool:
        """
        Enforce HTTPS/TLS for all connections (SEC-008 PATCH)

        Returns:
            True if request was redirected to HTTPS, False otherwise
        """
        # Get watchfloor instance from server
        wf = self.server.watchfloor
        config = getattr(wf, 'config', {})

        # Check if HTTPS is required
        require_https = config.get('require_https', False)

        # Check if this is an HTTPS request
        # HTTP/1.1 connections won't have SSL info, only HTTPS will
        is_https = isinstance(self.connection, ssl.SSLSocket)

        # If HTTPS is required and this is HTTP, redirect
        if require_https and not is_https:
            self.send_response(301)
            host = self.headers.get('Host', 'localhost')
            https_url = f"https://{host}{self.path}"
            self.send_header('Location', https_url)
            self.end_headers()
            logger.warning(f"[SEC-008] Redirecting HTTP to HTTPS: {https_url}")
            return True

        # Log HTTPS enforcement status on first connection
        if not hasattr(self.server, '_https_logged'):
            enable_https = config.get('enable_https', False)
            if enable_https and is_https:
                logger.info(f"[SEC-008] Dashboard using HTTPS/TLS")
            elif require_https and not enable_https:
                logger.warning(f"[SEC-008] HTTPS required but not enabled - accepting HTTP")
            self.server._https_logged = True

        return False

    def check_authentication(self) -> bool:
        """
        Check HTTP Basic Authentication

        Returns:
            True if authenticated or auth disabled, False otherwise
        """
        # Get watchfloor instance from server
        wf = self.server.watchfloor
        config = getattr(wf, 'config', {})

        # Check if auth is enabled
        if not config.get('enable_auth', False):
            return True  # Auth disabled, allow access

        # Check for Authorization header
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False

        # Parse Basic auth
        try:
            # Format: "Basic base64(username:password)"
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False

            # Decode credentials
            decoded = base64.b64decode(auth_string).decode('utf-8')
            username, password = decoded.split(':', 1)

            # Check against config
            expected_username = config.get('auth_username', 'admin')
            expected_password = config.get('auth_password', 'changeme')

            return username == expected_username and password == expected_password

        except Exception as e:
            # [SEC-003 PATCH] Log generic error, not exception details
            logger.debug(f"Authentication validation failed (invalid header format)")
            logger.debug(f"[SEC-003] Error type: {type(e).__name__} (details redacted)")
            return False

    def require_authentication(self):
        """Send 401 Unauthorized response with authentication prompt"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="CobaltGraph Watchfloor"')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

        html = """<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>401 Unauthorized</h1>
<p>This CobaltGraph instance requires authentication.</p>
</body>
</html>"""
        self.wfile.write(html.encode())

    def do_GET(self):
        """Handle GET requests"""
        self.log_request()

        # [SEC-008 PATCH] Enforce HTTPS
        if self.enforce_https():
            return

        # Check authentication
        if not self.check_authentication():
            self.require_authentication()
            return

        # Route requests
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/data':
            self.serve_api()
        elif self.path == '/api/health':
            self.serve_health()
        elif self.path == '/favicon.ico':
            # Suppress favicon 404 errors
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def serve_dashboard(self):
        """
        Serve dashboard HTML

        Looks for dashboard_minimal.html in dashboard/templates/ directory
        """
        dashboard_path = Path(__file__).parent / 'templates' / 'dashboard_minimal.html'

        if dashboard_path.exists():
            with open(dashboard_path, 'r') as f:
                html = f.read()

            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(html.encode())))
            self.end_headers()

            try:
                self.wfile.write(html.encode())
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected, safe to ignore
                pass
        else:
            logger.error(f"Dashboard file not found: {dashboard_path}")
            self.send_error(404, "Dashboard not found")

    def serve_api(self):
        """
        Serve API data endpoint

        Returns JSON with:
        - Recent connections (last 60 seconds)
        - Geo intelligence (threat zones, countries)
        - System health (component status)
        - Metrics (totals, uptime, queue size)
        """
        try:
            # Get orchestrator/watchfloor instance
            wf = self.server.watchfloor

            # Heartbeat check
            if hasattr(wf, 'heartbeat') and wf.heartbeat:
                wf.heartbeat.beat('dashboard')
                system_health = wf.heartbeat.check_health() if hasattr(wf.heartbeat, 'check_health') else {}
            else:
                system_health = {}

            # Recent connections - works with both orchestrator and watchfloor
            if hasattr(wf, 'get_recent_connections'):
                # New orchestrator method
                connections = wf.get_recent_connections(limit=50)
            elif hasattr(wf, 'connection_monitor'):
                # Old watchfloor method
                connections = wf.connection_monitor.get_recent(
                    limit=50,
                    time_window=60,
                    heartbeat=wf.heartbeat
                )
            else:
                connections = []

            # Get buffer age for staleness indicator
            buffer_age = None
            if hasattr(wf, 'connection_monitor') and hasattr(wf.connection_monitor, 'get_buffer_age'):
                buffer_age = wf.connection_monitor.get_buffer_age()

            # System metrics - flexible for both orchestrator and watchfloor
            if hasattr(wf, 'get_metrics'):
                # Orchestrator has get_metrics()
                metrics = wf.get_metrics()
                # Add derived metrics
                metrics.setdefault('active_countries', len(set(c.get('country', '') for c in connections if c.get('country'))))
                metrics.setdefault('threat_zones', 0)
                metrics.setdefault('queue_size', metrics.get('buffer_size', 0))
            else:
                # Old watchfloor
                metrics = {
                    'total_connections': wf.db.get_connection_count() if hasattr(wf, 'db') else 0,
                    'active_countries': len(wf.geo.countries) if hasattr(wf, 'geo') and hasattr(wf.geo, 'countries') else 0,
                    'threat_zones': len(wf.geo.threat_zones) if hasattr(wf, 'geo') and hasattr(wf.geo, 'threat_zones') else 0,
                    'uptime': int(time.time() - wf.start_time) if hasattr(wf, 'start_time') else 0,
                    'buffer_age': buffer_age,
                    'queue_size': wf.connection_monitor.geo_queue.qsize() if hasattr(wf, 'connection_monitor') and hasattr(wf.connection_monitor, 'geo_queue') else 0
                }

            # Build API response - clean signal stack data
            data = {
                'timestamp': time.time(),
                'connections': connections,  # CONNECTION layer (last 60s only)
                'geo_intelligence': {  # GEOINT layer
                    'threat_zones': wf.geo.threat_zones[:10] if hasattr(wf, 'geo') and hasattr(wf.geo, 'threat_zones') else [],
                    'statistics': {
                        'total_countries': len(wf.geo.countries) if hasattr(wf, 'geo') and hasattr(wf.geo, 'countries') else 0,
                        'active_threats': sum(
                            1 for z in (wf.geo.threat_zones if hasattr(wf, 'geo') and hasattr(wf.geo, 'threat_zones') else [])
                            if z.get('threat_score', 0) > 0.5
                        )
                    }
                },
                'system_health': {  # HEARTBEAT layer
                    'overall': system_health,
                    'components': wf.heartbeat.get_status() if hasattr(wf, 'heartbeat') and hasattr(wf.heartbeat, 'get_status') else {}
                },
                'metrics': metrics,
                'integration_status': {
                    'database': 'ACTIVE' if hasattr(wf, 'db') and wf.db else 'INACTIVE',
                    'geo_engine': 'ACTIVE' if hasattr(wf, 'geo') and wf.geo else 'INACTIVE',
                    'connection_monitor': 'ACTIVE' if hasattr(wf, 'connection_monitor') else 'ORCHESTRATOR'
                }
            }

            # Send JSON response
            response = json.dumps(data).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()

            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                # Client disconnected, safe to ignore
                pass

        except Exception as e:
            logger.error(f"API error: {e}")
            self.send_error(500)

    def serve_health(self):
        """
        Serve health check endpoint

        Simple health check for monitoring/load balancing
        Returns: {"status": "OK"}
        """
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "OK"}')


def create_dashboard_server(host: str, port: int, watchfloor_instance) -> HTTPServer:
    """
    Create HTTP server for dashboard

    Args:
        host: Host to bind to (e.g., 'localhost', '0.0.0.0')
        port: Port to bind to (e.g., 8080)
        watchfloor_instance: Main watchfloor instance with db, geo, heartbeat, etc.

    Returns:
        Configured HTTPServer instance
    """
    server = HTTPServer((host, port), DashboardHandler)
    server.watchfloor = watchfloor_instance

    logger.info(f"📊 Dashboard server created: http://{host}:{port}")
    return server


def run_dashboard_server(server: HTTPServer):
    """
    Run dashboard server (blocking)

    Args:
        server: HTTPServer instance from create_dashboard_server()
    """
    try:
        logger.info("🚀 Dashboard server starting...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("⏹️  Dashboard server stopped")
    finally:
        server.shutdown()
