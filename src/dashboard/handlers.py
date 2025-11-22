"""
CobaltGraph Dashboard HTTP Handlers
Request routing and response generation

Handles:
- HTTP request routing
- Authentication
- Static file serving
- API endpoint dispatch
- Error responses
"""

import logging
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

logger = logging.getLogger(__name__)

class DashboardHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for dashboard

    Routes requests to appropriate handlers based on path
    """

    # Will be set by server
    watchfloor = None
    api = None

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # Route to appropriate handler
        if path == '/':
            self._serve_dashboard()
        elif path.startswith('/api/'):
            self._handle_api(path, parsed_path.query)
        elif path.startswith('/static/'):
            self._serve_static(path)
        else:
            self._send_error(404, "Not Found")

    def _serve_dashboard(self):
        """Serve main dashboard HTML"""
        # TODO: Load and serve templates/dashboard.html
        logger.debug("Serving dashboard HTML")
        self._send_response(200, "<html><body><h1>CobaltGraph Dashboard</h1><p>TODO: Load template</p></body></html>", "text/html")

    def _handle_api(self, path: str, query: str):
        """
        Handle API endpoint requests

        Args:
            path: API path (e.g., /api/connections)
            query: Query string
        """
        # TODO: Route to API methods
        logger.debug(f"API request: {path}")

        if path == '/api/health':
            # TODO: Call api.get_health()
            response = {"status": "ok"}
            self._send_json(response)
        else:
            self._send_error(404, "API endpoint not found")

    def _serve_static(self, path: str):
        """
        Serve static files (CSS, JS)

        Args:
            path: Static file path
        """
        # TODO: Implement static file serving
        self._send_error(404, "Static files not implemented")

    def _send_response(self, code: int, content: str, content_type: str = "text/plain"):
        """Send HTTP response"""
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.send_header('Content-length', len(content))
        self.end_headers()
        self.wfile.write(content.encode())

    def _send_json(self, data: dict):
        """Send JSON response"""
        import json
        content = json.dumps(data)
        self._send_response(200, content, "application/json")

    def _send_error(self, code: int, message: str):
        """Send error response"""
        self.send_error(code, message)

    def log_message(self, format, *args):
        """Override to use Python logging"""
        logger.debug(f"HTTP: {format % args}")
