"""
CobaltGraph Dashboard Application
Flask application factory with SocketIO integration for real-time network monitoring
"""

from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
import logging
from datetime import datetime

from src.services.database import PostgreSQLDatabase
from src.services.api.devices import create_device_api
from src.services.oui_lookup import OUIResolver

logger = logging.getLogger(__name__)

# Global SocketIO instance (will be initialized in create_app)
socketio = SocketIO()


def create_app(config=None):
    """
    Flask application factory

    Args:
        config: Optional configuration dict

    Returns:
        Flask app instance with SocketIO attached
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # Configuration
    if config is None:
        config = {}

    app.config['SECRET_KEY'] = config.get('secret_key', 'dev-secret-change-in-production')
    app.config['DEBUG'] = config.get('debug', False)

    # Enable CORS for API endpoints
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize SocketIO with app
    socketio.init_app(app,
                      cors_allowed_origins="*",
                      async_mode='threading',
                      logger=True,
                      engineio_logger=True)

    # Initialize services
    try:
        app.db = PostgreSQLDatabase()
        app.oui_resolver = OUIResolver()
        logger.info("✅ Services initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize services: {e}")
        raise

    # Register blueprints
    from .routes import dashboard_bp
    from .websocket import register_socketio_events

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(create_device_api(app.db))

    # Register WebSocket events
    register_socketio_events(socketio, app.db)

    logger.info("✅ Routes and WebSocket events registered")

    return app


def run_app(host='0.0.0.0', port=5000, debug=False):
    """
    Run Flask application with SocketIO

    Args:
        host: Bind address
        port: Bind port
        debug: Debug mode
    """
    app = create_app({'debug': debug})

    logger.info(f"🚀 Starting CobaltGraph Dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    run_app(debug=True)
