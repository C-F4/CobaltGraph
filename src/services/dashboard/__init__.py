"""
CobaltGraph Dashboard Service
Real-time network monitoring dashboard with WebSocket support
"""

from .app import create_app, run_app, socketio

__all__ = ['create_app', 'run_app', 'socketio']
