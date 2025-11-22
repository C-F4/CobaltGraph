"""
CobaltGraph Dashboard Routes
Server-rendered HTML pages for network monitoring
"""

from flask import Blueprint, render_template, jsonify
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    """Dashboard home - redirect to device list"""
    return render_template('index.html')


@dashboard_bp.route('/devices')
def device_list():
    """Device inventory list page"""
    return render_template('devices/list.html')


@dashboard_bp.route('/devices/<mac_address>')
def device_detail(mac_address):
    """Device detail page"""
    # Normalize MAC
    mac = mac_address.upper().replace('-', ':')

    return render_template('devices/detail.html', mac_address=mac)


@dashboard_bp.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'cobaltgraph_dashboard',
        'version': '0.1.0-phase0'
    })


@dashboard_bp.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('errors/404.html'), 404


@dashboard_bp.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f"Internal error: {error}")
    return render_template('errors/500.html'), 500
