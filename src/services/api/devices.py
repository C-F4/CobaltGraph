"""
CobaltGraph Device Inventory API
Phase 0-1: RESTful API endpoints for device management

Endpoints:
- GET  /api/devices              - List all devices (paginated, filtered)
- GET  /api/devices/{mac}        - Get device details
- GET  /api/devices/{mac}/connections  - Get device connections
- GET  /api/devices/{mac}/events       - Get device events
- GET  /api/devices/stats        - Get device statistics

Features:
- Pagination (page, per_page)
- Filtering (status, vendor, search)
- Sorting (by field, direction)
- JSON responses
- Error handling
"""

import logging
from typing import Dict, List, Optional
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# Create Blueprint for device API
device_api = Blueprint('device_api', __name__, url_prefix='/api/devices')


def create_device_api(database):
    """
    Create device API blueprint with database dependency injection

    Args:
        database: PostgreSQL database instance

    Returns:
        Flask Blueprint
    """

    @device_api.route('/', methods=['GET'])
    @device_api.route('', methods=['GET'])
    def list_devices():
        """
        GET /api/devices - List all devices

        Query Parameters:
            page (int): Page number (default: 1)
            per_page (int): Items per page (default: 50, max: 200)
            status (str): Filter by status (discovered, active, idle, offline)
            vendor (str): Filter by vendor (partial match)
            search (str): Search by MAC or IP (partial match)
            sort (str): Sort field (default: last_seen)
            order (str): Sort order (asc, desc) (default: desc)

        Returns:
            JSON: {
                "total": int,
                "page": int,
                "per_page": int,
                "devices": [...],
                "success": true
            }
        """
        try:
            # Parse pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            per_page = min(per_page, 200)  # Max 200 per page

            # Parse filter parameters
            status = request.args.get('status')
            vendor = request.args.get('vendor')
            search = request.args.get('search')

            # Parse sort parameters
            sort_field = request.args.get('sort', 'last_seen')
            sort_order = request.args.get('order', 'desc')

            # Get devices from database
            devices = database.get_devices(status=status, limit=per_page * 10)

            # Apply additional filtering (vendor, search)
            if vendor:
                devices = [
                    d for d in devices
                    if d.get('vendor') and vendor.lower() in d['vendor'].lower()
                ]

            if search:
                search_lower = search.lower()
                devices = [
                    d for d in devices
                    if search_lower in d.get('mac_address', '').lower()
                    or search_lower in str(d.get('ip_address', '')).lower()
                ]

            # Simple pagination (client-side for now)
            total = len(devices)
            start = (page - 1) * per_page
            end = start + per_page
            devices_page = devices[start:end]

            return jsonify({
                'success': True,
                'total': total,
                'page': page,
                'per_page': per_page,
                'devices': devices_page
            })

        except Exception as e:
            logger.error(f"Error listing devices: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @device_api.route('/<mac_address>', methods=['GET'])
    def get_device(mac_address: str):
        """
        GET /api/devices/{mac} - Get device details

        Args:
            mac_address: Device MAC address (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)

        Returns:
            JSON: {
                "device": {...},
                "success": true
            }
        """
        try:
            # Normalize MAC address format
            mac = mac_address.upper().replace('-', ':')

            # Get device from database
            device = database.get_device_by_mac(mac)

            if not device:
                return jsonify({
                    'success': False,
                    'error': 'Device not found'
                }), 404

            return jsonify({
                'success': True,
                'device': device
            })

        except Exception as e:
            logger.error(f"Error getting device {mac_address}: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @device_api.route('/<mac_address>/connections', methods=['GET'])
    def get_device_connections(mac_address: str):
        """
        GET /api/devices/{mac}/connections - Get device connections

        Query Parameters:
            limit (int): Maximum connections to return (default: 100, max: 1000)
            threat_only (bool): Only show threat connections (default: false)

        Returns:
            JSON: {
                "total": int,
                "connections": [...],
                "success": true
            }
        """
        try:
            # Parse parameters
            limit = request.args.get('limit', 100, type=int)
            limit = min(limit, 1000)  # Max 1000
            threat_only = request.args.get('threat_only', 'false').lower() == 'true'

            # Normalize MAC
            mac = mac_address.upper().replace('-', ':')

            # Get connections
            connections = database.get_connections_by_device(mac, limit=limit)

            # Filter threats if requested
            if threat_only:
                connections = [
                    c for c in connections
                    if c.get('threat_score', 0) > 0
                ]

            return jsonify({
                'success': True,
                'total': len(connections),
                'connections': connections
            })

        except Exception as e:
            logger.error(f"Error getting connections for {mac_address}: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @device_api.route('/<mac_address>/events', methods=['GET'])
    def get_device_events(mac_address: str):
        """
        GET /api/devices/{mac}/events - Get device events

        Query Parameters:
            limit (int): Maximum events to return (default: 50, max: 500)

        Returns:
            JSON: {
                "total": int,
                "events": [...],
                "success": true
            }
        """
        try:
            # Parse parameters
            limit = request.args.get('limit', 50, type=int)
            limit = min(limit, 500)  # Max 500

            # Normalize MAC
            mac = mac_address.upper().replace('-', ':')

            # Get events
            events = database.get_device_events(mac, limit=limit)

            return jsonify({
                'success': True,
                'total': len(events),
                'events': events
            })

        except Exception as e:
            logger.error(f"Error getting events for {mac_address}: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @device_api.route('/stats', methods=['GET'])
    def get_device_stats():
        """
        GET /api/devices/stats - Get device statistics

        Returns:
            JSON: {
                "total_devices": int,
                "active_devices": int,
                "offline_devices": int,
                "vendors": {...},
                "success": true
            }
        """
        try:
            # Get all devices
            all_devices = database.get_devices(limit=10000)

            # Calculate statistics
            total = len(all_devices)
            active = len([d for d in all_devices if d.get('status') == 'active'])
            offline = len([d for d in all_devices if d.get('status') == 'offline'])
            idle = len([d for d in all_devices if d.get('status') == 'idle'])
            discovered = len([d for d in all_devices if d.get('status') == 'discovered'])

            # Vendor breakdown
            vendors = {}
            for device in all_devices:
                vendor = device.get('vendor', 'Unknown')
                vendors[vendor] = vendors.get(vendor, 0) + 1

            # Top vendors
            top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

            return jsonify({
                'success': True,
                'total_devices': total,
                'by_status': {
                    'active': active,
                    'idle': idle,
                    'offline': offline,
                    'discovered': discovered
                },
                'top_vendors': dict(top_vendors),
                'total_vendors': len(vendors)
            })

        except Exception as e:
            logger.error(f"Error getting device stats: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return device_api


# ==============================================================================
# FLASK APP FACTORY (for standalone testing)
# ==============================================================================

def create_test_app():
    """Create Flask app for testing (standalone mode)"""
    from flask import Flask
    from src.services.database import PostgreSQLDatabase

    app = Flask(__name__)

    # Initialize database
    db = PostgreSQLDatabase()

    # Register device API
    app.register_blueprint(create_device_api(db))

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint"""
        return jsonify({'status': 'healthy', 'service': 'device_api'})

    return app


if __name__ == '__main__':
    """
    Test device API standalone
    Usage: python3 devices.py
    """
    import sys
    import os

    print("=" * 60)
    print("CobaltGraph Device API - Test Mode")
    print("=" * 60)
    print()
    print("Starting Flask development server...")
    print("Endpoints:")
    print("  GET  /api/devices")
    print("  GET  /api/devices/{mac}")
    print("  GET  /api/devices/{mac}/connections")
    print("  GET  /api/devices/{mac}/events")
    print("  GET  /api/devices/stats")
    print("  GET  /health")
    print()

    try:
        app = create_test_app()
        app.run(host='0.0.0.0', port=5000, debug=True)

    except FileNotFoundError as e:
        print(f"❌ Config error: {e}")
        print("   Please configure config/database.conf first")
        sys.exit(1)

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
