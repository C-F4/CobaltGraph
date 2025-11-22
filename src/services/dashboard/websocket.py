"""
CobaltGraph WebSocket Event Handlers
Room-based real-time updates for network monitoring dashboard
"""

from flask_socketio import emit, join_room, leave_room, rooms
from flask import request
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def register_socketio_events(socketio, database):
    """
    Register all SocketIO event handlers

    Args:
        socketio: SocketIO instance
        database: Database instance
    """

    @socketio.on('connect')
    def handle_connect():
        """Client connected"""
        client_id = request.sid
        logger.info(f"🔌 Client connected: {client_id}")

        emit('connection_established', {
            'status': 'connected',
            'client_id': client_id,
            'timestamp': str(datetime.now())
        })

    @socketio.on('disconnect')
    def handle_disconnect():
        """Client disconnected"""
        client_id = request.sid
        logger.info(f"🔌 Client disconnected: {client_id}")

    @socketio.on('subscribe_device_list')
    def handle_subscribe_device_list():
        """Subscribe to device list updates"""
        client_id = request.sid
        join_room('device_list')

        logger.info(f"📋 Client {client_id} subscribed to device_list")

        # Send current device count
        try:
            # Get device count from database
            devices = database.get_devices(limit=10000)
            device_count = len(devices)
            emit('device_count_update', {'count': device_count})
        except Exception as e:
            logger.error(f"Error getting device count: {e}")

    @socketio.on('unsubscribe_device_list')
    def handle_unsubscribe_device_list():
        """Unsubscribe from device list updates"""
        client_id = request.sid
        leave_room('device_list')
        logger.info(f"📋 Client {client_id} unsubscribed from device_list")

    @socketio.on('subscribe_device')
    def handle_subscribe_device(data):
        """
        Subscribe to specific device updates

        Args:
            data: {'mac_address': 'AA:BB:CC:DD:EE:FF'}
        """
        client_id = request.sid
        mac_address = data.get('mac_address')

        if not mac_address:
            emit('error', {'message': 'mac_address required'})
            return

        room = f'device_{mac_address}'
        join_room(room)

        logger.info(f"📱 Client {client_id} subscribed to device {mac_address}")

        # Send current device data
        try:
            device = database.get_device_by_mac(mac_address)
            if device:
                emit('device_data', device)
            else:
                emit('error', {'message': 'Device not found'})
        except Exception as e:
            logger.error(f"Error getting device {mac_address}: {e}")
            emit('error', {'message': str(e)})

    @socketio.on('unsubscribe_device')
    def handle_unsubscribe_device(data):
        """Unsubscribe from specific device updates"""
        client_id = request.sid
        mac_address = data.get('mac_address')

        if mac_address:
            room = f'device_{mac_address}'
            leave_room(room)
            logger.info(f"📱 Client {client_id} unsubscribed from device {mac_address}")

    @socketio.on('request_device_list')
    def handle_request_device_list(data):
        """
        Request device list (with filters)

        Args:
            data: {
                'status': 'active' | 'offline' | 'idle' | None,
                'limit': 100
            }
        """
        try:
            status = data.get('status') if data else None
            limit = data.get('limit', 100) if data else 100

            devices = database.get_devices(status=status, limit=limit)

            emit('device_list_data', {
                'devices': devices,
                'total': len(devices),
                'timestamp': str(datetime.now())
            })

        except Exception as e:
            logger.error(f"Error getting device list: {e}")
            emit('error', {'message': str(e)})

    # ========================================================================
    # Server-side event emitters (called from Device Discovery Service)
    # ========================================================================

    def emit_device_discovered(device_data):
        """
        Emit device_discovered event to device_list room

        Args:
            device_data: Device dictionary
        """
        socketio.emit('device_discovered', device_data, room='device_list')
        logger.debug(f"📡 Emitted device_discovered: {device_data.get('mac_address')}")

    def emit_device_updated(device_data):
        """
        Emit device_updated event to both device_list and device-specific room

        Args:
            device_data: Device dictionary
        """
        mac = device_data.get('mac_address')

        # Emit to device list
        socketio.emit('device_updated', device_data, room='device_list')

        # Emit to device-specific room
        socketio.emit('device_updated', device_data, room=f'device_{mac}')

        logger.debug(f"📡 Emitted device_updated: {mac}")

    def emit_device_status_changed(mac_address, old_status, new_status):
        """
        Emit device_status_changed event

        Args:
            mac_address: Device MAC
            old_status: Previous status
            new_status: New status
        """
        data = {
            'mac_address': mac_address,
            'old_status': old_status,
            'new_status': new_status,
            'timestamp': str(datetime.now())
        }

        socketio.emit('device_status_changed', data, room='device_list')
        socketio.emit('device_status_changed', data, room=f'device_{mac_address}')

        logger.debug(f"📡 Emitted status change: {mac_address} {old_status} → {new_status}")

    def emit_connection_added(connection_data):
        """
        Emit connection_added event to device-specific room

        Args:
            connection_data: Connection dictionary
        """
        mac = connection_data.get('src_mac')
        if mac:
            socketio.emit('connection_added', connection_data, room=f'device_{mac}')
            logger.debug(f"📡 Emitted connection_added for device {mac}")

    # Store emitter functions on socketio object for external access
    socketio.emit_device_discovered = emit_device_discovered
    socketio.emit_device_updated = emit_device_updated
    socketio.emit_device_status_changed = emit_device_status_changed
    socketio.emit_connection_added = emit_connection_added

    logger.info("✅ WebSocket events registered")
