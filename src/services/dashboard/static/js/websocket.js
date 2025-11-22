/**
 * CobaltGraph WebSocket Client
 * Room-based real-time updates for network monitoring
 */

class SuaronWebSocket {
    constructor() {
        this.socket = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000; // ms

        this.eventHandlers = {};
        this.rooms = new Set();
    }

    /**
     * Connect to WebSocket server
     */
    connect() {
        console.log('🔌 Connecting to WebSocket server...');

        this.socket = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: this.reconnectDelay,
            reconnectionAttempts: this.maxReconnectAttempts
        });

        this._registerCoreEvents();

        return this;
    }

    /**
     * Register core socket events
     */
    _registerCoreEvents() {
        this.socket.on('connect', () => {
            console.log('✅ WebSocket connected');
            this.connected = true;
            this.reconnectAttempts = 0;
            this._updateConnectionStatus('connected');

            // Resubscribe to rooms after reconnect
            this._resubscribeRooms();
        });

        this.socket.on('disconnect', (reason) => {
            console.warn('❌ WebSocket disconnected:', reason);
            this.connected = false;
            this._updateConnectionStatus('disconnected');
        });

        this.socket.on('connect_error', (error) => {
            console.error('⚠️ WebSocket connection error:', error);
            this._updateConnectionStatus('error');
        });

        this.socket.on('error', (error) => {
            console.error('⚠️ WebSocket error:', error);
        });

        this.socket.on('connection_established', (data) => {
            console.log('🎉 Connection established:', data);
        });
    }

    /**
     * Update connection status indicator in UI
     */
    _updateConnectionStatus(status) {
        const statusEl = document.getElementById('connection-status');
        if (!statusEl) return;

        const icon = statusEl.querySelector('i');
        const text = statusEl.querySelector('span');

        switch (status) {
            case 'connected':
                icon.className = 'bi bi-circle-fill text-success';
                text.textContent = 'Connected';
                break;
            case 'disconnected':
                icon.className = 'bi bi-circle-fill text-warning';
                text.textContent = 'Disconnected';
                break;
            case 'error':
                icon.className = 'bi bi-circle-fill text-danger';
                text.textContent = 'Connection Error';
                break;
        }
    }

    /**
     * Resubscribe to all rooms after reconnect
     */
    _resubscribeRooms() {
        for (const room of this.rooms) {
            if (room === 'device_list') {
                this.subscribeDeviceList();
            } else if (room.startsWith('device_')) {
                const mac = room.replace('device_', '');
                this.subscribeDevice(mac);
            }
        }
    }

    /**
     * Subscribe to device list updates
     */
    subscribeDeviceList() {
        console.log('📋 Subscribing to device_list room');
        this.socket.emit('subscribe_device_list');
        this.rooms.add('device_list');
    }

    /**
     * Unsubscribe from device list updates
     */
    unsubscribeDeviceList() {
        console.log('📋 Unsubscribing from device_list room');
        this.socket.emit('unsubscribe_device_list');
        this.rooms.delete('device_list');
    }

    /**
     * Subscribe to specific device updates
     * @param {string} macAddress - Device MAC address
     */
    subscribeDevice(macAddress) {
        console.log(`📱 Subscribing to device ${macAddress}`);
        this.socket.emit('subscribe_device', { mac_address: macAddress });
        this.rooms.add(`device_${macAddress}`);
    }

    /**
     * Unsubscribe from specific device
     * @param {string} macAddress - Device MAC address
     */
    unsubscribeDevice(macAddress) {
        console.log(`📱 Unsubscribing from device ${macAddress}`);
        this.socket.emit('unsubscribe_device', { mac_address: macAddress });
        this.rooms.delete(`device_${macAddress}`);
    }

    /**
     * Request device list
     * @param {Object} options - Filter options
     */
    requestDeviceList(options = {}) {
        this.socket.emit('request_device_list', options);
    }

    /**
     * Register event handler
     * @param {string} event - Event name
     * @param {Function} handler - Handler function
     */
    on(event, handler) {
        if (!this.eventHandlers[event]) {
            this.eventHandlers[event] = [];
            this.socket.on(event, (data) => {
                this.eventHandlers[event].forEach(h => h(data));
            });
        }
        this.eventHandlers[event].push(handler);
    }

    /**
     * Disconnect from server
     */
    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
        }
    }
}

// Global instance
window.suaronWS = new SuaronWebSocket();
