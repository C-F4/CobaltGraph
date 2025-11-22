/**
 * Device Detail Page JavaScript
 * Real-time device monitoring for CobaltGraph dashboard
 */

class DeviceDetailManager {
    constructor(macAddress) {
        this.macAddress = macAddress;
        this.connections = [];
        this.events = [];
    }

    /**
     * Initialize device detail page
     */
    init() {
        console.log(`🚀 Initializing device detail page for ${this.macAddress}`);

        // Connect WebSocket
        window.suaronWS.connect();

        // Subscribe to this device
        window.suaronWS.subscribeDevice(this.macAddress);

        // Register event handlers
        this._registerWebSocketEvents();

        // Load initial data
        this._loadDeviceData();
        this._loadConnections();
        this._loadEvents();

        // Register UI handlers
        this._registerUIHandlers();
    }

    /**
     * Register WebSocket event handlers
     */
    _registerWebSocketEvents() {
        // Device data (initial)
        window.suaronWS.on('device_data', (device) => {
            console.log('📱 Received device data:', device);
            this._updateDeviceHeader(device);
            this._updateStats(device);
        });

        // Device updated
        window.suaronWS.on('device_updated', (device) => {
            if (device.mac_address === this.macAddress) {
                console.log('🔄 Device updated:', device);
                this._updateDeviceHeader(device);
                this._updateStats(device);
            }
        });

        // Connection added
        window.suaronWS.on('connection_added', (connection) => {
            if (connection.src_mac === this.macAddress) {
                console.log('🔗 New connection:', connection);
                this._addConnection(connection);
            }
        });

        // Status changed
        window.suaronWS.on('device_status_changed', (data) => {
            if (data.mac_address === this.macAddress) {
                console.log(`📊 Status changed: ${data.new_status}`);
                this._updateStatus(data.new_status);
            }
        });
    }

    /**
     * Register UI event handlers
     */
    _registerUIHandlers() {
        const refreshBtn = document.getElementById('refresh-device-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this._loadDeviceData();
                this._loadConnections();
                this._loadEvents();
            });
        }
    }

    /**
     * Load device data via API
     */
    async _loadDeviceData() {
        try {
            const response = await fetch(`/api/devices/${this.macAddress}`);
            const data = await response.json();

            if (data.success) {
                this._updateDeviceHeader(data.device);
                this._updateStats(data.device);
            } else {
                console.error('Failed to load device:', data.error);
            }
        } catch (error) {
            console.error('Error loading device data:', error);
        }
    }

    /**
     * Load device connections
     */
    async _loadConnections() {
        try {
            const response = await fetch(`/api/devices/${this.macAddress}/connections?limit=100`);
            const data = await response.json();

            if (data.success) {
                this.connections = data.connections;
                this._renderConnections();
            }
        } catch (error) {
            console.error('Error loading connections:', error);
        }
    }

    /**
     * Load device events
     */
    async _loadEvents() {
        try {
            const response = await fetch(`/api/devices/${this.macAddress}/events?limit=50`);
            const data = await response.json();

            if (data.success) {
                this.events = data.events;
                this._renderEvents();
            }
        } catch (error) {
            console.error('Error loading events:', error);
        }
    }

    /**
     * Update device header
     */
    _updateDeviceHeader(device) {
        // Update IP
        const ipEl = document.getElementById('device-ip');
        if (ipEl) {
            ipEl.textContent = device.ip_address || 'No IP';
        }

        // Update vendor
        const vendorEl = document.getElementById('device-vendor');
        if (vendorEl) {
            vendorEl.textContent = device.vendor || 'Unknown';
        }

        // Update status
        const statusEl = document.getElementById('device-status');
        if (statusEl) {
            statusEl.className = `status-badge status-${device.status}`;
            statusEl.innerHTML = `<i class="bi bi-circle-fill"></i> ${device.status}`;
        }
    }

    /**
     * Update statistics cards
     */
    _updateStats(device) {
        // Connection count
        const connCountEl = document.getElementById('connection-count');
        if (connCountEl) {
            connCountEl.textContent = device.connection_count || 0;
        }

        // Threat count
        const threatCountEl = document.getElementById('threat-count');
        if (threatCountEl) {
            threatCountEl.textContent = device.threat_count || 0;
        }

        // Unique destinations
        const uniqueEl = document.getElementById('unique-destinations');
        if (uniqueEl) {
            // Calculate from connections if available
            if (this.connections.length > 0) {
                const uniqueIPs = new Set(this.connections.map(c => c.dst_ip));
                uniqueEl.textContent = uniqueIPs.size;
            } else {
                uniqueEl.textContent = '-';
            }
        }

        // Calculate days active
        if (device.first_seen) {
            const firstSeen = new Date(device.first_seen);
            const now = new Date();
            const days = Math.floor((now - firstSeen) / (1000 * 60 * 60 * 24));
            const daysEl = document.getElementById('days-active');
            if (daysEl) {
                daysEl.textContent = days;
            }
        }
    }

    /**
     * Add new connection to table
     */
    _addConnection(connection) {
        this.connections.unshift(connection);
        if (this.connections.length > 100) {
            this.connections.pop();
        }
        this._renderConnections();

        // Update unique destinations count
        const uniqueIPs = new Set(this.connections.map(c => c.dst_ip));
        const uniqueEl = document.getElementById('unique-destinations');
        if (uniqueEl) {
            uniqueEl.textContent = uniqueIPs.size;
        }
    }

    /**
     * Render connections table
     */
    _renderConnections() {
        const tbody = document.getElementById('connections-table-body');
        if (!tbody) return;

        if (this.connections.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-muted">
                        No connections yet
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.connections.map(conn => `
            <tr>
                <td class="text-muted small">${formatDateTime(conn.timestamp)}</td>
                <td><code>${escapeHtml(conn.dst_ip)}</code></td>
                <td>${conn.dst_port || '-'}</td>
                <td>${escapeHtml(conn.protocol || 'TCP')}</td>
                <td>${escapeHtml(conn.dst_country || '-')}</td>
                <td>${escapeHtml(conn.dst_org || '-')}</td>
                <td>
                    ${conn.threat_score > 0 ?
                      `<span class="badge bg-danger">${conn.threat_score}</span>` :
                      '<span class="text-muted">-</span>'}
                </td>
            </tr>
        `).join('');
    }

    /**
     * Render events list
     */
    _renderEvents() {
        const list = document.getElementById('events-list');
        if (!list) return;

        if (this.events.length === 0) {
            list.innerHTML = `
                <div class="text-center text-muted">
                    No events yet
                </div>
            `;
            return;
        }

        list.innerHTML = this.events.map(event => `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${escapeHtml(event.event_type)}</h6>
                    <small class="text-muted">${formatDateTime(event.timestamp)}</small>
                </div>
                <p class="mb-1">
                    ${event.old_value ? escapeHtml(event.old_value) + ' → ' : ''}
                    ${escapeHtml(event.new_value || '')}
                </p>
            </div>
        `).join('');
    }

    /**
     * Update device status
     */
    _updateStatus(newStatus) {
        console.log(`Status updated to: ${newStatus}`);

        const statusEl = document.getElementById('device-status');
        if (statusEl) {
            statusEl.className = `status-badge status-${newStatus}`;
            statusEl.innerHTML = `<i class="bi bi-circle-fill"></i> ${newStatus}`;
        }
    }

    /**
     * Cleanup on page unload
     */
    cleanup() {
        window.suaronWS.unsubscribeDevice(this.macAddress);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Extract MAC from URL
    const pathParts = window.location.pathname.split('/');
    const macAddress = pathParts[pathParts.length - 1];

    if (macAddress) {
        window.deviceDetailManager = new DeviceDetailManager(macAddress);
        window.deviceDetailManager.init();
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.deviceDetailManager) {
        window.deviceDetailManager.cleanup();
    }
});
