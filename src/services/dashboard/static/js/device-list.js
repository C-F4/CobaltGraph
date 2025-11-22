/**
 * Device List Page JavaScript
 * Handles real-time device table updates for CobaltGraph dashboard
 */

class DeviceListManager {
    constructor() {
        this.devices = new Map(); // MAC -> device object
        this.filteredDevices = [];
        this.filters = {
            status: '',
            vendor: '',
            search: ''
        };
    }

    /**
     * Initialize device list page
     */
    init() {
        console.log('🚀 Initializing device list page');

        // Connect WebSocket
        window.suaronWS.connect();

        // Subscribe to device list updates
        window.suaronWS.subscribeDeviceList();

        // Register event handlers
        this._registerWebSocketEvents();

        // Register UI event handlers
        this._registerUIEvents();

        // Initial load
        this._requestDeviceList();
    }

    /**
     * Register WebSocket event handlers
     */
    _registerWebSocketEvents() {
        // Device discovered
        window.suaronWS.on('device_discovered', (device) => {
            console.log('🆕 Device discovered:', device.mac_address);
            this.addDevice(device);
            showToast('New device discovered', device.mac_address, 'success');
        });

        // Device updated
        window.suaronWS.on('device_updated', (device) => {
            console.log('🔄 Device updated:', device.mac_address);
            this.updateDevice(device);
        });

        // Device status changed
        window.suaronWS.on('device_status_changed', (data) => {
            console.log(`📊 Status change: ${data.mac_address} → ${data.new_status}`);
            this.updateDeviceStatus(data.mac_address, data.new_status);
        });

        // Device list data
        window.suaronWS.on('device_list_data', (data) => {
            console.log(`📋 Received ${data.devices.length} devices`);
            this.loadDevices(data.devices);
        });

        // Device count update
        window.suaronWS.on('device_count_update', (data) => {
            this.updateDeviceCount(data.count);
        });
    }

    /**
     * Register UI event handlers
     */
    _registerUIEvents() {
        // Status filter
        document.getElementById('status-filter').addEventListener('change', (e) => {
            this.filters.status = e.target.value;
            this._applyFilters();
        });

        // Vendor filter
        document.getElementById('vendor-filter').addEventListener('input', (e) => {
            this.filters.vendor = e.target.value.toLowerCase();
            this._applyFilters();
        });

        // Search box
        document.getElementById('search-box').addEventListener('input', (e) => {
            this.filters.search = e.target.value.toLowerCase();
            this._applyFilters();
        });

        // Refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this._requestDeviceList();
        });
    }

    /**
     * Request device list from server
     */
    _requestDeviceList() {
        window.suaronWS.requestDeviceList({
            status: this.filters.status || null,
            limit: 1000
        });
    }

    /**
     * Load devices into table
     * @param {Array} devices - Array of device objects
     */
    loadDevices(devices) {
        this.devices.clear();
        devices.forEach(device => {
            this.devices.set(device.mac_address, device);
        });
        this._applyFilters();
    }

    /**
     * Add single device
     * @param {Object} device - Device object
     */
    addDevice(device) {
        this.devices.set(device.mac_address, device);
        this._applyFilters();
    }

    /**
     * Update device
     * @param {Object} device - Updated device object
     */
    updateDevice(device) {
        this.devices.set(device.mac_address, device);
        this._updateDeviceRow(device);
    }

    /**
     * Update device status only
     * @param {string} macAddress - Device MAC
     * @param {string} newStatus - New status
     */
    updateDeviceStatus(macAddress, newStatus) {
        const device = this.devices.get(macAddress);
        if (device) {
            device.status = newStatus;
            this._updateDeviceRow(device);
        }
    }

    /**
     * Update device count badge
     * @param {number} count - Device count
     */
    updateDeviceCount(count) {
        const badge = document.getElementById('device-count');
        if (badge) {
            badge.textContent = count;
        }
    }

    /**
     * Apply filters and re-render table
     */
    _applyFilters() {
        this.filteredDevices = Array.from(this.devices.values()).filter(device => {
            // Status filter
            if (this.filters.status && device.status !== this.filters.status) {
                return false;
            }

            // Vendor filter
            if (this.filters.vendor &&
                (!device.vendor || !device.vendor.toLowerCase().includes(this.filters.vendor))) {
                return false;
            }

            // Search filter (MAC or IP)
            if (this.filters.search) {
                const searchLower = this.filters.search;
                const matchMAC = device.mac_address.toLowerCase().includes(searchLower);
                const matchIP = device.ip_address &&
                               device.ip_address.toLowerCase().includes(searchLower);
                if (!matchMAC && !matchIP) {
                    return false;
                }
            }

            return true;
        });

        // Sort by last_seen descending
        this.filteredDevices.sort((a, b) => {
            return new Date(b.last_seen) - new Date(a.last_seen);
        });

        this._renderTable();
    }

    /**
     * Render table with filtered devices
     */
    _renderTable() {
        const tbody = document.getElementById('device-table-body');

        if (this.filteredDevices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="10" class="text-center text-muted">
                        No devices found
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.filteredDevices.map(device =>
            this._renderDeviceRow(device)
        ).join('');

        // Update count
        this.updateDeviceCount(this.filteredDevices.length);
    }

    /**
     * Render single device row
     * @param {Object} device - Device object
     * @returns {string} HTML string
     */
    _renderDeviceRow(device) {
        const statusClass = `status-${device.status}`;
        const vendorBadge = escapeHtml(device.vendor || 'Unknown');
        const firstSeen = formatTimeAgo(device.first_seen);
        const lastSeen = formatTimeAgo(device.last_seen);

        return `
            <tr class="device-row" data-mac="${escapeHtml(device.mac_address)}">
                <td>
                    <span class="status-badge ${statusClass}">
                        <i class="bi bi-circle-fill"></i> ${escapeHtml(device.status)}
                    </span>
                </td>
                <td><code>${escapeHtml(device.mac_address)}</code></td>
                <td>${escapeHtml(device.ip_address || '-')}</td>
                <td><span class="badge bg-secondary">${vendorBadge}</span></td>
                <td>${escapeHtml(device.device_type || 'unknown')}</td>
                <td class="text-muted small">${firstSeen}</td>
                <td class="text-muted small">${lastSeen}</td>
                <td><span class="badge bg-info">${device.connection_count || 0}</span></td>
                <td><span class="badge bg-danger">${device.threat_count || 0}</span></td>
                <td>
                    <a href="/devices/${encodeURIComponent(device.mac_address)}"
                       class="btn btn-sm btn-outline-primary">
                        <i class="bi bi-eye"></i> View
                    </a>
                </td>
            </tr>
        `;
    }

    /**
     * Update single device row in place
     * @param {Object} device - Device object
     */
    _updateDeviceRow(device) {
        const row = document.querySelector(`tr[data-mac="${device.mac_address}"]`);
        if (row) {
            row.outerHTML = this._renderDeviceRow(device);
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    window.deviceListManager = new DeviceListManager();
    window.deviceListManager.init();
});
