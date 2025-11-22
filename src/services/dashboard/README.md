# CobaltGraph Dashboard - Real-time Network Monitoring

**Phase 0: Device Discovery MVP**

Real-time web-based dashboard for monitoring network devices discovered by CobaltGraph.

## Features

### Task 0.6: Dashboard UI with WebSocket Updates ✅

- **Real-time Device Inventory**: Live view of all discovered network devices
- **WebSocket Updates**: Instant notifications when devices are discovered or updated
- **Device Detail Pages**: Comprehensive view of individual device activity
- **Connection Monitoring**: Track all network connections per device
- **Event Timeline**: Audit trail of device state changes
- **Status Badges**: Visual indicators for device states (active, idle, offline, discovered)
- **Search & Filtering**: Filter devices by status, vendor, MAC, or IP
- **Responsive Design**: Mobile-friendly Bootstrap 5 interface

## Architecture

### Technology Stack

- **Backend**: Flask 2.3+ with Flask-SocketIO 5.3+
- **Frontend**: Bootstrap 5, htmx, Alpine.js
- **Real-time**: WebSocket (Socket.IO) with room-based architecture
- **Database**: PostgreSQL (via existing database service)

### WebSocket Room Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Flask-SocketIO Server                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Room:        │  │ Room:        │  │ Room:        │      │
│  │ device_list  │  │ device_AA... │  │ device_BB... │      │
│  │              │  │              │  │              │      │
│  │ [Client 1]   │  │ [Client 2]   │  │ [Client 3]   │      │
│  │ [Client 2]   │  │              │  │              │      │
│  │ [Client 3]   │  │              │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Event Flow

1. **ARP Monitor** detects device → Emits callback
2. **Device Discovery Service** → Writes to database
3. Database write complete → **Emit WebSocket event** to appropriate room
4. Clients in room → Receive update → **Update UI** (htmx partial refresh)

## Project Structure

```
src/services/dashboard/
├── app.py                  # Flask application factory
├── routes.py               # Dashboard routes (HTML pages)
├── websocket.py            # WebSocket event handlers
├── templates/
│   ├── base.html           # Base layout with navigation
│   ├── index.html          # Dashboard home
│   ├── devices/
│   │   ├── list.html       # Device inventory table
│   │   └── detail.html     # Device detail page
│   └── errors/
│       ├── 404.html        # Not found page
│       └── 500.html        # Server error page
└── static/
    ├── css/
    │   └── dashboard.css   # Custom styling
    └── js/
        ├── websocket.js    # WebSocket client wrapper
        ├── dashboard.js    # Common utilities
        ├── device-list.js  # Device list real-time updates
        └── device-detail.js # Device detail real-time updates
```

## Usage

### Starting the Dashboard

```bash
# From CobaltGraph root directory
python3 run_dashboard.py
```

Or directly:

```bash
cd src/services/dashboard
python3 app.py
```

### Accessing the Dashboard

- **Dashboard Home**: http://localhost:5000
- **Device List**: http://localhost:5000/devices
- **Device Detail**: http://localhost:5000/devices/AA:BB:CC:DD:EE:FF
- **API Endpoints**: http://localhost:5000/api/devices
- **Health Check**: http://localhost:5000/health

### WebSocket Events

#### Client → Server

- `subscribe_device_list` - Subscribe to device list updates
- `subscribe_device` - Subscribe to specific device updates
- `request_device_list` - Request current device list
- `unsubscribe_device_list` - Unsubscribe from device list
- `unsubscribe_device` - Unsubscribe from specific device

#### Server → Client

- `device_discovered` - New device found
- `device_updated` - Device information changed
- `device_status_changed` - Device status changed (active/idle/offline)
- `connection_added` - New connection detected
- `device_count_update` - Total device count changed

## Integration with Device Discovery

The dashboard automatically receives real-time updates from the Device Discovery Service:

```python
from src.services.dashboard import socketio
from src.services.arp_monitor import DeviceDiscoveryService

# Initialize with SocketIO integration
discovery = DeviceDiscoveryService(
    database=db,
    oui_lookup=oui,
    socketio=socketio  # Pass socketio instance
)
```

When devices are discovered or updated, WebSocket events are automatically emitted to connected clients.

## API Endpoints

All REST API endpoints from Task 0.5 are available:

- `GET /api/devices` - List all devices (paginated, filtered)
- `GET /api/devices/{mac}` - Get device details
- `GET /api/devices/{mac}/connections` - Get device connections
- `GET /api/devices/{mac}/events` - Get device events
- `GET /api/devices/stats` - Get device statistics

## Security Considerations

- **CORS**: Enabled for API endpoints (configured in app.py)
- **Input Validation**: MAC addresses normalized and validated
- **XSS Prevention**: All user input escaped in templates
- **WebSocket Auth**: Currently open (production should add authentication)

## Development

### Debug Mode

The dashboard runs in debug mode by default during development:

```python
run_app(host='0.0.0.0', port=5000, debug=True)
```

### Console Logging

WebSocket events are logged to browser console:
- 🔌 Connection events
- 📋 Device list subscriptions
- 🆕 Device discovered
- 🔄 Device updated

## Performance

- **Room-based Updates**: Only send updates to subscribed clients
- **Efficient Filtering**: Client-side filtering reduces server load
- **Connection Pooling**: Reuses database connections
- **Minimal Dependencies**: Fast startup, low memory footprint

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Next Steps (Phase 1)

- [ ] User authentication & authorization
- [ ] Multi-user support with role-based access
- [ ] Advanced visualizations (network graphs, charts)
- [ ] Alert system for threat detection
- [ ] Export functionality (CSV, JSON, PDF)
- [ ] Dark mode theme
- [ ] Customizable dashboards
- [ ] Real-time packet capture viewer

## Troubleshooting

### WebSocket Connection Issues

If WebSocket fails to connect:
1. Check that SocketIO is properly initialized
2. Verify CORS settings allow your client origin
3. Check browser console for connection errors
4. Ensure port 5000 is accessible

### Database Connection Errors

If database connection fails:
1. Verify PostgreSQL is running
2. Check `config/database.conf` configuration
3. Ensure database schema is initialized
4. Check PostgreSQL logs for errors

### No Devices Showing

If no devices appear in the dashboard:
1. Verify Device Discovery Service is running
2. Check that ARP monitor has captured packets
3. Verify database contains device records
4. Check browser console for JavaScript errors

## Contributing

See main CobaltGraph documentation for contribution guidelines.

## License

Part of the CobaltGraph project - see LICENSE file in project root.
