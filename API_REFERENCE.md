# CobaltGraph API Reference

**Base URL**: `http://localhost:5000/api`
**Format**: JSON
**Authentication**: None (Phase 0 - single-user mode)

## Table of Contents

1. [Device Endpoints](#device-endpoints)
2. [Response Format](#response-format)
3. [Error Handling](#error-handling)
4. [Examples](#examples)

---

## Device Endpoints

### 1. List All Devices

**GET** `/api/devices`

Returns a paginated list of all discovered network devices.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number for pagination |
| `per_page` | int | 50 | Items per page (max: 200) |
| `status` | string | - | Filter by status: `discovered`, `active`, `idle`, `offline` |
| `vendor` | string | - | Filter by vendor name (partial match, case-insensitive) |
| `search` | string | - | Search by MAC address or IP (partial match) |
| `sort` | string | last_seen | Sort field |
| `order` | string | desc | Sort order: `asc` or `desc` |

#### Response

```json
{
  "success": true,
  "total": 42,
  "page": 1,
  "per_page": 50,
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "ip_address": "192.168.1.100",
      "vendor": "Apple, Inc.",
      "device_type": "smartphone",
      "status": "active",
      "first_seen": "2025-11-20T10:00:00",
      "last_seen": "2025-11-20T14:30:00",
      "connection_count": 156,
      "threat_count": 0,
      "metadata": {
        "discovery_method": "arp",
        "hostname": "iPhone-John"
      }
    },
    ...
  ]
}
```

#### Device Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `mac_address` | string | Device MAC address (format: AA:BB:CC:DD:EE:FF) |
| `ip_address` | string | Current IP address |
| `vendor` | string | Vendor name from OUI lookup (e.g., "Apple, Inc.") |
| `device_type` | string | Device type: `unknown`, `smartphone`, `laptop`, `desktop`, `server`, `iot` |
| `status` | string | Current status: `discovered`, `active`, `idle`, `offline` |
| `first_seen` | string | ISO 8601 timestamp of first discovery |
| `last_seen` | string | ISO 8601 timestamp of last activity |
| `connection_count` | int | Total number of connections made |
| `threat_count` | int | Number of threat connections detected |
| `metadata` | object | Additional device information |

#### Example Requests

```bash
# Get all devices
curl http://localhost:5000/api/devices

# Get active devices only
curl http://localhost:5000/api/devices?status=active

# Search for Apple devices
curl http://localhost:5000/api/devices?vendor=apple

# Search by MAC address
curl "http://localhost:5000/api/devices?search=AA:BB:CC"

# Get page 2 with 100 items per page
curl "http://localhost:5000/api/devices?page=2&per_page=100"
```

---

### 2. Get Device Details

**GET** `/api/devices/{mac_address}`

Returns detailed information about a specific device.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `mac_address` | string | Device MAC address (format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF) |

#### Response

```json
{
  "success": true,
  "device": {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "ip_address": "192.168.1.100",
    "vendor": "Apple, Inc.",
    "device_type": "smartphone",
    "status": "active",
    "first_seen": "2025-11-20T10:00:00",
    "last_seen": "2025-11-20T14:30:00",
    "connection_count": 156,
    "threat_count": 0,
    "metadata": {
      "discovery_method": "arp",
      "hostname": "iPhone-John",
      "last_arp_timestamp": "2025-11-20T14:30:00"
    }
  }
}
```

#### Example Requests

```bash
# Get device with colon-separated MAC
curl http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF

# Get device with dash-separated MAC (automatically normalized)
curl http://localhost:5000/api/devices/AA-BB-CC-DD-EE-FF
```

---

### 3. Get Device Connections

**GET** `/api/devices/{mac_address}/connections`

Returns network connections made by a specific device.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `mac_address` | string | Device MAC address |

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Maximum connections to return (max: 1000) |
| `threat_only` | boolean | false | Only show connections with threat score > 0 |

#### Response

```json
{
  "success": true,
  "total": 156,
  "connections": [
    {
      "src_mac": "AA:BB:CC:DD:EE:FF",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "dst_port": 443,
      "protocol": "TCP",
      "timestamp": "2025-11-20T14:30:00",
      "dst_country": "US",
      "dst_org": "Cloudflare, Inc.",
      "threat_score": 0,
      "threat_categories": []
    },
    {
      "src_mac": "AA:BB:CC:DD:EE:FF",
      "src_ip": "192.168.1.100",
      "dst_ip": "192.0.2.100",
      "dst_port": 8080,
      "protocol": "TCP",
      "timestamp": "2025-11-20T14:29:45",
      "dst_country": "CN",
      "dst_org": "Unknown",
      "threat_score": 75,
      "threat_categories": ["malware", "c2"]
    }
  ]
}
```

#### Connection Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `src_mac` | string | Source device MAC address |
| `src_ip` | string | Source IP address |
| `dst_ip` | string | Destination IP address |
| `dst_port` | int | Destination port number |
| `protocol` | string | Protocol: `TCP`, `UDP`, `ICMP` |
| `timestamp` | string | ISO 8601 timestamp of connection |
| `dst_country` | string | Destination country code (ISO 3166-1 alpha-2) |
| `dst_org` | string | Destination organization/ASN name |
| `threat_score` | int | Threat score (0-100, 0 = benign, 100 = critical) |
| `threat_categories` | array | List of threat categories if threat_score > 0 |

#### Example Requests

```bash
# Get all connections for device
curl http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/connections

# Get only threat connections
curl "http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/connections?threat_only=true"

# Get last 500 connections
curl "http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/connections?limit=500"
```

---

### 4. Get Device Events

**GET** `/api/devices/{mac_address}/events`

Returns audit trail events for a specific device (status changes, IP changes, etc.)

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `mac_address` | string | Device MAC address |

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Maximum events to return (max: 500) |

#### Response

```json
{
  "success": true,
  "total": 23,
  "events": [
    {
      "device_mac": "AA:BB:CC:DD:EE:FF",
      "event_type": "status_changed",
      "old_value": "idle",
      "new_value": "active",
      "timestamp": "2025-11-20T14:30:00",
      "metadata": {
        "trigger": "connection_detected"
      }
    },
    {
      "device_mac": "AA:BB:CC:DD:EE:FF",
      "event_type": "ip_changed",
      "old_value": "192.168.1.99",
      "new_value": "192.168.1.100",
      "timestamp": "2025-11-20T12:15:30",
      "metadata": {
        "dhcp_renewal": true
      }
    },
    {
      "device_mac": "AA:BB:CC:DD:EE:FF",
      "event_type": "discovered",
      "old_value": null,
      "new_value": "192.168.1.100",
      "timestamp": "2025-11-20T10:00:00",
      "metadata": {
        "discovery_method": "arp"
      }
    }
  ]
}
```

#### Event Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `device_mac` | string | Device MAC address |
| `event_type` | string | Event type: `discovered`, `status_changed`, `ip_changed`, `offline`, `active`, `idle` |
| `old_value` | string/null | Previous value (null for discovery events) |
| `new_value` | string | New value |
| `timestamp` | string | ISO 8601 timestamp of event |
| `metadata` | object | Additional event information |

#### Example Requests

```bash
# Get device events
curl http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/events

# Get last 100 events
curl "http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/events?limit=100"
```

---

### 5. Get Device Statistics

**GET** `/api/devices/stats`

Returns aggregate statistics about all discovered devices.

#### Query Parameters

None

#### Response

```json
{
  "success": true,
  "total_devices": 42,
  "by_status": {
    "active": 28,
    "idle": 8,
    "offline": 5,
    "discovered": 1
  },
  "top_vendors": {
    "Apple, Inc.": 12,
    "Samsung Electronics": 8,
    "Dell Inc.": 6,
    "Hewlett Packard": 5,
    "Google, Inc.": 4,
    "Amazon Technologies": 3,
    "Microsoft Corporation": 2,
    "Cisco Systems": 1,
    "Intel Corporate": 1
  },
  "total_vendors": 15
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `total_devices` | int | Total number of discovered devices |
| `by_status` | object | Device count breakdown by status |
| `by_status.active` | int | Devices currently active |
| `by_status.idle` | int | Devices idle (no recent activity) |
| `by_status.offline` | int | Devices offline (not seen recently) |
| `by_status.discovered` | int | Newly discovered devices |
| `top_vendors` | object | Top 10 vendors by device count |
| `total_vendors` | int | Total number of unique vendors |

#### Example Request

```bash
# Get device statistics
curl http://localhost:5000/api/devices/stats
```

---

## Response Format

### Success Response

All successful API responses follow this format:

```json
{
  "success": true,
  "data_field": { ... }
}
```

### Error Response

All error responses follow this format:

```json
{
  "success": false,
  "error": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Request successful |
| 404 | Not Found | Device/resource not found |
| 500 | Internal Server Error | Server error occurred |

---

## Error Handling

### Common Errors

#### Device Not Found (404)

```json
{
  "success": false,
  "error": "Device not found"
}
```

**Causes**:
- MAC address doesn't exist in database
- Incorrect MAC address format

**Solution**: Verify MAC address is correct and device has been discovered

#### Server Error (500)

```json
{
  "success": false,
  "error": "Database connection failed"
}
```

**Causes**:
- Database unavailable
- Internal server error
- Data corruption

**Solution**: Check server logs, verify database connection

---

## Examples

### Python Example

```python
import requests

# Base URL
BASE_URL = "http://localhost:5000/api"

# Get all active devices
response = requests.get(f"{BASE_URL}/devices", params={"status": "active"})
if response.json()["success"]:
    devices = response.json()["devices"]
    for device in devices:
        print(f"{device['mac_address']} - {device['vendor']} - {device['ip_address']}")

# Get specific device details
mac = "AA:BB:CC:DD:EE:FF"
response = requests.get(f"{BASE_URL}/devices/{mac}")
device = response.json()["device"]
print(f"Device: {device['vendor']} ({device['status']})")

# Get device connections
response = requests.get(f"{BASE_URL}/devices/{mac}/connections", params={"limit": 10})
connections = response.json()["connections"]
for conn in connections:
    print(f"  → {conn['dst_ip']}:{conn['dst_port']} (threat: {conn['threat_score']})")

# Get statistics
response = requests.get(f"{BASE_URL}/devices/stats")
stats = response.json()
print(f"Total devices: {stats['total_devices']}")
print(f"Active: {stats['by_status']['active']}")
```

### JavaScript Example

```javascript
// Base URL
const BASE_URL = "http://localhost:5000/api";

// Get all devices
fetch(`${BASE_URL}/devices`)
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      data.devices.forEach(device => {
        console.log(`${device.mac_address} - ${device.vendor}`);
      });
    }
  });

// Get device with threat connections
const mac = "AA:BB:CC:DD:EE:FF";
fetch(`${BASE_URL}/devices/${mac}/connections?threat_only=true`)
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log(`Threats found: ${data.total}`);
      data.connections.forEach(conn => {
        console.log(`  ${conn.dst_ip} - Score: ${conn.threat_score}`);
      });
    }
  });

// Get statistics
fetch(`${BASE_URL}/devices/stats`)
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log(`Total: ${data.total_devices}`);
      console.log(`Active: ${data.by_status.active}`);
    }
  });
```

### cURL Examples

```bash
# Get all devices with pagination
curl "http://localhost:5000/api/devices?page=1&per_page=20"

# Search for iPhone devices
curl "http://localhost:5000/api/devices?search=iphone"

# Get Apple devices that are active
curl "http://localhost:5000/api/devices?vendor=apple&status=active"

# Get device details
curl http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF

# Get threat connections for device
curl "http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/connections?threat_only=true"

# Get device events
curl http://localhost:5000/api/devices/AA:BB:CC:DD:EE:FF/events

# Get system statistics
curl http://localhost:5000/api/devices/stats

# Pretty print JSON (with jq)
curl -s http://localhost:5000/api/devices/stats | jq .
```

---

## Rate Limiting

**Phase 0**: No rate limiting implemented

**Future Phases**: Rate limiting will be added based on:
- IP address
- API key (when authentication is added)
- Typical limit: 100 requests/minute per client

---

## Authentication

**Phase 0**: No authentication required (single-user mode)

**Future Phases**: Authentication will be added:
- API keys
- JWT tokens
- Role-based access control (RBAC)

---

## WebSocket Events

In addition to REST API, real-time updates are available via WebSocket (Socket.IO):

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `device_discovered` | Server → Client | New device discovered |
| `device_updated` | Server → Client | Device information updated |
| `device_status_changed` | Server → Client | Device status changed |
| `connection_added` | Server → Client | New connection detected |
| `device_count_update` | Server → Client | Total device count changed |

See Dashboard documentation for WebSocket integration details.

---

## Additional Resources

- **Dashboard UI**: http://localhost:5000
- **Device List**: http://localhost:5000/devices
- **Health Check**: http://localhost:5000/health
- **Source Code**: `src/services/api/devices.py`

---

**API Version**: 1.0.0 (Phase 0)
**Last Updated**: 2025-11-20
