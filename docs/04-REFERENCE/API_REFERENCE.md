# CobaltGraph API Reference

**Last Updated**: November 11, 2025

## Dashboard Endpoints

### Web Dashboard
```
GET /
```

**Description**: Serves the web dashboard HTML interface

**Response**: HTML page with interactive map and connection table

**Example**:
```bash
# Open in browser
http://localhost:8080/

# Or with curl
curl http://localhost:8080/
```

---

### Connection Data API
```
GET /api/data
```

**Description**: Returns real-time connection data with geo enrichment and threat intelligence

**Response Format**: JSON
```json
{
  "timestamp": 1762892718.45,
  "connections": [
    {
      "id": null,
      "timestamp": 1762892519.53,
      "src_mac": "",
      "src_ip": "172.22.158.173",
      "dst_ip": "160.79.104.10",
      "dst_port": 443,
      "dst_country": "United States",
      "dst_lat": 37.7901,
      "dst_lon": -122.401,
      "dst_org": "Anthropic, PBC",
      "dst_hostname": null,
      "threat_score": 0.2,
      "device_vendor": null,
      "protocol": "TCP",
      "threat_details": "{...}",
      "process": "claude",
      "metadata": "{...}"
    }
  ],
  "system_health": {
    "database": {"health": 100, "last_beat": 1762892718},
    "geo_engine": {"health": 100, "last_beat": 1762892718},
    "dashboard": {"health": 100, "last_beat": 1762892718}
  },
  "metrics": {
    "total_connections": 20,
    "buffer_size": 20,
    "uptime_seconds": 198,
    "mode": "device"
  }
}
```

**Example**:
```bash
# Get connection data
curl http://localhost:8080/api/data | jq .

# Get just connection count
curl -s http://localhost:8080/api/data | jq '.connections | length'

# Get latest connection
curl -s http://localhost:8080/api/data | jq '.connections[0]'
```

---

### Health Check API
```
GET /api/health
```

**Description**: Simple health check endpoint for monitoring

**Response Format**: JSON
```json
{
  "status": "OK"
}
```

**Example**:
```bash
curl http://localhost:8080/api/health
```

**Use Cases**:
- Monitoring scripts
- Load balancer health checks
- Uptime monitoring
- CI/CD health verification

---

## Connection Data Fields

### Core Fields
| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | float | Unix timestamp of connection |
| `src_ip` | string | Source IP address |
| `src_mac` | string | Source MAC address (if available) |
| `dst_ip` | string | Destination IP address |
| `dst_port` | int | Destination port |
| `protocol` | string | Protocol (TCP/UDP) |

### Geo Enrichment
| Field | Type | Description |
|-------|------|-------------|
| `dst_country` | string | Destination country |
| `dst_lat` | float | Destination latitude |
| `dst_lon` | float | Destination longitude |
| `dst_org` | string | Organization (ISP/company) |
| `dst_hostname` | string | Reverse DNS hostname (if available) |

### Threat Intelligence
| Field | Type | Description |
|-------|------|-------------|
| `threat_score` | float | 0.0-1.0 threat score |
| `threat_details` | string (JSON) | Detailed threat analysis |

### Additional Data
| Field | Type | Description |
|-------|------|-------------|
| `process` | string | Process name (if captured) |
| `metadata` | string (JSON) | Additional connection metadata |
| `device_vendor` | string | MAC vendor (if available) |

---

## API Usage Examples

### Monitor New Connections
```bash
# Poll for new connections every 5 seconds
while true; do
  curl -s http://localhost:8080/api/data | jq '.connections[0] | .dst_ip, .dst_port, .dst_country'
  sleep 5
done
```

### Export Connections to File
```bash
# Export to JSON
curl -s http://localhost:8080/api/data > connections_$(date +%s).json

# Export to CSV (requires jq)
curl -s http://localhost:8080/api/data | \
  jq -r '.connections[] | [.timestamp, .src_ip, .dst_ip, .dst_port, .dst_country, .threat_score] | @csv' \
  > connections.csv
```

### Filter High-Threat Connections
```bash
# Show connections with threat score > 0.5
curl -s http://localhost:8080/api/data | \
  jq '.connections[] | select(.threat_score > 0.5)'
```

### Monitor Specific Destination
```bash
# Watch for connections to specific IP
curl -s http://localhost:8080/api/data | \
  jq '.connections[] | select(.dst_ip == "160.79.104.10")'
```

### Count Connections by Country
```bash
# Count connections per country
curl -s http://localhost:8080/api/data | \
  jq -r '.connections[].dst_country' | sort | uniq -c | sort -rn
```

---

## Error Responses

### 404 Not Found
```
Path not recognized
```

**Valid paths**:
- `/` - Dashboard
- `/api/data` - Connection data
- `/api/health` - Health check

**Common mistakes**:
- ❌ `/api/connections` (use `/api/data` instead)
- ❌ `/api` (incomplete path)
- ❌ `/dashboard` (use `/` instead)

### 401 Unauthorized
```
Authentication required
```

**Cause**: HTTP Basic Auth is enabled in config

**Solution**: Add credentials to request:
```bash
curl -u username:password http://localhost:8080/api/data
```

---

## Authentication (Optional)

Enable authentication in `config/server.yaml`:
```yaml
enable_auth: true
auth_username: admin
auth_password: your_secure_password_here
```

**Access with auth**:
```bash
# Using curl
curl -u admin:password http://localhost:8080/api/data

# Using browser
# Will prompt for username/password
```

---

## Programmatic Access

### Python Example
```python
import requests
import json

# Get connection data
response = requests.get('http://localhost:8080/api/data')
data = response.json()

# Process connections
for conn in data['connections']:
    print(f"{conn['src_ip']} → {conn['dst_ip']}:{conn['dst_port']}")
    print(f"  Country: {conn['dst_country']}")
    print(f"  Threat: {conn['threat_score']}")
```

### JavaScript Example
```javascript
// Fetch connection data
fetch('http://localhost:8080/api/data')
  .then(response => response.json())
  .then(data => {
    console.log(`Total connections: ${data.connections.length}`);
    data.connections.forEach(conn => {
      console.log(`${conn.dst_ip}:${conn.dst_port} - ${conn.dst_country}`);
    });
  });
```

### Bash Script Example
```bash
#!/bin/bash
# Monitor for suspicious connections

THRESHOLD=0.5

while true; do
  curl -s http://localhost:8080/api/data | \
    jq -r ".connections[] | select(.threat_score > $THRESHOLD) | \"⚠️ ALERT: \\(.dst_ip):\\(.dst_port) - Threat: \\(.threat_score)\""

  sleep 10
done
```

---

## Rate Limiting

**Current**: No rate limiting implemented

**Best Practice**: Poll no more than once per second to avoid excessive load

---

## CORS

**Current**: CORS headers not set

**Cross-origin requests**: Will fail from browser unless dashboard is on same origin

**Workaround**: Use server-side requests (curl, Python, etc.)

---

## Performance Notes

- **API Response Time**: < 50ms typical
- **Connection Buffer**: Last 100 connections cached in memory
- **Data Freshness**: Real-time (updated as connections occur)
- **Concurrent Requests**: Supported (thread-safe)

---

## Troubleshooting

### "Connection refused"
**Problem**: CobaltGraph not running or dashboard not started

**Solution**:
```bash
# Check if running
ps aux | grep start.py

# Start CobaltGraph
python3 start.py --mode device
```

### "Empty connections array"
**Problem**: No network activity or capture not working

**Solution**:
```bash
# Generate test traffic
curl google.com
curl github.com

# Wait a few seconds and retry
curl -s http://localhost:8080/api/data | jq '.connections | length'
```

### "404 Not Found"
**Problem**: Wrong API path

**Solution**: Use correct paths:
- ✅ `/api/data` (not `/api/connections`)
- ✅ `/api/health` (not `/health`)
- ✅ `/` (not `/dashboard`)

---

## Summary

**Available Endpoints**:
1. `GET /` - Web dashboard UI
2. `GET /api/data` - Connection data + metrics
3. `GET /api/health` - Health check

**Data Format**: JSON
**Authentication**: Optional (disabled by default)
**Update Frequency**: Real-time

For more examples, see `examples/` directory or dashboard source code.
