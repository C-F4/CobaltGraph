# CobaltGraph - Geo-Spatial Network Intelligence Platform

**Passive Reconnaissance & Network Intelligence Tool -- UNDER DEVELOPMENT **

CobaltGraph is a comprehensive network monitoring and intelligence platform that provides real-time visualization of network connections with geolocation data, threat intelligence scoring, and device tracking.

---

## 🚀 **Quick Start**

### **Interactive Mode (Recommended)**
```bash
# Clone repository
cd CobaltGraph

# Start CobaltGraph (interactive prompts)
./start.sh

# Or with Python
python3 start.py
```

### **Command-Line Mode**
```bash
# Network-wide monitoring (requires root)
sudo python3 start.py --mode network

# Device-only monitoring
python3 start.py --mode device

# With specific interface
python3 start.py --interface web --port 8080

# Supervised mode (auto-restart)
python3 start.py --supervised

# Skip disclaimer (for automation)
python3 start.py --no-disclaimer --mode device
```

---

## 📋 **Features**

### **✅ Geo-Intelligence**
- **Geolocation**: Automatic IP-to-location mapping
- **Country identification**: Identify connection destinations
- **Organization lookup**: Identify ASN and organization names
- **Latitude/Longitude**: Precise geographic coordinates

### **✅ Threat Intelligence**
- **IP Reputation**: AbuseIPDB and VirusTotal integration
- **Threat Scoring**: AI-powered threat assessment
- **Local Scoring**: Fallback to local threat indicators
- **Configurable Sources**: Priority-based threat feed chain

### **✅ Dashboards**
- **Web Dashboard**: Interactive web interface (http://localhost:8080)
- **Terminal UI**: ncurses-based terminal interface (experimental)
- **Real-time Updates**: Live connection feed
- **Export Capabilities**: CSV and JSON export

---

## 🏗️ **Architecture**

CobaltGraph follows a modular architecture with clear separation of concerns:

```
CobaltGraph/
├── start.py                    # Cross-platform entry point
├── start.sh                    # Interactive bash launcher
│
├── src/                        # Core source code
│   ├── capture/                # Network capture modules
│   │   ├── network_monitor.py # Main capture engine
│   │   ├── device_capture.py  # Device-only fallback
│   │   └── packet_parser.py   # Packet parsing utilities
│   │
│   ├── core/                   # Core system modules
│   │   ├── config.py          # Configuration management
│   │   ├── launcher.py        # Startup orchestration
│   │   ├── watchfloor.py      # Main system orchestrator
│   │   └── supervisor.py      # Auto-restart logic
│   │
│   ├── intelligence/           # Threat intelligence
│   │   ├── ip_reputation.py   # IP reputation lookups
│   │   └── threat_scoring.py  # Threat assessment
│   │
│   ├── storage/                # Data storage
│   │   └── database.py        # SQLite database wrapper
│   │
│   ├── dashboard/              # User interfaces
│   │   └── server.py          # Web dashboard server
│   │
│   └── utils/                  # Utilities
│       ├── errors.py          # Custom exceptions
│       ├── logging_config.py  # Logging setup
│       └── heartbeat.py       # Health monitoring
│
├── config/                     # Configuration files
│   ├── cobaltgraph.conf            # Main configuration
│   ├── threat_intel.conf      # API keys and settings
│   └── auth.conf              # Authentication
│
├── data/                       # Database storage
├── logs/                       # Log files
├── exports/                    # Exported data
└── tests/                      # Test suite
    └── run_all_tests.py       # Comprehensive tests
```

---

## ⚙️ **Installation**

### **Requirements**
- Python 3.8+
- Linux, macOS, WSL2, or Windows
- Root/sudo access (for network-wide monitoring)

### **Dependencies**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Or manually:
pip install sqlite3  # (built-in with Python)
```

### **Configuration**
```bash
# 1. Copy example configs
cp config/cobaltgraph.conf.example config/cobaltgraph.conf
cp config/threat_intel.conf.example config/threat_intel.conf

# 2. Edit configuration
nano config/cobaltgraph.conf

# 3. Add API keys (optional)
nano config/threat_intel.conf
```

---

## 🔧 **Configuration**

### **Main Configuration (`config/cobaltgraph.conf`)**

```ini
[General]
system_name = CobaltGraph
log_level = INFO
max_database_size_mb = 1000
retention_days = 30

[Network]
monitor_mode = auto          # auto, device, network
capture_interface =          # Leave empty for auto-detect
buffer_size = 100
enable_device_tracking = true

[Dashboard]
web_port = 8080
web_host = 127.0.0.1        # 0.0.0.0 for all interfaces
enable_auth = false
refresh_interval = 5

[ThreatScoring]
enable_ip_reputation = true
enable_ml_detection = true
alert_threshold = 0.7
```

### **Threat Intelligence (`config/threat_intel.conf`)**

```ini
[VirusTotal]
enabled = true
api_key = YOUR_API_KEY_HERE
cache_ttl = 86400

[AbuseIPDB]
enabled = true
api_key = YOUR_API_KEY_HERE
cache_ttl = 86400

[ThreatFeed]
priority = virustotal,abuseipdb,local
fallback_to_local = true
```

---

## 📖 **Usage Examples**

### **Basic Usage**
```bash
# Interactive mode (asks questions)
./start.sh

# Network monitoring (requires sudo)
sudo python3 start.py --mode network

# Device-only mode (no sudo needed)
python3 start.py --mode device
```

### **Advanced Usage**
```bash
# Custom port
python3 start.py --port 9000

# Terminal UI (experimental)
python3 start.py --interface terminal

# Supervised mode (auto-restart on crash)
python3 start.py --supervised

# Show version
python3 start.py --version

# Show help
python3 start.py --help
```

### **Automation**
```bash
# Headless operation (skip disclaimer)
python3 start.py --no-disclaimer --mode device --interface web

# Run as systemd service
sudo cp cobaltgraph.service /etc/systemd/system/
sudo systemctl enable cobaltgraph
sudo systemctl start cobaltgraph
```

---

## 🧪 **Testing**

### **Run Test Suite**
```bash
# Run all tests
python3 tests/run_all_tests.py

# Expected output:
# ✅ PASSED: 22/22 tests
```

### **Test Coverage**
- Error handling (4 tests)
- Logging configuration (4 tests)
- Database operations (5 tests)
- Configuration loading (4 tests)
- Launcher functionality (5 tests)

---

## 🛡️ **Security**

### **Legal Disclaimer**
⚠️ **IMPORTANT**: CobaltGraph is designed for AUTHORIZED network monitoring ONLY.

You may ONLY use CobaltGraph to monitor networks where you have:
- Explicit written authorization from the network owner
- Legal ownership of the network
- Proper consent from all parties being monitored

**Unauthorized network monitoring may violate**:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar laws in other jurisdictions

### **Authentication**
```ini
# Enable authentication in config/auth.conf
[BasicAuth]
username = admin
password = changeme  # CHANGE THIS!
session_timeout = 60
max_login_attempts = 5
```

### **Network Security**
- Default: Dashboard binds to `127.0.0.1` (localhost only)
- For remote access: Set `web_host = 0.0.0.0` and enable authentication
- Use firewall rules to restrict access
- Consider running behind nginx/Apache reverse proxy
---

## 🐛 **Troubleshooting**

### **"Port 8080 already in use"**
```bash
# Use custom port
python3 start.py --port 9000

# Or kill existing process
lsof -ti:8080 | xargs kill
```

### **Database errors**
```bash
# Reset database
rm data/cobaltgraph.db

# Restart CobaltGraph (will recreate)
python3 start.py
```

---

## 📊 **Performance**

### **System Requirements**
- **CPU**: 1+ cores (2+ recommended)
- **RAM**: 512MB minimum (1GB+ recommended)
- **Disk**: 100MB+ for installation, varies by usage
- **Network**: Any standard network interface

### **Benchmarks**
- **Connection Processing**: ~1000 connections/second
- **Database Write**: ~500 inserts/second
- **Memory Usage**: 50-200MB (depending on buffer size)
- **CPU Usage**: 5-15% (single core)

---


## 📝 **License**

MIT License - See LICENSE file for details

---

## 🙏 **Acknowledgments**

- **Threat Intelligence**: AbuseIPDB, VirusTotal
- **Geolocation**: ip-api.com
- **Mapping**: Leaflet.js
- **Icon**: CobaltGraph logo

---
