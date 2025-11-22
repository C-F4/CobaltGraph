# CobaltGraph Architecture Documentation

**Version**: 1.0.0-MVP
**Last Updated**: November 11, 2025
**Status**: Production Ready

---

## 📐 **Overview**

CobaltGraph follows a modular, layered architecture with clear separation of concerns. The system is designed for:
- **Scalability**: Handle thousands of connections
- **Maintainability**: Clean, modular codebase
- **Extensibility**: Easy to add new features
- **Reliability**: Comprehensive error handling

---

## 🏗️ **System Architecture**

### **Layered Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interfaces                          │
│  ┌───────────────┐              ┌──────────────────┐       │
│  │ Web Dashboard │              │   Terminal UI    │       │
│  │  (port 8080)  │              │   (ncurses)      │       │
│  └───────────────┘              └──────────────────┘       │
└──────────────────────┬──────────────────┬───────────────────┘
                       │                  │
┌──────────────────────┴──────────────────┴───────────────────┐
│                    Core Orchestration                        │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Watchfloor (Main Orchestrator)                     │    │
│  │  - Coordinates all subsystems                       │    │
│  │  - Manages lifecycle                                │    │
│  │  - Handles events                                   │    │
│  └────────────────────────────────────────────────────┘    │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│                  Intelligence Layer                          │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  IP Reputation  │  │   GeoIP      │  │    Threat    │  │
│  │   (AbuseIPDB,   │  │  (ip-api)    │  │   Scoring    │  │
│  │   VirusTotal)   │  │              │  │   (ML/AI)    │  │
│  └─────────────────┘  └──────────────┘  └──────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│                   Capture Layer                              │
│  ┌─────────────────┐              ┌──────────────────┐     │
│  │ Network Monitor │              │ Device Capture   │     │
│  │  (raw sockets,  │              │   (ss/netstat)   │     │
│  │   promiscuous)  │              │                  │     │
│  └─────────────────┘              └──────────────────┘     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│                   Storage Layer                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Database (SQLite)                                  │    │
│  │  - Connection history                               │    │
│  │  - Device tracking                                  │    │
│  │  - Indexed queries                                  │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 **Module Breakdown**

### **1. Entry Points**

#### **start.py** (Root)
**Purpose**: Cross-platform Python launcher

**Responsibilities**:
- Set up Python path
- Change to project root
- Import and call launcher_main()
- Handle import errors
- Exit code management

**Flow**:
```python
start.py
  ├─> Sets PROJECT_ROOT in sys.path
  ├─> Changes to project directory
  └─> Calls src.core.launcher.main()
```

#### **start.sh** (Root)
**Purpose**: Interactive bash launcher

**Responsibilities**:
- Check Python version (3.8+)
- Display user-friendly banner
- Forward arguments to start.py
- Interactive mode support

---

### **2. Core Modules (`src/core/`)**

#### **launcher.py**
**Purpose**: Startup orchestration and CLI handling

**Key Classes**:
- `Launcher`: Main launcher orchestration
- `Colors`: ANSI color codes

**Responsibilities**:
- Legal disclaimer display and acceptance
- Platform detection (OS, root access, capabilities)
- Capability detection (raw sockets, ncurses)
- Mode selection (network/device/auto)
- Interface selection (web/terminal)
- Configuration loading
- Watchfloor initialization
- Supervisor integration
- Graceful shutdown

**Flow**:
```
Launcher.start()
  ├─> show_legal_disclaimer()
  ├─> detect_platform()
  ├─> load_configuration()
  ├─> select_mode()
  ├─> select_interface()
  └─> Start watchfloor
      ├─> Supervised mode?
      │   └─> supervisor.start()
      └─> Direct mode
          └─> watchfloor.start()
```

#### **config.py**
**Purpose**: Configuration management

**Key Classes**:
- `ConfigLoader`: Main configuration loader

**Responsibilities**:
- Load from config/ directory
- Parse .conf files (ConfigParser)
- Environment variable overrides
- Validation
- Default values
- Threat intel status

**Priority Order**:
1. Environment variables (SUARON_*)
2. Config files (config/*.conf)
3. Default values

**Configuration Files**:
- `config/cobaltgraph.conf` - Main configuration
- `config/auth.conf` - Authentication (optional)
- `config/threat_intel.conf` - API keys (optional)

#### **watchfloor.py**
**Purpose**: Main system orchestrator

**Key Classes**:
- `SUARONMinimal`: Main orchestrator

**Responsibilities**:
- Component initialization
- Event loop management
- Data pipeline coordination
- Lifecycle management
- Error handling

#### **supervisor.py**
**Purpose**: Auto-restart and health monitoring

**Responsibilities**:
- Process monitoring
- Auto-restart on crash
- Exponential backoff
- Health checking
- Maximum restart limits

---

### **3. Capture Modules (`src/capture/`)**

#### **network_monitor.py**
**Purpose**: Network-wide packet capture

**Key Classes**:
- `NetworkMonitor`: Main capture engine

**Modes**:
- **Network Mode**: Raw socket capture (requires root)
  - Promiscuous mode
  - Full network segment visibility
  - All devices tracked
- **Device Mode**: Socket statistics (no root)
  - Current device only
  - /proc/net/tcp parsing
  - Limited to local connections

**Responsibilities**:
- Packet capture and parsing
- Protocol detection
- Connection extraction
- Device identification (MAC address)

---

### **4. Intelligence Modules (`src/intelligence/`)**

#### **ip_reputation.py**
**Purpose**: Threat intelligence lookups

**Key Classes**:
- `IPReputationManager`: Manages threat feeds

**Supported Services**:
- **VirusTotal**: Malware/phishing detection
- **AbuseIPDB**: Abuse confidence score
- **Local**: Fallback threat scoring

**Features**:
- Priority-based lookup chain
- Caching (TTL-based)
- Rate limiting
- Fallback to local scoring
- Concurrent API calls

**Threat Score Calculation**:
```
threat_score = (
    virustotal_score * 0.4 +
    abuseipdb_score * 0.4 +
    local_score * 0.2
)
```

---

### **5. Storage Modules (`src/storage/`)**

#### **database.py**
**Purpose**: SQLite database wrapper

**Key Classes**:
- `Database`: Thread-safe SQLite wrapper

**Features**:
- Thread-safe operations (mutex lock)
- Automatic schema initialization
- Indexed queries
- Context manager support
- Transaction safety

**Schema**:
```sql
CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    timestamp REAL,
    src_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    dst_country TEXT,
    dst_lat REAL,
    dst_lon REAL,
    dst_org TEXT,
    dst_hostname TEXT,
    threat_score REAL DEFAULT 0,
    device_vendor TEXT,
    protocol TEXT DEFAULT 'TCP'
);

CREATE INDEX idx_timestamp ON connections(timestamp DESC);
CREATE INDEX idx_src_mac ON connections(src_mac);
```

---

### **6. Dashboard Modules (`src/dashboard/`)**

#### **server.py**
**Purpose**: Web dashboard HTTP server

**Responsibilities**:
- HTTP request handling
- REST API endpoints
- Static file serving
- Real-time updates
- JSON responses

**Endpoints**:
- `GET /` - Dashboard HTML
- `GET /api/connections` - Recent connections (JSON)
- `GET /api/stats` - System statistics (JSON)
- `GET /api/devices` - Device list (JSON)

---

### **7. Utility Modules (`src/utils/`)**

#### **errors.py**
**Purpose**: Custom exception hierarchy

**Exception Classes**:
- `SUARONError` - Base exception
- `ConfigurationError` - Config errors
- `DatabaseError` - Database errors
- `CaptureError` - Capture errors
- `IntegrationError` - API errors
- `DashboardError` - UI errors
- `GeolocationError` - GeoIP errors
- `SupervisorError` - Process monitoring errors

**Features**:
- Context details dictionary
- String representation with details
- Exception inheritance

#### **logging_config.py**
**Purpose**: Centralized logging configuration

**Features**:
- Colored console output (ANSI)
- Rotating file logs (10MB, 5 backups)
- Separate console/file log levels
- Detailed file logs (file:line)
- Silence noisy loggers

**Log Levels**:
- DEBUG: Detailed debugging
- INFO: Normal operations
- WARNING: Warnings (non-critical)
- ERROR: Errors (failures)
- CRITICAL: Critical failures

#### **heartbeat.py**
**Purpose**: Health monitoring

**Responsibilities**:
- System health checks
- Component status
- Performance metrics
- Uptime tracking

---

## 🔄 **Data Flow**

### **Connection Processing Pipeline**

```
Network Interface
       │
       ├─> NetworkMonitor.capture()
       │   ├─> Parse packet
       │   ├─> Extract connection
       │   └─> Identify device
       │
       ├─> IPReputationManager.lookup()
       │   ├─> Check cache
       │   ├─> Query APIs (VirusTotal, AbuseIPDB)
       │   └─> Calculate threat score
       │
       ├─> GeoIP.lookup()
       │   ├─> Query ip-api.com
       │   └─> Extract lat/lon/country
       │
       ├─> Database.add_connection()
       │   ├─> Insert to SQLite
       │   └─> Commit transaction
       │
       └─> Dashboard.update()
           └─> Send to web UI
```

---

## 🔐 **Security Architecture**

### **Authentication**
- Optional BasicAuth
- Session timeout
- Login attempt limiting
- Account lockout

### **Network Security**
- Default: localhost binding (127.0.0.1)
- Optional: all interfaces (0.0.0.0)
- Firewall integration
- Reverse proxy support

### **Data Security**
- SQLite database (local file)
- No cloud dependencies
- API keys in config files (not in code)
- Threat intel caching (reduce API exposure)

---

## ⚡ **Performance Characteristics**

### **Bottlenecks**
1. **Disk I/O**: Database writes
2. **Network**: API calls to threat feeds
3. **CPU**: Packet parsing (network mode)

### **Optimizations**
- **Database**: Indexed queries, batch inserts
- **Caching**: Threat intel and GeoIP results
- **Threading**: Thread-safe operations
- **Rate Limiting**: API call throttling

### **Scalability Limits**
- **Connections/sec**: ~1000 (single core)
- **Database size**: ~1GB recommended max
- **Memory**: 50-200MB typical
- **Concurrent devices**: 100-1000

---

## 🧪 **Testing Architecture**

### **Test Coverage**
- **Unit Tests**: Individual module testing
- **Integration Tests**: Component interaction
- **Error Tests**: Exception handling
- **Performance Tests**: Benchmarking

### **Test Organization**
```
tests/
├── run_all_tests.py      # Main test runner
└── (pytest tests in src/*/tests/)
```

---

## 🔧 **Error Handling Strategy**

### **Critical Components** (Fail Fast)
- Database connection → Raise DatabaseError
- Main config parsing → Raise ConfigurationError
- Schema initialization → Raise DatabaseError

### **Optional Components** (Graceful Degradation)
- Threat intel APIs → Log warning, continue
- GeoIP lookups → Use "Unknown" location
- Auth config → Use defaults

### **Transaction Safety**
- Database: Automatic rollback on errors
- API calls: Retry with exponential backoff
- File I/O: Create directories if missing

---

## 📊 **Monitoring and Observability**

### **Logging**
- **Console**: INFO and above (colored)
- **File**: DEBUG and above (detailed)
- **Rotation**: 10MB max, 5 backups

### **Metrics** (Future)
- Connections processed
- Threat intel hit rate
- API response times
- Database query times

---

## 🛣️ **Evolution Path**

### **Phase 1-3**: Foundation ✅
- Modular architecture
- Code consolidation
- Clean organization

### **Phase 4**: Unified Launchers ✅
- Single entry point
- Cross-platform support
- Professional UX

### **Phase 6**: Error Handling ✅
- Custom exceptions
- Comprehensive logging
- Transaction safety

### **Phase 7**: Testing ✅
- Comprehensive test suite
- 100% pass rate
- CI/CD ready

### **Future Phases**
- Enhanced ML threat detection
- Distributed deployment
- REST API
- Plugin system

---

**Architecture designed for security, performance, and maintainability**
