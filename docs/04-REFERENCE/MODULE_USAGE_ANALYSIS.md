# CobaltGraph - Module Usage Analysis

**Current Status**: Using 10 of 25 available modules (40%)

---

## ✅ **CURRENTLY USING** (10 modules)

### **Core** (3/5)
- ✅ `src/core/orchestrator.py` - Main system coordinator
- ✅ `src/core/launcher.py` - CLI entry point
- ✅ `src/core/config.py` - Configuration loader
- ❌ `src/core/supervisor.py` - Auto-restart (NOT INTEGRATED)
- ❌ `src/core/watchfloor.py` - Old minimal system (REPLACED by orchestrator)

### **Storage** (1/3)
- ✅ `src/storage/database.py` - SQLite operations
- ❌ `src/storage/models.py` - Data models (NOT USING)
- ❌ `src/storage/migrations.py` - Schema migrations (NOT NEEDED YET)

### **Intelligence** (2/2)
- ✅ `src/intelligence/geo_enrichment.py` - IP geolocation
- ✅ `src/intelligence/ip_reputation.py` - Threat intel

### **Dashboard** (1/4)
- ✅ `src/dashboard/server.py` - HTTP server + API
- ❌ `src/dashboard/api.py` - API helpers (STUB/TODO)
- ❌ `src/dashboard/handlers.py` - Request handlers (UNCLEAR PURPOSE)
- ❌ `src/dashboard/templates.py` - HTML helpers (NOT USED)

### **Utils** (2/5)
- ✅ `src/utils/heartbeat.py` - Health monitoring
- ✅ `src/utils/errors.py` - Custom exceptions
- ❌ `src/utils/platform.py` - Platform detection (SHOULD USE)
- ❌ `src/utils/logging.py` - Logging helpers (NOT USING)
- ❌ `src/utils/logging_config.py` - Logging setup (NOT USING)

### **Tools** (2/5)
- ✅ `tools/grey_man.py` - Raw packet capture (network mode)
- ✅ `tools/network_capture.py` - ss-based capture (device mode)
- ❌ `tools/neural_client.py` - ML anomaly detection (NOT INTEGRATED)
- ❌ `tools/wsl_recon.py` - WSL-specific recon (NOT INTEGRATED)
- ❌ `tools/ultrathink_modified.py` - Terminal UI (NOT INTEGRATED)

### **Capture** (0/5)
- ❌ `src/capture/network_monitor.py` - Network capture (AVAILABLE AS FALLBACK)
- ❌ `src/capture/device_monitor.py` - Device capture (STUB ONLY)
- ❌ `src/capture/packet_parser.py` - Parsing utilities (NOT NEEDED)
- ❌ `src/capture/legacy_raw.py` - Legacy capture (DEPRECATED)
- ❌ `src/capture/legacy_ss.py` - Legacy ss capture (DEPRECATED)

### **Terminal** (0/1)
- ❌ `src/terminal/ultrathink.py` - Terminal UI (NOT INTEGRATED)

---

## 🎯 **SHOULD INTEGRATE** (High Priority)

### **1. Platform Detection** (`src/utils/platform.py`)
**Why**: Better OS detection, WSL detection, capability checks

**Current**: Using `platform.system()` directly in orchestrator
**Better**: Use centralized platform detection module

**Integration**:
```python
# Instead of:
os_name = platform.system().lower()

# Use:
from src.utils.platform import get_platform_info
info = get_platform_info()
# Returns: os, is_wsl, is_root, has_raw_sockets, etc.
```

**Value**: ⭐⭐⭐⭐⭐ (Essential for proper cross-platform support)

---

### **2. Data Models** (`src/storage/models.py`)
**Why**: Structured data classes for connections and devices

**Current**: Using plain dicts everywhere
**Better**: Typed dataclasses with validation

**Integration**:
```python
from src.storage.models import Connection

# Instead of:
connection = {
    'src_ip': '1.2.3.4',
    'dst_ip': '5.6.7.8',
    # ...
}

# Use:
connection = Connection(
    src_ip='1.2.3.4',
    dst_ip='5.6.7.8',
    # Type checking and validation!
)
```

**Value**: ⭐⭐⭐⭐ (Better code quality, easier refactoring)

---

### **3. WSL Recon** (`tools/wsl_recon.py`)
**Why**: Leverage Windows tools from WSL (Wireshark, Nmap)

**Current**: Basic capture only
**Better**: Can use Windows network tools for enhanced capture

**Integration**:
```python
from tools.wsl_recon import WSLRecon

if is_wsl():
    wsl_recon = WSLRecon()
    if wsl_recon.wireshark_path:
        # Use Windows Wireshark from WSL!
        wsl_recon.start_wireshark_capture()
```

**Value**: ⭐⭐⭐ (Useful for WSL users, not critical)

---

### **4. Supervisor** (`src/core/supervisor.py`)
**Why**: Auto-restart on crashes

**Current**: Manual restart required
**Better**: Automatic recovery

**Integration**:
```python
# Already has --supervised flag, just needs wiring
from src.core.supervisor import Supervisor
supervisor = Supervisor(orchestrator)
supervisor.start()  # Auto-restarts on crash
```

**Value**: ⭐⭐⭐⭐ (Production stability)

---

## 🔬 **OPTIONAL INTEGRATION** (Advanced Features)

### **5. Neural Client** (`tools/neural_client.py`)
**Why**: ML-based anomaly detection

**Requirements**:
- Rust toolchain
- Compiled neural engine binary
- Unix domain socket communication

**Integration**:
```python
from tools.neural_client import NeuralClient

neural = NeuralClient()
neural.start_neural_engine()
anomaly_score = neural.check_connection(connection_data)
```

**Value**: ⭐⭐⭐⭐⭐ (Advanced threat detection, but complex setup)

---

### **6. Terminal UI** (`tools/ultrathink_modified.py`, `src/terminal/ultrathink.py`)
**Why**: Alternative to web dashboard (ncurses-based)

**Integration**:
```python
# As alternative interface
if args.interface == 'terminal':
    from src.terminal.ultrathink import UltraThink
    ui = UltraThink(orchestrator)
    ui.run()
```

**Value**: ⭐⭐⭐ (Nice-to-have, web dashboard is primary)

---

## ❌ **NOT NEEDED** (Skip These)

### **Deprecated/Legacy**
- `src/capture/legacy_raw.py` - Old implementation
- `src/capture/legacy_ss.py` - Old implementation
- `src/core/watchfloor.py` - Replaced by orchestrator (keep for reference)

### **Stubs/Incomplete**
- `src/dashboard/api.py` - Only has TODO methods
- `src/capture/device_monitor.py` - Incomplete stub

### **Unclear Purpose**
- `src/dashboard/handlers.py` - Purpose unclear, may duplicate server.py
- `src/dashboard/templates.py` - Not used, dashboard HTML is standalone

### **Not Using Yet**
- `src/storage/migrations.py` - Database migrations (schema is stable)
- `src/utils/logging.py` - Using standard logging module
- `src/utils/logging_config.py` - Using basic logging config

---

## 📊 **USAGE SUMMARY**

| Category | Using | Available | % Used |
|----------|-------|-----------|--------|
| Core | 3 | 5 | 60% |
| Storage | 1 | 3 | 33% |
| Intelligence | 2 | 2 | 100% ✅ |
| Dashboard | 1 | 4 | 25% |
| Utils | 2 | 5 | 40% |
| Tools | 2 | 5 | 40% |
| Capture | 0 | 5 | 0% |
| Terminal | 0 | 1 | 0% |
| **TOTAL** | **10** | **25** | **40%** |

---

## 🎯 **RECOMMENDATION**

### **Immediate Priorities** (Next 2 hours)
1. ✅ Integrate `src/utils/platform.py` - Better platform detection
2. ✅ Integrate `src/storage/models.py` - Structured data
3. ✅ Integrate `src/core/supervisor.py` - Auto-restart

### **Short-term** (Next session)
4. ⏰ Integrate `tools/wsl_recon.py` - WSL enhancements
5. ⏰ Integrate `tools/neural_client.py` - ML anomaly detection (if Rust engine available)

### **Optional** (Future)
6. 🔮 Terminal UI integration
7. 🔮 API helpers refactor
8. 🔮 Database migrations

---

## 🚀 **ACTION PLAN**

Would you like me to:

**A) Integrate the 3 high-priority modules NOW** (platform.py, models.py, supervisor.py)?
   - Takes ~30 minutes
   - Significantly improves system quality
   - Better cross-platform support
   - Auto-restart capability

**B) Keep current setup** (works, but not using full potential)?
   - System is functional as-is
   - Can integrate modules later

**C) Full integration** (all 10 unused modules)?
   - Takes ~2-3 hours
   - Maximum feature set
   - Includes experimental features (neural, terminal UI)

---

## 💡 **MY RECOMMENDATION: Option A**

Integrate the 3 essential modules:
1. **platform.py** - Better OS detection
2. **models.py** - Structured data (type safety)
3. **supervisor.py** - Production stability

This gives you **90% of the value** with minimal complexity.

What do you think?
