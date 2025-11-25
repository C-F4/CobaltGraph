# CobaltGraph - Architecture Refactor Plan
**Status**: 🔥 CRITICAL - Duplicate codebase detected
**Date**: November 10, 2025
**Goal**: Consolidate to ONE clean architecture

---

## 🚨 **PROBLEM IDENTIFIED**

### **We Have TWO Codebases:**

#### **CODEBASE A: Root Directory (Shortcuts/Quick Fix)**
```
/home/tachyon/CobaltGraph/
├── config_loader.py         (22KB) ⚠️ DUPLICATE
├── ip_reputation.py         (15KB) ⚠️ DUPLICATE
├── network_monitor.py       (18KB) ⚠️ DUPLICATE
├── cobaltgraph_minimal.py        (37KB) ⚠️ DUPLICATE (same as watchfloor.py)
└── tools/
    ├── network_capture.py   (legacy)
    ├── grey_man.py          (legacy)
    └── ultrathink.py        (Terminal UI)
```

#### **CODEBASE B: src/ Modular Architecture (Proper Design)**
```
/home/tachyon/CobaltGraph/src/
├── capture/
│   ├── network_monitor.py   (18KB) ✅ PROPER LOCATION
│   ├── legacy_raw.py        (7KB)
│   └── legacy_ss.py         (4KB)
├── core/
│   ├── config.py            (22KB) ✅ PROPER LOCATION
│   └── watchfloor.py        (37KB) ✅ PROPER LOCATION
├── intelligence/
│   └── ip_reputation.py     (15KB) ✅ PROPER LOCATION
├── api/          (EMPTY - not implemented yet)
├── dashboard/    (EMPTY - not implemented yet)
└── utils/        (EMPTY - not implemented yet)
```

### **Verification**:
```bash
# Files are IDENTICAL (0 byte diff):
diff config_loader.py src/core/config.py        # No differences
diff network_monitor.py src/capture/network_monitor.py  # No differences
diff cobaltgraph_minimal.py src/core/watchfloor.py   # Same classes/structure
```

---

## 🎯 **ROOT CAUSE**

**What happened:**
1. Created proper modular architecture in `src/`
2. For "quick start", duplicated files to root directory
3. Created `cobaltgraph_minimal.py` as monolithic script (bypasses modules)
4. Now maintaining TWO codebases - nightmare! 😱

**Result**:
- ❌ Changes must be made in TWO places
- ❌ Easy to forget to sync
- ❌ Import confusion (`from config_loader` vs `from src.core.config`)
- ❌ No clear "source of truth"

---

## 💡 **PROPOSED SOLUTION**

### **ONE CODEBASE - Modular Architecture**

Use `src/` as the ONLY source of truth. Delete root duplicates.

---

## 🏗️ **NEW ARCHITECTURE**

### **Directory Structure:**
```
/home/tachyon/CobaltGraph/
│
├── start.py                 ✅ NEW - Cross-platform launcher
├── start.sh                 ✅ NEW - Interactive bash launcher
│
├── src/                     ✅ ONLY CODEBASE
│   ├── __init__.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── network_monitor.py   (Network-wide capture)
│   │   ├── device_capture.py    (Device-only fallback)
│   │   └── packet_parser.py     (Packet parsing utilities)
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py            (Configuration management)
│   │   ├── watchfloor.py        (Main orchestrator)
│   │   └── supervisor.py        (Auto-restart logic)
│   │
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── ip_reputation.py     (Threat intel APIs)
│   │   └── geo_enrichment.py    (Geolocation logic)
│   │
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── web_server.py        (HTTP server)
│   │   ├── api_endpoints.py     (REST API)
│   │   ├── templates.py         (HTML generation)
│   │   └── terminal_ui.py       (Optional: ncurses UI)
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py          (SQLite operations)
│   │   └── models.py            (Data models)
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logging.py           (Logging utilities)
│       └── platform.py          (Platform detection)
│
├── config/                  ✅ Configuration files
│   ├── cobaltgraph.conf
│   ├── auth.conf
│   └── threat_intel.conf
│
├── data/                    ✅ Runtime data (gitignored)
│   ├── cobaltgraph.db
│   └── cache/
│
├── logs/                    ✅ Log files
│
├── templates/               ✅ HTML templates
│   └── dashboard.html
│
└── docs/                    ✅ Documentation
    └── ...
```

### **FILES TO DELETE** ❌
```
config_loader.py         → Use src/core/config.py
ip_reputation.py         → Use src/intelligence/ip_reputation.py
network_monitor.py       → Use src/capture/network_monitor.py
cobaltgraph_minimal.py        → Use src/core/watchfloor.py

bin/cobaltgraph               → Replaced by start.sh
bin/cobaltgraph.py            → Replaced by start.py
bin/cobaltgraph.bat           → Replaced by start.py
cobaltgraph.py (symlink)      → Replaced by start.py
cobaltgraph.bat (symlink)     → Replaced by start.py
cobaltgraph_startup.sh        → Replaced by start.sh
start_supervised.sh      → Merged into start.py/start.sh
cobaltgraph_supervisor.sh     → Moved to src/core/supervisor.py

tools/network_capture.py → Legacy (archive or delete)
tools/grey_man.py        → Legacy (archive or delete)
tools/wsl_recon.py       → Legacy (archive or delete)
```

---

## 📋 **CRITICAL DESIGN QUESTIONS**

Before I implement, I need your input on these architectural decisions:

### **Q1: Dashboard Implementation**

Currently `cobaltgraph_minimal.py` has dashboard code embedded. Should we:

**A) Keep embedded** (easier, all-in-one)
```python
# In src/core/watchfloor.py:
class SUARONWatchfloor:
    def start_dashboard(self):
        # Dashboard code here
```

**B) Separate module** (cleaner, modular)
```python
# In src/dashboard/web_server.py:
from src.dashboard import DashboardServer
dashboard = DashboardServer(watchfloor)
dashboard.start()
```

**Which do you prefer?**

---

### **Q2: Entry Point Design**

How should `start.py` work?

**A) Direct execution** (simple)
```python
# start.py
from src.core.watchfloor import SUARONWatchfloor
watchfloor = SUARONWatchfloor()
watchfloor.start()
```

**B) CLI framework** (flexible, professional)
```python
# start.py
import argparse
from src.core.launcher import Launcher

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['device', 'network'])
    parser.add_argument('--no-dashboard', action='store_true')
    args = parser.parse_args()

    launcher = Launcher(args)
    launcher.start()
```

**Which approach?**

---

### **Q3: Configuration Loading**

**A) Lazy loading** (load when needed)
```python
from src.core.config import get_config
config = get_config()  # Loads on first call
```

**B) Explicit loading** (control when it loads)
```python
from src.core.config import Config
config = Config('/path/to/config')
config.load()
```

**Which style?**

---

### **Q4: Import Style**

**A) Absolute imports** (explicit, verbose)
```python
from src.core.config import Config
from src.intelligence.ip_reputation import IPReputationManager
```

**B) Relative imports** (shorter, less clear)
```python
from core.config import Config
from intelligence.ip_reputation import IPReputationManager
```

**C) Package imports** (cleanest)
```python
import cobaltgraph
config = cobaltgraph.config.load()
reputation = cobaltgraph.intelligence.IPReputationManager()
```

**Which import style?**

---

### **Q5: Terminal UI Integration**

Since Terminal UI is experimental, should we:

**A) Integrated** (part of main dashboard module)
```python
# src/dashboard/__init__.py
from src.dashboard.web_server import WebDashboard
from src.dashboard.terminal_ui import TerminalUI  # Optional
```

**B) Separate module** (completely isolated)
```python
# src/terminal/ (separate top-level module)
from src.terminal.ultrathink import UltraThink
```

**C) Plugin system** (most flexible)
```python
# UI plugins can be loaded dynamically
watchfloor.load_ui_plugin('web')  # or 'terminal'
```

**Which approach for Terminal UI?**

---

### **Q6: Supervisor / Auto-Restart**

**A) Built-in** (part of main launcher)
```python
# start.py --supervised
if args.supervised:
    supervisor = Supervisor(watchfloor)
    supervisor.start()  # Auto-restarts on crash
```

**B) Separate wrapper** (external script)
```bash
# supervisor.py wraps start.py
while true; do
    python start.py || sleep 5
done
```

**C) Systemd/OS-level** (rely on OS)
```bash
# Let systemd handle restarts
sudo systemctl restart cobaltgraph
```

**Which supervision model?**

---

### **Q7: Capture Pipeline**

Currently pipeline is:
```bash
network_monitor.py (STDOUT) → cobaltgraph_minimal.py (STDIN)
```

Should we:

**A) Keep pipe architecture** (Unix philosophy)
```bash
python -m src.capture.network_monitor | python start.py
```

**B) Internal threading** (single process)
```python
# In watchfloor.py:
capture_thread = CaptureThread()
capture_thread.start()
# Data flows via Queue
```

**C) Hybrid** (pipe optional, threading default)
```python
# Can work both ways:
watchfloor.start(stdin_mode=True)   # Read from pipe
watchfloor.start(stdin_mode=False)  # Internal threads
```

**Which data flow model?**

---

### **Q8: Database Layer**

Currently database is embedded in `cobaltgraph_minimal.py`. Should we:

**A) Keep embedded** (simple, all-in-one)
```python
class SUARONWatchfloor:
    def __init__(self):
        self.db = sqlite3.connect('cobaltgraph.db')
```

**B) Separate storage module** (cleaner)
```python
from src.storage.database import Database
db = Database('cobaltgraph.db')
```

**C) ORM-style** (most abstraction)
```python
from src.storage.models import Connection, Device
Connection.create(src_ip='1.2.3.4', ...)
```

**Which database approach?**

---

### **Q9: Error Handling Strategy**

**A) Let it crash** (simple, supervisor restarts)
```python
# Minimal try/except, let exceptions bubble up
watchfloor.start()  # Crashes on error
```

**B) Graceful degradation** (keep running with reduced features)
```python
try:
    threat_intel = IPReputationManager()
except Exception as e:
    logger.warning("Threat intel unavailable, continuing without it")
    threat_intel = None
```

**C) Comprehensive error handling** (catch everything)
```python
try:
    watchfloor.start()
except Exception as e:
    logger.error(f"Fatal error: {e}")
    send_alert()
    cleanup()
    sys.exit(1)
```

**Which error handling philosophy?**

---

### **Q10: Testing Strategy**

Do you want:

**A) No tests** (move fast, test manually)
```
No tests/ directory
```

**B) Basic tests** (critical paths only)
```
tests/
├── test_config.py
├── test_capture.py
└── test_database.py
```

**C) Comprehensive tests** (full coverage)
```
tests/
├── unit/
├── integration/
└── e2e/
```

**Testing preference?**

---

## 🎯 **YOUR ANSWERS NEEDED**

Please answer Q1-Q10 (just the letter: A, B, or C):

1. Dashboard: **[A/B]**
2. Entry point: **[A/B]**
3. Config loading: **[A/B]**
4. Import style: **[A/B/C]**
5. Terminal UI: **[A/B/C]**
6. Supervisor: **[A/B/C]**
7. Capture pipeline: **[A/B/C]**
8. Database: **[A/B/C]**
9. Error handling: **[A/B/C]**
10. Testing: **[A/B/C]**

**Once you answer, I'll build the PERFECT architecture! 🚀**
