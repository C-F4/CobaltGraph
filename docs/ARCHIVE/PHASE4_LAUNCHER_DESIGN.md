# PHASE 4: UNIFIED LAUNCHER DESIGN

## 📊 **CURRENT STATE ANALYSIS**

### Existing Launchers (7 files):
1. **bin/cobaltgraph** (14K) - Bash script with legal disclaimer, interactive prompts
2. **bin/cobaltgraph.py** (2.1K) - Python wrapper calling bin/cobaltgraph
3. **bin/cobaltgraph.bat** (328B) - Windows batch file
4. **start.sh** (2.1K) - Simple pipeline launcher
5. **start_supervised.sh** (1.3K) - Supervisor wrapper
6. **cobaltgraph_startup.sh** (14K) - Another startup variant
7. **cobaltgraph_supervisor.sh** (4.3K) - Supervisor implementation

**Problems:**
- ❌ Too many entry points (7 files!)
- ❌ Duplicated functionality
- ❌ Inconsistent behavior
- ❌ Hard to maintain
- ❌ Confusing for users

---

## 🎯 **UNIFIED LAUNCHER GOALS**

### Target: 2 Simple Entry Points

1. **start.py** - Cross-platform Python launcher (CLI + Interactive)
2. **start.sh** - Bash launcher (for Unix power users)

---

## 🏗️ **ARCHITECTURE DESIGN**

### **Component 1: src/core/launcher.py**
Main launcher logic - orchestrates startup

**Responsibilities:**
- Legal disclaimer display
- Platform detection (Windows/WSL/Linux/macOS)
- Capability detection (root/admin, raw sockets)
- Configuration loading
- Mode selection (network/device/auto)
- Interface selection (web/terminal)
- Start watchfloor with appropriate settings
- Supervisor integration

**Class Structure:**
```python
class Launcher:
    def __init__(self, config_path=None, args=None)
    def show_legal_disclaimer(self) -> bool
    def detect_platform(self) -> Dict
    def detect_capabilities(self) -> Dict
    def select_mode(self, requested=None) -> str
    def select_interface(self, requested=None) -> str
    def start(self)
```

### **Component 2: src/core/supervisor.py**
Auto-restart logic (already exists as placeholder)

**Responsibilities:**
- Watch watchfloor process
- Auto-restart on crash
- Exponential backoff
- Maximum restart attempts
- Health checking

### **Component 3: start.py** (root)
User-facing entry point - thin CLI wrapper

**Features:**
- Argparse CLI interface
- Interactive mode (no args)
- Non-interactive mode (with flags)
- Cross-platform (Windows, WSL, Linux, macOS)

**Usage:**
```bash
# Interactive (asks questions):
python start.py

# CLI flags:
python start.py --mode network --interface web
python start.py --mode device --interface terminal
python start.py --supervised
python start.py --health
```

### **Component 4: start.sh** (root)
Bash launcher for Unix users

**Features:**
- Interactive prompts (like current bin/cobaltgraph)
- Legal disclaimer
- Colorful output
- Platform detection
- Calls start.py internally

---

## 📋 **IMPLEMENTATION PLAN**

### Step 1: Implement src/core/launcher.py ✅
- [ ] Create Launcher class
- [ ] Implement legal disclaimer
- [ ] Implement platform detection
- [ ] Implement mode selection logic
- [ ] Integration with watchfloor

### Step 2: Update src/core/supervisor.py ✅
- [ ] Implement auto-restart logic
- [ ] Add exponential backoff
- [ ] Add health checking
- [ ] Integration with launcher

### Step 3: Create start.py ✅
- [ ] Argparse setup
- [ ] Interactive mode
- [ ] Non-interactive mode
- [ ] Call launcher.py

### Step 4: Create start.sh ✅
- [ ] Interactive bash script
- [ ] Calls start.py internally
- [ ] Preserves current user experience

### Step 5: Test & Validate ✅
- [ ] Test on WSL
- [ ] Test interactive mode
- [ ] Test CLI flags
- [ ] Test supervisor mode

### Step 6: Archive Old Launchers ✅
- [ ] Move bin/cobaltgraph → bin/archive/
- [ ] Move other old launchers to archive
- [ ] Update symlinks

---

## 🎨 **USER EXPERIENCE**

### Interactive Mode (No Arguments):
```bash
$ python start.py

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CobaltGraph Geo-Spatial Watchfloor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚖️  LEGAL DISCLAIMER
[Shows disclaimer text...]

Do you accept these terms? [yes/no]: yes

🔍 Platform: Linux (WSL2)
✅ Root access: Available
✅ Raw sockets: Available
✅ Network capture: Supported

📡 Monitoring Mode:
  1. Network-wide (full capture)
  2. Device-only (no root required)
  3. Auto-detect (recommended)

Choose mode [1-3]: 3

🖥️ Interface:
  1. Web Dashboard (port 8080)
  2. Terminal UI (experimental)

Choose interface [1-2]: 1

🚀 Starting CobaltGraph...
  Mode: network-wide
  Interface: web
  Dashboard: http://localhost:8080

Press Ctrl+C to stop
```

### CLI Mode (With Flags):
```bash
$ python start.py --mode network --interface web --supervised

✅ Terms auto-accepted (use --show-disclaimer to review)
🚀 Starting CobaltGraph in supervised mode...
  Dashboard: http://localhost:8080
```

---

## 🔧 **TECHNICAL DETAILS**

### Argument Structure:
```python
parser.add_argument('--mode', choices=['network', 'device', 'auto'], default='auto')
parser.add_argument('--interface', choices=['web', 'terminal'], default='web')
parser.add_argument('--supervised', action='store_true')
parser.add_argument('--no-disclaimer', action='store_true')
parser.add_argument('--show-disclaimer', action='store_true')
parser.add_argument('--port', type=int, default=8080)
parser.add_argument('--config', help='Path to config file')
parser.add_argument('--health', action='store_true')
parser.add_argument('--version', action='version', version='CobaltGraph 1.0.0')
```

### Platform Detection:
```python
import platform
import os

def detect_platform():
    system = platform.system()
    is_wsl = 'microsoft' in platform.uname().release.lower()
    
    return {
        'os': system,
        'is_wsl': is_wsl,
        'is_root': os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
        'can_raw_socket': check_raw_socket_capability(),
    }
```

---

## 💡 **MIGRATION PATH**

### Old → New Mapping:
```bash
# OLD:
bin/cobaltgraph                    → start.sh (interactive)
bin/cobaltgraph.py                 → start.py (with args)
start.sh                      → start.sh (updated)
start_supervised.sh           → start.py --supervised
cobaltgraph_startup.sh             → start.sh
cobaltgraph_supervisor.sh          → integrated in supervisor.py
```

### Backwards Compatibility:
- Keep bin/cobaltgraph as symlink to start.sh for 1 version
- Show deprecation warning if old launchers used
- Documentation updated with new commands

---

## ✅ **SUCCESS CRITERIA**

- [ ] Only 2 user-facing entry points (start.py, start.sh)
- [ ] Both interactive and CLI modes work
- [ ] Cross-platform support (Windows, WSL, Linux, macOS)
- [ ] Supervisor mode functional
- [ ] Legal disclaimer properly shown
- [ ] Platform detection works correctly
- [ ] All old launchers archived
- [ ] Documentation updated

---

**Status**: ⏸️ **READY TO IMPLEMENT**
