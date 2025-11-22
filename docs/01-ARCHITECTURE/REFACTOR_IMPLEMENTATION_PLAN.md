# CobaltGraph - Complete Refactor Implementation Plan
**Date**: November 10, 2025
**Status**: 🚀 READY TO BUILD
**Goal**: Transform into production-grade modular architecture

---

## 📊 **YOUR ARCHITECTURE DECISIONS**

| Question | Choice | Decision |
|----------|--------|----------|
| Q1: Dashboard | **B** | Separate module (`src/dashboard/`) |
| Q2: Entry Point | **B** | CLI framework (argparse, professional) |
| Q3: Config Loading | **B** | Explicit loading (controlled init) |
| Q4: Import Style | **A** | Absolute imports (`from src.core...`) |
| Q5: Terminal UI | **B** | Separate module (`src/terminal/`) |
| Q6: Supervisor | **A** | Built-in (part of launchers) |
| Q7: Capture Pipeline | **C** | Hybrid (pipe OR threading) |
| Q8: Database | **B** | Separate module (`src/storage/`) |
| Q9: Error Handling | **C** | Comprehensive (catch, log, graceful) |
| Q10: Testing | **C** | Comprehensive (`src/tests/`) |

---

## 🏗️ **NEW DIRECTORY STRUCTURE**

```
/home/tachyon/CobaltGraph/
│
├── start.py                    ✅ NEW - Main cross-platform launcher
├── start.sh                    ✅ NEW - Interactive bash launcher
├── README.md                   ✅ KEEP - Main documentation
├── .gitignore                  ✅ KEEP
│
├── src/                        ✅ ONLY CODEBASE (source of truth)
│   ├── __init__.py            ✅ Package init
│   │
│   ├── capture/               ✅ Network capture module
│   │   ├── __init__.py
│   │   ├── network_monitor.py    (Network-wide capture)
│   │   ├── device_monitor.py     (Device-only fallback) NEW
│   │   ├── packet_parser.py      (Packet utilities) NEW
│   │   └── tests/
│   │       ├── test_network_monitor.py
│   │       └── test_packet_parser.py
│   │
│   ├── core/                  ✅ Core application logic
│   │   ├── __init__.py
│   │   ├── config.py             (Configuration management)
│   │   ├── watchfloor.py         (Main orchestrator)
│   │   ├── launcher.py           (CLI launcher logic) NEW
│   │   ├── supervisor.py         (Auto-restart logic) NEW
│   │   └── tests/
│   │       ├── test_config.py
│   │       ├── test_watchfloor.py
│   │       └── test_supervisor.py
│   │
│   ├── intelligence/          ✅ Threat intelligence
│   │   ├── __init__.py
│   │   ├── ip_reputation.py      (VirusTotal, AbuseIPDB)
│   │   ├── geo_enrichment.py     (Geolocation) NEW
│   │   └── tests/
│   │       ├── test_ip_reputation.py
│   │       └── test_geo_enrichment.py
│   │
│   ├── dashboard/             ✅ NEW - Web dashboard module
│   │   ├── __init__.py
│   │   ├── server.py             (HTTP server)
│   │   ├── api.py                (REST API endpoints)
│   │   ├── handlers.py           (Request handlers)
│   │   ├── templates.py          (HTML generation)
│   │   └── tests/
│   │       ├── test_server.py
│   │       └── test_api.py
│   │
│   ├── terminal/              ✅ NEW - Terminal UI (experimental)
│   │   ├── __init__.py
│   │   ├── ultrathink.py         (ncurses UI)
│   │   └── tests/
│   │       └── test_terminal.py
│   │
│   ├── storage/               ✅ NEW - Database layer
│   │   ├── __init__.py
│   │   ├── database.py           (SQLite operations)
│   │   ├── models.py             (Data models)
│   │   ├── migrations.py         (Schema migrations) NEW
│   │   └── tests/
│   │       ├── test_database.py
│   │       └── test_models.py
│   │
│   └── utils/                 ✅ Utilities
│       ├── __init__.py
│       ├── logging.py            (Logging setup) NEW
│       ├── platform.py           (Platform detection) NEW
│       ├── heartbeat.py          (Health monitoring) NEW
│       └── tests/
│           └── test_utils.py
│
├── config/                    ✅ Configuration files
│   ├── cobaltgraph.conf
│   ├── auth.conf
│   └── threat_intel.conf
│
├── templates/                 ✅ HTML templates
│   └── dashboard.html
│
├── data/                      ✅ Runtime data (gitignored)
│   ├── cobaltgraph.db
│   └── cache/
│
├── logs/                      ✅ Log files (gitignored)
│
├── docs/                      ✅ Documentation
│   ├── ARCHITECTURE.md
│   ├── API.md                NEW
│   ├── CONFIGURATION.md      NEW
│   └── DEVELOPMENT.md        NEW
│
└── legacy/                    ✅ Archive old scripts
    ├── OLD_README.txt
    └── archived_scripts/
        ├── config_loader.py      (DELETE after moving)
        ├── cobaltgraph_minimal.py     (DELETE after moving)
        └── bin/                  (DELETE after moving)
```

---

## 🔥 **FILES TO DELETE**

### **Root Directory Duplicates:**
```bash
rm config_loader.py          # → Now src/core/config.py
rm ip_reputation.py          # → Now src/intelligence/ip_reputation.py
rm network_monitor.py        # → Now src/capture/network_monitor.py
rm cobaltgraph_minimal.py         # → Now src/core/watchfloor.py + src/dashboard/
```

### **All Old Launchers:**
```bash
rm -rf bin/                  # Entire bin directory
rm cobaltgraph.py                 # Symlink
rm cobaltgraph.bat                # Symlink
rm cobaltgraph_startup.sh
rm start.sh
rm start_supervised.sh
rm cobaltgraph_supervisor.sh
```

### **Legacy Tools (archive, don't delete yet):**
```bash
mkdir -p legacy/tools
mv tools/network_capture.py legacy/tools/
mv tools/grey_man.py legacy/tools/
mv tools/wsl_recon.py legacy/tools/
# Keep tools/ultrathink.py → moving to src/terminal/ultrathink.py
```

---

## 📝 **IMPLEMENTATION PHASES**

### **PHASE 1: Setup New Structure** ✅
- [x] Create new directory structure
- [ ] Move `tools/ultrathink.py` → `src/terminal/ultrathink.py`
- [ ] Create `__init__.py` files in all modules
- [ ] Create placeholder files for NEW modules
- [ ] Setup `src/tests/` structure

### **PHASE 2: Split Monolithic Code** 🔄
- [ ] Extract dashboard from `watchfloor.py` → `src/dashboard/`
  - [ ] Create `src/dashboard/server.py` (HTTP server)
  - [ ] Create `src/dashboard/api.py` (API endpoints)
  - [ ] Create `src/dashboard/handlers.py` (Request handlers)
  - [ ] Create `src/dashboard/templates.py` (HTML generation)
- [ ] Extract database from `watchfloor.py` → `src/storage/`
  - [ ] Create `src/storage/database.py` (SQLite wrapper)
  - [ ] Create `src/storage/models.py` (Connection, Device models)
- [ ] Extract utilities from `watchfloor.py` → `src/utils/`
  - [ ] Create `src/utils/heartbeat.py` (Health monitoring)
  - [ ] Create `src/utils/logging.py` (Logging setup)
  - [ ] Create `src/utils/platform.py` (OS detection)

### **PHASE 3: Create New Modules** 🆕
- [ ] Create `src/core/launcher.py` (CLI argument handling)
- [ ] Create `src/core/supervisor.py` (Auto-restart logic)
- [ ] Create `src/capture/device_monitor.py` (Fallback capture)
- [ ] Create `src/capture/packet_parser.py` (Packet utilities)
- [ ] Create `src/intelligence/geo_enrichment.py` (Split from IP reputation)
- [ ] Create `src/storage/migrations.py` (Database schema versioning)

### **PHASE 4: Build New Launchers** 🚀
- [ ] Create `start.py` (cross-platform CLI launcher)
  - [ ] Argument parsing (--mode, --interface, --supervised, etc.)
  - [ ] Platform detection
  - [ ] Legal disclaimer
  - [ ] Configuration loading
  - [ ] Launch orchestration
  - [ ] Built-in supervisor mode
- [ ] Create `start.sh` (interactive bash launcher)
  - [ ] Colored prompts
  - [ ] UI selection (web/terminal)
  - [ ] Platform checks
  - [ ] Calls `start.py` with appropriate args

### **PHASE 5: Update Imports** 🔗
- [ ] Update all files to use absolute imports: `from src.core.config import Config`
- [ ] Update `src/core/watchfloor.py` to import from new modules
- [ ] Ensure `src/__init__.py` exports key classes
- [ ] Test all imports work correctly

### **PHASE 6: Add Error Handling** 🛡️
- [ ] Wrap all major operations in try/except
- [ ] Add comprehensive logging
- [ ] Graceful degradation (e.g., continue without threat intel if API fails)
- [ ] User-friendly error messages
- [ ] Cleanup on shutdown

### **PHASE 7: Write Tests** 🧪
- [ ] Unit tests for each module
- [ ] Integration tests for data flow
- [ ] End-to-end tests for full system
- [ ] Test runners and fixtures
- [ ] CI/CD pipeline config (future)

### **PHASE 8: Documentation** 📚
- [ ] Update README.md
- [ ] Create API.md (REST endpoints)
- [ ] Create CONFIGURATION.md (config options)
- [ ] Create DEVELOPMENT.md (contributing guide)
- [ ] Update ARCHITECTURE.md with new structure
- [ ] Add docstrings to all functions/classes

### **PHASE 9: Testing & Validation** ✅
- [ ] Test on Linux
- [ ] Test on WSL
- [ ] Test on macOS (if available)
- [ ] Test Windows (Python only)
- [ ] Test with/without sudo
- [ ] Test with/without API keys
- [ ] Test supervised mode
- [ ] Test pipe mode vs threading mode

### **PHASE 10: Cleanup & Archive** 🧹
- [ ] Move old files to `legacy/`
- [ ] Update .gitignore
- [ ] Remove dead code
- [ ] Archive old documentation
- [ ] Final verification

---

## 🎯 **NEW LAUNCHER SPECIFICATIONS**

### **start.py** (Main Cross-Platform Launcher)

```python
#!/usr/bin/env python3
"""
CobaltGraph - Network Security Platform
Cross-platform launcher with CLI interface

Usage:
    python start.py                          # Interactive mode
    python start.py --mode network           # Network-wide capture
    python start.py --mode device            # Device-only capture
    python start.py --dashboard web          # Web dashboard (default)
    python start.py --dashboard terminal     # Terminal UI (experimental)
    python start.py --supervised             # Auto-restart on crash
    python start.py --no-disclaimer          # Skip legal disclaimer
    python start.py --config /path/config    # Custom config file
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core.launcher import Launcher

def main():
    parser = argparse.ArgumentParser(
        description='CobaltGraph Network Security Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--mode',
        choices=['device', 'network', 'auto'],
        default='auto',
        help='Capture mode (default: auto-detect)'
    )

    parser.add_argument(
        '--dashboard',
        choices=['web', 'terminal', 'none'],
        default='web',
        help='Dashboard type (default: web)'
    )

    parser.add_argument(
        '--supervised',
        action='store_true',
        help='Enable auto-restart on crash'
    )

    parser.add_argument(
        '--no-disclaimer',
        action='store_true',
        help='Skip legal disclaimer'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )

    parser.add_argument(
        '--interface',
        type=str,
        help='Network interface to monitor'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Dashboard port (default: 8080)'
    )

    parser.add_argument(
        '--stdin',
        action='store_true',
        help='Read from stdin (pipe mode)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    args = parser.parse_args()

    # Create and run launcher
    launcher = Launcher(args)
    launcher.start()

if __name__ == '__main__':
    main()
```

### **start.sh** (Interactive Bash Launcher)

```bash
#!/bin/bash
# CobaltGraph - Interactive Launcher
# Provides user-friendly prompts and calls start.py

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}     CobaltGraph Network Security Platform${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Legal Disclaimer
echo -e "${YELLOW}${BOLD}⚖️  LEGAL DISCLAIMER${NC}"
echo ""
echo -e "${RED}This tool is for AUTHORIZED network monitoring ONLY.${NC}"
echo "Unauthorized use may violate laws including CFAA (US), Computer Misuse Act (UK)."
echo ""
read -p "Do you accept legal responsibility? [yes/no]: " ACCEPT

if [[ ! "$ACCEPT" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${RED}Terms not accepted. Exiting.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Terms accepted${NC}"
echo ""

# Dashboard Selection
echo -e "${BOLD}Choose Dashboard:${NC}"
echo "  1) Web Dashboard (http://localhost:8080) ${GREEN}[RECOMMENDED]${NC}"
echo "  2) Terminal UI (ncurses) ${YELLOW}[EXPERIMENTAL - Linux/macOS only]${NC}"
echo ""
read -p "Select [1/2]: " DASH_CHOICE

DASHBOARD="web"
if [ "$DASH_CHOICE" = "2" ]; then
    DASHBOARD="terminal"
fi

# Supervised Mode
echo ""
read -p "Enable auto-restart on crash? [y/n]: " SUPERVISED

SUPERVISED_FLAG=""
if [[ "$SUPERVISED" =~ ^[Yy]$ ]]; then
    SUPERVISED_FLAG="--supervised"
fi

# Launch
echo ""
echo -e "${GREEN}🚀 Launching CobaltGraph...${NC}"
echo ""

python3 start.py --dashboard "$DASHBOARD" $SUPERVISED_FLAG --no-disclaimer
```

---

## 📦 **MODULE SPECIFICATIONS**

### **src/core/launcher.py**
- Parses CLI arguments
- Shows legal disclaimer (if not skipped)
- Loads configuration
- Detects platform capabilities
- Initializes watchfloor
- Optionally wraps in supervisor
- Handles shutdown signals

### **src/core/supervisor.py**
- Monitors watchfloor process
- Restarts on crash (max N times)
- Logs restart events
- Exponential backoff on repeated crashes
- Clean shutdown on Ctrl+C

### **src/dashboard/server.py**
- HTTP server (localhost:8080)
- Request routing
- Authentication middleware
- Static file serving

### **src/dashboard/api.py**
- REST API endpoints
- JSON responses
- Error handling

### **src/storage/database.py**
- SQLite connection management
- Thread-safe operations
- Query builders
- Migration support

### **src/terminal/ultrathink.py**
- Moved from tools/
- Enhanced error handling
- Separate from main codebase

---

## 🚀 **IMMEDIATE NEXT STEPS**

1. **Create directory structure** (Phase 1)
2. **Move ultrathink.py to src/terminal/**
3. **Create __init__.py files**
4. **Start splitting watchfloor.py** (Phase 2)
5. **Build start.py launcher** (Phase 4)
6. **Test basic functionality**

---

## ✅ **SUCCESS CRITERIA**

When complete, you should be able to:

```bash
# Simple start (cross-platform)
python start.py

# Interactive start (Linux/WSL/Mac)
./start.sh

# Advanced options
python start.py --mode network --supervised --dashboard web

# Help
python start.py --help
```

And have:
- ✅ Clean modular codebase (src/ only)
- ✅ No duplicate files
- ✅ Comprehensive tests
- ✅ Professional CLI interface
- ✅ Auto-restart capability
- ✅ Graceful error handling
- ✅ Clear documentation

---

## 🎉 **READY TO BUILD?**

Say the word and I'll start Phase 1! 🚀
