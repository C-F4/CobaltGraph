# CobaltGraph - Launcher & Script Comparison Guide
**Understanding the Different Ways to Start CobaltGraph**

---

## 🎯 Quick Answer: Which Should I Use?

| Use Case | Command | Why |
|----------|---------|-----|
| **Simple start** | `python cobaltgraph.py` | ✅ **RECOMMENDED** - Works everywhere |
| **Interactive setup** | `./cobaltgraph_startup.sh` | Full config, legal disclaimer, UI choice |
| **Production** | `./start_supervised.sh` | Auto-restart on crash |
| **Legacy** | `./start.sh` | Original script (still works) |
| **Windows** | `cobaltgraph.bat` or `python cobaltgraph.py` | Double-click or command line |

---

## 📁 File Organization

```
CobaltGraph/
├── bin/                          # ⭐ NEW: Cross-platform launchers
│   ├── cobaltgraph.py                 # Python launcher (primary)
│   ├── cobaltgraph.bat                # Windows batch file
│   ├── cobaltgraph                    # Bash launcher (interactive)
│   ├── cobaltgraph-health             # Health check utility
│   └── README.md                 # Launcher documentation
│
├── cobaltgraph.py          → symlink to bin/cobaltgraph.py ✅
├── cobaltgraph.bat         → symlink to bin/cobaltgraph.bat ✅
├── cobaltgraph_startup.sh  → IDENTICAL to bin/cobaltgraph ✅
├── cobaltgraph_minimal.py             # 🎯 ACTUAL APPLICATION (dashboard)
│
├── start.sh                      # Legacy: Simple start
├── start_supervised.sh           # Legacy: Wrapper for supervisor
└── cobaltgraph_supervisor.sh          # Supervisor/watchdog (auto-restart)
```

---

## 🔍 Detailed Breakdown

### **1. `cobaltgraph.py` (Root & bin/cobaltgraph.py)**

**Type**: Symlink → `bin/cobaltgraph.py`
**Purpose**: Universal Python launcher (cross-platform entry point)
**Location**: Both root and `bin/` (root is symlink)

```python
# What it does:
1. Parse command-line arguments (--health, --mode, --interface)
2. Change to script directory
3. Execute bin/cobaltgraph (bash script) for actual startup
```

**Usage**:
```bash
python cobaltgraph.py              # Windows, WSL, Linux, macOS
python3 cobaltgraph.py             # Explicit Python 3
python cobaltgraph.py --health     # Run health check
```

**Why it exists**:
- ✅ Works on ALL platforms (no bash required on Windows)
- ✅ Single command for cross-platform compatibility
- ✅ Can be called from any directory
- ✅ Entry point for `cobaltgraph.bat`

**Actual behavior**: It's a **wrapper** that calls `bin/cobaltgraph` (bash script)

---

### **2. `cobaltgraph.bat` (Root & bin/cobaltgraph.bat)**

**Type**: Symlink → `bin/cobaltgraph.bat`
**Purpose**: Windows double-click launcher
**Location**: Both root and `bin/` (root is symlink)

```batch
@echo off
# What it does:
1. Check if Python is installed
2. Call: python cobaltgraph.py %*
```

**Usage**:
```cmd
cobaltgraph.bat                    # Windows CMD
.\cobaltgraph.bat                  # PowerShell
double-click cobaltgraph.bat       # GUI
```

**Why it exists**:
- ✅ Windows users can double-click to launch
- ✅ Checks for Python before running
- ✅ Passes all arguments through (`%*`)

**Actual behavior**: Thin wrapper that calls `cobaltgraph.py`

---

### **3. `bin/cobaltgraph` (Bash Script)**

**Type**: Bash script (executable)
**Purpose**: **MAIN INTERACTIVE LAUNCHER** with full features
**Location**: `bin/cobaltgraph`
**Duplicate**: `cobaltgraph_startup.sh` is IDENTICAL (0 byte diff)

```bash
# What it does:
1. Show legal disclaimer (requires "yes" to proceed)
2. Load configuration (config/cobaltgraph.conf)
3. Detect monitoring mode (network vs device)
4. Check threat intelligence status (VirusTotal, AbuseIPDB)
5. User selects UI (web dashboard vs terminal)
6. System health check (port 8080, cleanup)
7. Start pipeline: capture → dashboard
```

**Usage**:
```bash
./bin/cobaltgraph                  # From root directory
bash bin/cobaltgraph               # Explicit bash
cd bin && ./cobaltgraph            # From bin/ directory
```

**Features**:
- ✅ Legal disclaimer acceptance
- ✅ Configuration validation
- ✅ Network mode detection (requires sudo)
- ✅ Threat intel status display
- ✅ Interactive UI selection (web vs terminal)
- ✅ Comprehensive logging (`/tmp/cobaltgraph_startup_*.log`)
- ✅ Colored output
- ✅ Process cleanup before start

**Why it exists**:
- 🎯 **Production-grade startup** with all safety checks
- 🎯 User-friendly interactive prompts
- 🎯 Professional presentation for demos

**Actual behavior**: This is the **"proper" way to start** with all features

---

### **4. `cobaltgraph_startup.sh`**

**Type**: Bash script (executable)
**Purpose**: IDENTICAL to `bin/cobaltgraph` (duplicate for backwards compatibility)
**Location**: Root directory

```bash
diff bin/cobaltgraph cobaltgraph_startup.sh
# Output: (no differences)
```

**Usage**:
```bash
./cobaltgraph_startup.sh           # Same as bin/cobaltgraph
```

**Why it exists**:
- ⚠️ **Legacy compatibility** - kept for users who used this path
- ✅ Ensures old documentation/commands still work
- 🔄 Consider: Could be a symlink instead

**Actual behavior**: Exact duplicate of `bin/cobaltgraph`

---

### **5. `start.sh`**

**Type**: Bash script (legacy)
**Purpose**: Original simple launcher (pre-refactor)
**Location**: Root directory

```bash
# What it does:
1. Clean up existing processes
2. Check port 8080
3. Start pipeline: network_capture.py | cobaltgraph_minimal.py
4. Simple logging
```

**Usage**:
```bash
./start.sh                    # Legacy method
```

**Differences from `bin/cobaltgraph`**:
- ❌ NO legal disclaimer
- ❌ NO configuration validation
- ❌ NO threat intel status
- ❌ NO UI selection (always web)
- ❌ NO network mode detection
- ✅ Simpler, faster startup
- ✅ Good for development/testing

**Why it still exists**:
- ✅ Backwards compatibility
- ✅ Quick start for developers
- ✅ Less interactive (good for scripts)

**Actual behavior**: Minimal launcher, starts pipeline immediately

---

### **6. `start_supervised.sh`**

**Type**: Bash script wrapper
**Purpose**: Launch with auto-restart supervisor
**Location**: Root directory

```bash
# What it does:
1. Show banner
2. Execute: ./cobaltgraph_supervisor.sh
```

**Usage**:
```bash
./start_supervised.sh         # Production deployment
```

**Features**:
- ✅ Auto-restart on crash (up to 10 times)
- ✅ Health monitoring
- ✅ Clean shutdown on Ctrl+C (no restart)
- ✅ Production-ready

**Why it exists**:
- 🎯 **Production deployments** where uptime is critical
- 🎯 Automatic recovery from crashes
- 🎯 Long-running server deployments

**Actual behavior**: Thin wrapper that calls `cobaltgraph_supervisor.sh`

---

### **7. `cobaltgraph_supervisor.sh`**

**Type**: Bash script (supervisor/watchdog)
**Purpose**: Auto-restart loop with crash detection
**Location**: Root directory

```bash
# What it does:
1. Check if already running (PID file)
2. Start pipeline in background
3. Monitor process health
4. On crash: Wait 5s, restart (max 10 times)
5. On Ctrl+C: Clean shutdown, NO restart
```

**Usage**:
```bash
./cobaltgraph_supervisor.sh        # Direct supervisor
./start_supervised.sh         # Recommended wrapper
```

**Features**:
- ✅ PID file management (`logs/cobaltgraph.pid`)
- ✅ Exit code detection (0=clean, non-zero=crash)
- ✅ Max restart limit (10 attempts)
- ✅ Restart delay (5 seconds)
- ✅ Log rotation (daily logs)
- ✅ Signal handling (SIGINT, SIGTERM)

**Why it exists**:
- 🎯 **Production uptime** - keeps CobaltGraph running
- 🎯 Crash recovery without manual intervention
- 🎯 Daemon-like behavior

**Actual behavior**: Runs pipeline in loop, restarts on unexpected exit

---

### **8. `cobaltgraph_minimal.py`**

**Type**: Python application (NOT a launcher)
**Purpose**: **THE ACTUAL APPLICATION** - Dashboard + processing
**Location**: Root directory

```python
# What it does:
1. Read connections from STDIN (piped from capture)
2. Geo-enrichment (ip-api.com)
3. Threat intelligence (VirusTotal, AbuseIPDB)
4. Database storage (SQLite)
5. Serve web dashboard (HTTP server on :8080)
6. REST API endpoints
```

**Usage**:
```bash
# Never run directly! Always piped from capture:
python3 network_monitor.py | python3 cobaltgraph_minimal.py

# Or use a launcher that sets up the pipeline
```

**Why it exists**:
- 🎯 **This IS CobaltGraph** - the core application
- 🎯 All other scripts are just launchers for this

**Actual behavior**: The dashboard, processing, and API server

---

## 🌊 Data Flow Through Scripts

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER STARTS CobaltGraph                               │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌──────────────────┐   ┌───────────────────┐   ┌──────────────────┐
│  python cobaltgraph.py│   │ ./cobaltgraph_startup.sh│   │  ./start.sh      │
│  (cross-platform)│   │ (interactive)      │   │  (legacy)        │
└────────┬─────────┘   └─────────┬─────────┘   └────────┬─────────┘
         │                       │                        │
         └───────────────┬───────┴────────────────────────┘
                         │
                         ▼
              ┌────────────────────┐
              │   bin/cobaltgraph       │
              │   (bash launcher)  │
              └──────────┬─────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌──────────────────┐          ┌──────────────────────┐
│ network_monitor.py│  PIPE   │ cobaltgraph_minimal.py    │
│ (packet capture) │ ──────> │ (dashboard/app)      │
└──────────────────┘  STDOUT  └──────────────────────┘
                       STDIN              │
                                          ▼
                                  ┌───────────────┐
                                  │ Web Dashboard │
                                  │ localhost:8080│
                                  └───────────────┘
```

---

## 🔄 With Supervisor (Auto-restart)

```
┌──────────────────────────┐
│ ./start_supervised.sh    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ cobaltgraph_supervisor.sh     │
│ (infinite restart loop)  │
└────────────┬─────────────┘
             │
             ▼
    ┌────────────────┐
    │  Run pipeline  │───┐
    └────────────────┘   │
             │           │
             ▼           │
    ┌────────────────┐   │
    │  Crash?        │───┘ YES: Wait 5s, restart
    └────────────────┘
             │ NO (clean exit)
             ▼
    ┌────────────────┐
    │  Exit (no      │
    │  restart)      │
    └────────────────┘
```

---

## 📊 Comparison Matrix

| Script | Platform | Interactive | Legal | Config | Network Mode | Auto-restart | Complexity |
|--------|----------|-------------|-------|--------|--------------|--------------|------------|
| **cobaltgraph.py** | All ✅ | No | No | No | No | No | ⭐ Simple |
| **cobaltgraph.bat** | Windows ✅ | No | No | No | No | No | ⭐ Simple |
| **bin/cobaltgraph** | Linux/WSL/Mac | Yes ✅ | Yes ✅ | Yes ✅ | Yes ✅ | No | ⭐⭐⭐ Full |
| **cobaltgraph_startup.sh** | Linux/WSL/Mac | Yes ✅ | Yes ✅ | Yes ✅ | Yes ✅ | No | ⭐⭐⭐ Full |
| **start.sh** | Linux/WSL/Mac | No | No | No | No | No | ⭐ Simple |
| **start_supervised.sh** | Linux/WSL/Mac | No | No | No | No | Yes ✅ | ⭐⭐ Wrapper |
| **cobaltgraph_supervisor.sh** | Linux/WSL/Mac | No | No | No | No | Yes ✅ | ⭐⭐⭐ Complex |
| **cobaltgraph_minimal.py** | All ✅ | N/A | N/A | N/A | N/A | N/A | ⭐⭐⭐⭐⭐ App |

---

## 🎓 Understanding the Layers

### **Layer 1: Entry Points (User-facing)**
- `python cobaltgraph.py` - Universal launcher
- `cobaltgraph.bat` - Windows double-click
- `./cobaltgraph_startup.sh` - Interactive bash launcher

### **Layer 2: Orchestration (Setup & Config)**
- `bin/cobaltgraph` - Main bash launcher with full features
- `start.sh` - Minimal bash launcher
- `cobaltgraph_supervisor.sh` - Auto-restart wrapper

### **Layer 3: Pipeline (Data Processing)**
- `network_monitor.py` - Packet capture (STDOUT)
- `cobaltgraph_minimal.py` - Dashboard + processing (STDIN)

### **Layer 4: Application (Core)**
- `cobaltgraph_minimal.py` - The actual CobaltGraph application

---

## 🚀 Recommendations

### **For Regular Use**:
```bash
python cobaltgraph.py              # ✅ BEST: Cross-platform, simple
./cobaltgraph_startup.sh           # ✅ GOOD: Full features, interactive
```

### **For Production Servers**:
```bash
./start_supervised.sh         # ✅ BEST: Auto-restart on crash
```

### **For Development/Testing**:
```bash
./start.sh                    # ✅ QUICK: No prompts, fast startup
```

### **For Windows**:
```cmd
python cobaltgraph.py              # ✅ BEST: Command line
cobaltgraph.bat                    # ✅ GOOD: Double-click GUI
```

---

## 🧹 Cleanup Opportunities

### **Current Redundancies**:
1. ✅ `cobaltgraph.py` (root) → symlink to `bin/cobaltgraph.py` (GOOD)
2. ✅ `cobaltgraph.bat` (root) → symlink to `bin/cobaltgraph.bat` (GOOD)
3. ⚠️ `cobaltgraph_startup.sh` → DUPLICATE of `bin/cobaltgraph` (could be symlink)
4. ⚠️ `start_supervised.sh` → thin wrapper (could be eliminated)

### **Potential Simplification**:
```bash
# Make cobaltgraph_startup.sh a symlink (like cobaltgraph.py)
rm cobaltgraph_startup.sh
ln -s bin/cobaltgraph cobaltgraph_startup.sh

# Or eliminate it and update docs to use bin/cobaltgraph
```

---

## 💡 Key Insights

1. **`cobaltgraph.py`** is the **universal entry point** (works everywhere)
2. **`bin/cobaltgraph`** is the **full-featured launcher** (interactive, production-ready)
3. **`cobaltgraph_minimal.py`** is the **actual application** (not a launcher!)
4. **`cobaltgraph_supervisor.sh`** is for **production uptime** (auto-restart)
5. **`start.sh`** is **legacy** (still works, simpler)

**The symlinks are smart design** - they provide multiple paths to the same functionality while keeping the source files organized in `bin/`.

---

## 📝 Summary

| If you want... | Use this |
|----------------|----------|
| Simple, cross-platform start | `python cobaltgraph.py` ✅ |
| Full interactive experience | `./bin/cobaltgraph` or `./cobaltgraph_startup.sh` |
| Production with auto-restart | `./start_supervised.sh` |
| Quick dev start (no prompts) | `./start.sh` |
| Windows double-click | `cobaltgraph.bat` |

**Bottom line**: Most users should use **`python cobaltgraph.py`** - it's universal, simple, and works everywhere. For full features, use **`./cobaltgraph_startup.sh`**. For production, use **`./start_supervised.sh`**.
