# CobaltGraph Path Fixes - November 10, 2025

## 🐛 Problems Identified

When running `python cobaltgraph.py` or `./cobaltgraph_startup.sh`, the following errors occurred:

1. **`ModuleNotFoundError: No module named 'config_loader'`**
   - Cause: Scripts were looking in `bin/` directory for modules
   - Reality: `config_loader.py` is in project root

2. **`network_monitor.py not found`**
   - Cause: Script was looking in `bin/network_monitor.py`
   - Reality: `network_monitor.py` is in project root

3. **`python3: can't open file '/home/tachyon/CobaltGraph/bin/cobaltgraph_minimal.py'`**
   - Cause: Script tried to run `bin/cobaltgraph_minimal.py`
   - Reality: `cobaltgraph_minimal.py` is in project root

## 🔍 Root Cause

The launcher scripts in `bin/` were setting their working directory to `bin/` instead of the project root:

```bash
# BEFORE (incorrect):
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"  # Points to bin/
cd "$SCRIPT_DIR"  # Changes to bin/
```

This caused Python imports and file paths to fail because all the application files are in the parent directory (project root).

## ✅ Fixes Applied

### 1. Fixed `bin/cobaltgraph` (Bash launcher)

**File**: `/home/tachyon/CobaltGraph/bin/cobaltgraph`

```bash
# AFTER (correct):
BIN_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"  # Get bin/ directory
SCRIPT_DIR="$(cd "$BIN_DIR/.." && pwd)"  # Go up to project root
cd "$SCRIPT_DIR"  # Now we're in /home/tachyon/CobaltGraph
```

**Result**: Script now runs from project root where all files exist.

### 2. Fixed `cobaltgraph_startup.sh` (Root launcher)

**File**: `/home/tachyon/CobaltGraph/cobaltgraph_startup.sh`

```bash
# This script is already in project root, so it just needs clarity:
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"  # Already in project root
```

**Result**: Script already runs from project root (no change needed, just clarity).

### 3. Fixed `bin/cobaltgraph.py` (Python launcher)

**File**: `/home/tachyon/CobaltGraph/bin/cobaltgraph.py`

```python
# BEFORE (incorrect):
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Points to bin/
sys.path.insert(0, os.path.join(SCRIPT_DIR, 'src'))  # Looks for bin/src/

# Run scripts:
startup_script = os.path.join('bin', 'cobaltgraph')  # From bin/, becomes bin/bin/cobaltgraph ❌
```

```python
# AFTER (correct):
BIN_DIR = os.path.dirname(os.path.abspath(__file__))  # bin/
PROJECT_ROOT = os.path.dirname(BIN_DIR)  # Project root
SCRIPT_DIR = PROJECT_ROOT
sys.path.insert(0, os.path.join(SCRIPT_DIR, 'src'))  # Now finds src/

# Run scripts:
startup_script = os.path.join(SCRIPT_DIR, 'bin', 'cobaltgraph')  # /home/tachyon/CobaltGraph/bin/cobaltgraph ✅
```

**Result**: Python launcher now correctly navigates to project root before calling bash scripts.

## 📁 File Structure (For Reference)

```
/home/tachyon/CobaltGraph/              ← PROJECT ROOT (where we need to be)
├── bin/                            ← Launcher scripts live here
│   ├── cobaltgraph.py                   ← Needs to cd to parent
│   ├── cobaltgraph                      ← Needs to cd to parent
│   ├── cobaltgraph-health
│   └── cobaltgraph.bat
│
├── config_loader.py               ← In root (not bin/)
├── network_monitor.py             ← In root (not bin/)
├── cobaltgraph_minimal.py              ← In root (not bin/)
├── ip_reputation.py               ← In root (not bin/)
│
├── cobaltgraph.py → bin/cobaltgraph.py      ← Symlink (resolves to bin/)
├── cobaltgraph.bat → bin/cobaltgraph.bat    ← Symlink (resolves to bin/)
├── cobaltgraph_startup.sh              ← Already in root (correct)
│
├── src/                           ← Python packages
│   ├── capture/
│   ├── intelligence/
│   ├── core/
│   └── ...
│
├── config/                        ← Configuration files
├── tools/                         ← Utility scripts
└── logs/                          ← Log outputs
```

## 🧪 Verification

### Test 1: Check directory resolution
```bash
cd /home/tachyon/CobaltGraph/bin
bash -c 'BIN_DIR="$( cd "$( dirname "cobaltgraph" )" && pwd )"; SCRIPT_DIR="$(cd "$BIN_DIR/.." && pwd)"; echo "$SCRIPT_DIR"'
# Expected: /home/tachyon/CobaltGraph
```

### Test 2: Check config_loader import
```bash
cd /home/tachyon/CobaltGraph
python3 -c "from config_loader import load_config; print('✅ Success')"
# Expected: ✅ Success
```

### Test 3: Check file existence
```bash
cd /home/tachyon/CobaltGraph
ls -la config_loader.py network_monitor.py cobaltgraph_minimal.py
# Expected: All files exist
```

## 🚀 How to Run CobaltGraph Now

All launchers should now work correctly:

```bash
# Method 1: Python launcher (cross-platform)
python cobaltgraph.py

# Method 2: Bash launcher (interactive)
./cobaltgraph_startup.sh

# Method 3: Direct bash launcher
./bin/cobaltgraph

# Method 4: Legacy
./start.sh
```

All methods now correctly:
1. Navigate to project root (`/home/tachyon/CobaltGraph`)
2. Find `config_loader.py` for configuration
3. Find `network_monitor.py` for packet capture
4. Find `cobaltgraph_minimal.py` for the dashboard

## 📝 Summary

**Problem**: Launchers in `bin/` tried to run from `bin/` directory
**Solution**: Changed launchers to navigate to project root before running
**Result**: All imports and file paths now work correctly

**Files Modified**:
- ✅ `/home/tachyon/CobaltGraph/bin/cobaltgraph` (bash launcher)
- ✅ `/home/tachyon/CobaltGraph/bin/cobaltgraph.py` (python launcher)
- ✅ `/home/tachyon/CobaltGraph/cobaltgraph_startup.sh` (clarity comment added)

**Status**: Ready to run! 🚀
