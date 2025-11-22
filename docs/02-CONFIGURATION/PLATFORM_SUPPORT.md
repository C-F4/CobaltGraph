# CobaltGraph Platform Support
## Works on Windows, WSL, Linux, and macOS

---

## 🎯 Quick Answer

**YES** - CobaltGraph works on:
- ✅ **Windows (native)** - CMD, PowerShell
- ✅ **WSL inside Windows** - Windows Subsystem for Linux
- ✅ **Linux (native)** - Ubuntu, Debian, RHEL, Arch, etc.
- ✅ **macOS** - Intel and Apple Silicon

**ONE command works everywhere**: `python cobaltgraph.py`

---

## 🪟 Understanding WSL

### What is WSL?
**WSL (Windows Subsystem for Linux)** is a Linux environment that runs INSIDE Windows.

```
┌─────────────────────────────────────┐
│         Windows 10/11               │
│                                     │
│  ┌───────────────────────────────┐ │
│  │         WSL2                  │ │
│  │  (Linux kernel inside Windows)│ │
│  │                               │ │
│  │  • Ubuntu, Debian, etc.       │ │
│  │  • Bash shell                 │ │
│  │  • Full Linux tools           │ │
│  └───────────────────────────────┘ │
│                                     │
│  Native Windows (CMD/PowerShell)    │
│  • Batch files                      │
│  • Windows tools                    │
└─────────────────────────────────────┘
```

### CobaltGraph Works in BOTH:

**Inside WSL** (Linux environment inside Windows):
```bash
# You're in WSL (check with: uname -a)
python3 cobaltgraph.py
# OR
./bin/cobaltgraph
```

**Native Windows** (CMD/PowerShell):
```cmd
REM You're in Windows (check with: ver)
python cobaltgraph.py
REM OR
cobaltgraph.bat
```

---

## ✅ Complete Platform Matrix

| Environment | OS | How to Run | Network Mode |
|------------|-----|------------|--------------|
| **Native Windows** | Windows 10/11 | `python cobaltgraph.py` or `cobaltgraph.bat` | Admin PowerShell |
| **WSL (Ubuntu)** | Linux inside Windows | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **WSL (Debian)** | Linux inside Windows | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **Native Linux** | Ubuntu, Debian, RHEL | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **macOS (Intel)** | macOS | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **macOS (Apple Silicon)** | macOS | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **Raspberry Pi** | Raspberry Pi OS | `python3 cobaltgraph.py` or `./bin/cobaltgraph` | `sudo` |
| **Docker Container** | Any | `python3 cobaltgraph.py` | Depends on host |

---

## 🔄 Backwards Compatibility

### YES - 100% Backwards Compatible!

**All original methods still work:**

```bash
# Original bash scripts - STILL WORK
./bin/cobaltgraph
./bin/cobaltgraph-health
bash bin/cobaltgraph

# Original start scripts - STILL WORK
./start.sh
./start_supervised.sh
./cobaltgraph_supervisor.sh

# Legacy capture scripts - STILL WORK
./tools/network_capture.py
./tools/grey_man.py

# Original Python scripts - STILL WORK
python3 cobaltgraph_minimal.py
```

**New methods added (not replaced):**

```bash
# New universal launcher
python cobaltgraph.py
python3 cobaltgraph.py

# New Windows batch
cobaltgraph.bat

# New network monitor
python src/capture/network_monitor.py
```

### Nothing Was Removed or Broken!

We **ADDED** cross-platform support without breaking existing functionality:

```
BEFORE (Still Works):
  ./bin/cobaltgraph              ✅
  ./start.sh                ✅
  python3 cobaltgraph_minimal.py ✅

AFTER (Added):
  python cobaltgraph.py          ✅ NEW
  cobaltgraph.bat                ✅ NEW

ALL WORK TOGETHER!
```

---

## 🏗️ Directory Structure (Backwards Compatible)

```
CobaltGraph/
├── bin/                          # NEW organized launchers
│   ├── cobaltgraph                    # Original bash (still works)
│   ├── cobaltgraph.py                 # NEW Python launcher
│   ├── cobaltgraph.bat                # NEW Windows batch
│   └── cobaltgraph-health             # Original health check
│
├── tools/                        # Original capture scripts
│   ├── network_capture.py        # Original (still works)
│   ├── grey_man.py               # Original (still works)
│   └── ultrathink.py             # Original (still works)
│
├── src/                          # NEW organized source
│   ├── core/                     # Enhanced versions
│   ├── capture/                  # Enhanced versions
│   └── intelligence/             # NEW features
│
├── start.sh                      # Original (still works)
├── cobaltgraph_minimal.py             # Original (still works)
├── cobaltgraph_startup.sh             # Enhanced version
├── cobaltgraph.py → bin/cobaltgraph.py    # NEW symlink
└── cobaltgraph.bat → bin/cobaltgraph.bat  # NEW symlink
```

**Key Point**: Original files are preserved. New files enhance them.

---

## 🧪 Testing: What Works Where?

### Windows Native (CMD/PowerShell):
```cmd
✅ python cobaltgraph.py
✅ cobaltgraph.bat
❌ ./bin/cobaltgraph          (bash script - won't work)
❌ ./start.sh            (bash script - won't work)
```

### WSL (Linux inside Windows):
```bash
✅ python3 cobaltgraph.py
✅ ./bin/cobaltgraph
✅ ./start.sh
✅ bash bin/cobaltgraph
❌ cobaltgraph.bat            (batch file - wrong environment)
```

### Linux (Native):
```bash
✅ python3 cobaltgraph.py
✅ ./bin/cobaltgraph
✅ ./start.sh
✅ bash bin/cobaltgraph
❌ cobaltgraph.bat            (Windows-only)
```

### macOS:
```bash
✅ python3 cobaltgraph.py
✅ ./bin/cobaltgraph
✅ ./start.sh
✅ bash bin/cobaltgraph
❌ cobaltgraph.bat            (Windows-only)
```

---

## 💡 Recommended Approach

### For Maximum Compatibility:
```bash
python cobaltgraph.py
# OR
python3 cobaltgraph.py  # Linux/macOS/WSL
```

This **ONE command** works on ALL platforms (Windows, WSL, Linux, macOS).

### For Platform-Specific Users:
```bash
# Windows users who prefer double-click
cobaltgraph.bat

# Unix users who prefer traditional style
./bin/cobaltgraph
```

---

## 🔧 Migration Guide (If You Used Original Scripts)

**Do you need to change anything?** NO!

**Old way** (still works):
```bash
./start.sh
```

**New way** (more compatible):
```bash
python cobaltgraph.py
```

**Both work!** Use whichever you prefer.

---

## 🎓 Understanding the Differences

### Why Different Commands?

**Historical Context**:
- Unix/Linux: Traditionally use bash scripts in `bin/`
- Windows: Traditionally use `.bat` or `.exe` files
- Cross-platform: Use Python (works everywhere)

**CobaltGraph provides all three**:
- Bash scripts for Unix purists
- Batch files for Windows users
- Python launcher for everyone

### What's the "Right" Way?

**There is no one "right" way!** Use whatever works for you:

```bash
# All of these are valid:
python cobaltgraph.py       # Universal (recommended)
python3 cobaltgraph.py      # Linux/macOS/WSL specific
./bin/cobaltgraph           # Unix-style
bash bin/cobaltgraph        # Explicit bash
cobaltgraph.bat             # Windows double-click

# They all do the same thing!
```

---

## ✅ Final Compatibility Checklist

- ✅ Works on native Windows
- ✅ Works on WSL (Linux inside Windows)
- ✅ Works on native Linux (all distros)
- ✅ Works on macOS (Intel & Apple Silicon)
- ✅ Works on Raspberry Pi
- ✅ Backwards compatible with ALL original scripts
- ✅ New features don't break old functionality
- ✅ ONE universal command: `python cobaltgraph.py`
- ✅ Platform-specific alternatives provided
- ✅ Comprehensive documentation for all scenarios

---

## 🚀 Summary

**YES** - CobaltGraph works everywhere:
- Native Windows (CMD/PowerShell)
- WSL inside Windows (Ubuntu, Debian, etc.)
- Native Linux (any distribution)
- macOS (Intel and Apple Silicon)

**YES** - 100% backwards compatible:
- All original scripts still work
- New launchers are additions, not replacements
- Nothing was removed or broken

**ONE command works everywhere:**
```bash
python cobaltgraph.py
```

That's it! Universal, cross-platform, backwards-compatible. ✅
