# CobaltGraph /bin Directory
## Executable Entry Points for All Platforms

This directory contains ALL executable entry points for CobaltGraph.

---

## Files

| File | Type | Works On | Description |
|------|------|----------|-------------|
| **cobaltgraph** | Bash script | Linux, WSL, macOS | Traditional Unix-style launcher |
| **cobaltgraph.py** | Python | Windows, Linux, WSL, macOS | Universal Python launcher (RECOMMENDED) |
| **cobaltgraph.bat** | Batch file | Windows | Windows-specific launcher |
| **cobaltgraph-health** | Bash script | Linux, WSL, macOS | Health check utility |

---

## Which One Should You Use?

### **Recommended for Everyone: `cobaltgraph.py`**
```bash
python bin/cobaltgraph.py
# OR from project root:
python cobaltgraph.py  # (symlink)
```

**Why?** Works identically on ALL platforms - Windows, Linux, WSL, macOS.

---

## Platform-Specific Recommendations

### Windows
```cmd
REM Option 1: Double-click in File Explorer
bin\cobaltgraph.bat

REM Option 2: Command line
python bin\cobaltgraph.py

REM For network-wide (as Admin):
python bin\cobaltgraph.py
```

### WSL (Windows Subsystem for Linux)
```bash
# Option 1: Python launcher (recommended)
python3 bin/cobaltgraph.py

# Option 2: Bash script
./bin/cobaltgraph

# For network-wide:
sudo python3 bin/cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

### Linux
```bash
# Option 1: Python launcher (recommended)
python3 bin/cobaltgraph.py

# Option 2: Bash script (traditional Unix)
./bin/cobaltgraph

# For network-wide:
sudo python3 bin/cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

### macOS
```bash
# Option 1: Python launcher (recommended)
python3 bin/cobaltgraph.py

# Option 2: Bash script
./bin/cobaltgraph

# For network-wide:
sudo python3 bin/cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

---

## Technical Details

### Bash Scripts (`cobaltgraph`, `cobaltgraph-health`)
- **File Type**: Shell scripts with `#!/bin/bash` shebang
- **Requirements**: Bash shell (included in Linux/WSL/macOS, NOT native Windows)
- **On Windows**: Only works inside WSL, Git Bash, or Cygwin
- **Advantage**: Native Unix-style interface

### Python Launcher (`cobaltgraph.py`)
- **File Type**: Python script with `#!/usr/bin/env python3` shebang
- **Requirements**: Python 3.8+ (must install on Windows)
- **On All Platforms**: Works identically
- **Advantage**: True cross-platform compatibility

### Batch File (`cobaltgraph.bat`)
- **File Type**: Windows batch script
- **Requirements**: Windows Command Prompt or PowerShell
- **On Windows Only**: Cannot run on Linux/macOS/WSL
- **Advantage**: Double-clickable on Windows

---

## Why Multiple Entry Points?

Different users prefer different workflows:

- **Unix purists**: Use `./bin/cobaltgraph` (bash script)
- **Python developers**: Use `python bin/cobaltgraph.py` (Python script)
- **Windows users**: Double-click `bin\cobaltgraph.bat` (batch file)

**All do the same thing** - they're just different interfaces to the same system.

---

## About Bash on Windows

**Bash does NOT work natively on Windows**, but works in:
- ✅ WSL (Windows Subsystem for Linux) - RECOMMENDED
- ✅ Git Bash (comes with Git for Windows)
- ✅ Cygwin (Unix-like environment for Windows)
- ❌ Native Windows CMD/PowerShell (cannot run bash scripts)

**That's why we provide multiple launchers!**

---

## Symlinks in Project Root

For convenience, symlinks exist in project root:
```
CobaltGraph/
├── cobaltgraph.py → bin/cobaltgraph.py      # Symlink for convenience
├── cobaltgraph.bat → bin/cobaltgraph.bat    # Symlink for convenience
└── bin/
    ├── cobaltgraph                     # Actual bash script
    ├── cobaltgraph.py                  # Actual Python launcher
    ├── cobaltgraph.bat                 # Actual batch file
    └── cobaltgraph-health              # Actual health check
```

This means you can run from project root:
```bash
python cobaltgraph.py           # Instead of: python bin/cobaltgraph.py
```

---

## Command Summary

### Start CobaltGraph:
```bash
python bin/cobaltgraph.py       # Universal (all platforms)
./bin/cobaltgraph               # Unix-style (Linux/WSL/macOS)
bin\cobaltgraph.bat             # Windows (double-click or CMD)
```

### Health Check:
```bash
python bin/cobaltgraph.py --health    # Universal
./bin/cobaltgraph-health              # Unix-style
```

### From Project Root (via symlinks):
```bash
python cobaltgraph.py           # Same as: python bin/cobaltgraph.py
```

---

## Best Practice

**For maximum compatibility**: Always use the Python launcher
```bash
python bin/cobaltgraph.py
```

This single command works on Windows, Linux, WSL, and macOS without modification.
