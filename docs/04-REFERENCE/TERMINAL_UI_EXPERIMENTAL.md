# Terminal UI - Experimental Feature Documentation

**Status**: ⚠️ EXPERIMENTAL - Linux/macOS only
**Last Updated**: November 10, 2025
**Recommended Alternative**: Web Dashboard (option 1)

---

## 🎯 Overview

CobaltGraph includes an **experimental** Terminal UI (ncurses-based dashboard) as an alternative to the Web Dashboard. However, due to platform compatibility limitations, the Terminal UI is **not recommended for general use**.

### **Recommendation**: Use Web Dashboard (Option 1)

The Web Dashboard is the **primary interface** for CobaltGraph and offers:
- ✅ **Cross-platform compatibility** (Windows, WSL, Linux, macOS)
- ✅ **Better visualization** (interactive maps, charts)
- ✅ **Professional appearance** (better for demos/screenshots)
- ✅ **No terminal requirements** (just needs a browser)
- ✅ **Remote access** (accessible from any device)

---

## 📊 Platform Compatibility Matrix

| Platform | Terminal UI Status | Reason |
|----------|-------------------|--------|
| **Linux** (native terminal) | ✅ Should work | Native ncurses support |
| **macOS** (Terminal.app/iTerm) | ✅ Should work | Native ncurses support |
| **WSL** (Windows Terminal) | ⚠️ May work | Depends on terminal emulator quality |
| **WSL** (other emulators) | ⚠️ Often fails | Limited ncurses support |
| **Windows** (CMD/PowerShell) | ❌ Not supported | No native ncurses |
| **Raspberry Pi** | ✅ Should work | It's Linux |
| **SSH sessions** | ✅ Good use case | Designed for this |
| **IDE terminals** | ❌ Often fails | Not true TTY |

---

## 🛠️ Error Handling Improvements

### **1. Launcher Pre-Checks** (`bin/cobaltgraph`, `cobaltgraph_startup.sh`)

The launcher now:
- ✅ Labels Terminal UI as `[EXPERIMENTAL]`
- ✅ Shows platform compatibility warnings
- ✅ Recommends Web Dashboard as `[RECOMMENDED]`
- ✅ Tests for proper terminal (TTY) before starting
- ✅ Checks `$TERM` environment variable
- ✅ Auto-falls back to Web Dashboard if terminal invalid

#### **Startup Output:**

```
🖥️  User Interface Selection

Choose your preferred interface:

  1) Web Dashboard (http://localhost:8080) [RECOMMENDED]
     • Interactive map with Leaflet.js
     • Real-time connection visualization
     • REST API for integrations
     • Cross-platform (Windows, WSL, Linux, macOS)
     • Best for: Screenshots, demos, remote access

  2) Terminal UI (ncurses-based) [EXPERIMENTAL]
     • Text-based dashboard in terminal
     • Real-time updates
     • Low resource usage
     • ⚠️  Linux/macOS only (not compatible with Windows)
     • ⚠️  May fail in some terminal emulators
     • Best for: SSH sessions, headless servers

Select interface [1/2]: _
```

### **2. Terminal Detection** (Automatic Fallback)

If user selects Terminal UI (option 2), the launcher checks:

```bash
# Check for proper TTY
if [ -t 0 ] && [ -t 1 ] && [ -n "$TERM" ] && [ "$TERM" != "dumb" ]; then
    ✓ Terminal environment detected: xterm-256color
    → Starting Terminal UI
else
    ❌ No interactive terminal detected
    → Falling back to Web Dashboard
fi
```

**Detected Issues:**
- ❌ Not running in a TTY (pipe, background)
- ❌ `$TERM` not set or set to `dumb`
- ❌ STDIN/STDOUT redirected

**Action**: Automatic fallback to Web Dashboard

### **3. Enhanced ultrathink.py Error Handling**

The Terminal UI script (`tools/ultrathink.py`) now includes:

#### **Pre-Flight Checks:**
```python
# Check for interactive terminal
if not sys.stdin.isatty() or not sys.stdout.isatty():
    print("❌ ERROR: Terminal UI requires an interactive terminal (TTY)")
    sys.exit(1)

# Check TERM variable
term = os.environ.get('TERM', '')
if not term or term == 'dumb':
    print(f"❌ ERROR: Invalid terminal type: '{term}'")
    sys.exit(1)
```

#### **Curses Error Handling:**
```python
try:
    ultra.start()
except curses.error as e:
    print("❌ TERMINAL UI ERROR: ncurses initialization failed")
    print("💡 RECOMMENDED SOLUTION: Use Web Dashboard")
    sys.exit(1)
```

#### **Error Message Output:**

When Terminal UI fails, users see:

```
======================================================================
❌ TERMINAL UI ERROR: ncurses initialization failed
======================================================================
Error: cbreak() returned ERR

This usually happens when:
  • Terminal emulator doesn't support ncurses properly
  • Running in WSL with incompatible Windows terminal
  • Terminal size is too small
  • Terminal capabilities are limited

Platform Compatibility:
  ✅ Linux (native terminal)     - Should work
  ✅ macOS (Terminal.app/iTerm)  - Should work
  ⚠️  WSL (Windows Terminal)      - May work
  ⚠️  WSL (other emulators)       - Often fails
  ❌ Windows (CMD/PowerShell)    - Not supported

💡 RECOMMENDED SOLUTION: Use Web Dashboard
   The web dashboard works on ALL platforms and provides:
   • Better visualization (interactive maps)
   • Cross-platform compatibility
   • No terminal compatibility issues

To use Web Dashboard:
   1. Run: python cobaltgraph.py
   2. Select option: 1 (Web Dashboard)
   3. Open browser: http://localhost:8080
======================================================================
```

---

## 🚀 Usage Guide

### **Recommended: Web Dashboard**

```bash
# Start CobaltGraph
python cobaltgraph.py

# When prompted, select:
Select interface [1/2]: 1  # Web Dashboard

# Open browser:
http://localhost:8080
```

### **Experimental: Terminal UI** (Linux/macOS only)

```bash
# Start CobaltGraph
python cobaltgraph.py

# When prompted, select:
Select interface [1/2]: 2  # Terminal UI

# If it fails, launcher automatically falls back to Web Dashboard
```

---

## 🔍 Troubleshooting Terminal UI

### **Issue: `cbreak() returned ERR`**

**Cause**: Terminal emulator doesn't support ncurses properly

**Solution**:
1. Use Web Dashboard (recommended)
2. OR try a different terminal emulator:
   - Linux: `xterm`, `gnome-terminal`, `konsole`
   - macOS: `Terminal.app`, `iTerm2`
   - WSL: `Windows Terminal` (best compatibility)

### **Issue: `Invalid terminal type: ''`**

**Cause**: `$TERM` environment variable not set

**Solution**:
```bash
# Set TERM variable
export TERM=xterm-256color

# Then retry
python cobaltgraph.py
```

### **Issue: Terminal UI starts but looks broken**

**Cause**: Terminal size too small or limited color support

**Solution**:
1. Resize terminal to at least 80x24 characters
2. Use terminal with 256-color support:
   ```bash
   export TERM=xterm-256color
   ```
3. Or use Web Dashboard

---

## 📝 Why Web Dashboard is Better

| Feature | Web Dashboard | Terminal UI |
|---------|---------------|-------------|
| **Platform Support** | Windows, WSL, Linux, macOS, Raspberry Pi | Linux, macOS only |
| **Visualization** | Interactive maps, charts, animations | Text-based only |
| **Screenshots** | Professional, colorful | Plain text |
| **Remote Access** | From any device with browser | SSH only |
| **Setup** | Zero configuration | Requires proper terminal |
| **Stability** | Rock solid | Can fail in some terminals |
| **Demos/LinkedIn** | Impressive visuals | Not visually appealing |
| **Dependencies** | None (just Python) | ncurses/curses required |

---

## 🎯 When to Use Terminal UI

Despite limitations, Terminal UI is useful for:

1. **SSH into headless servers** - No GUI available
2. **Extremely low bandwidth** - Text uses less bandwidth than web
3. **Purist reasons** - Love terminal-only workflows
4. **Security-conscious environments** - No web browser allowed

**For all other use cases, use Web Dashboard.**

---

## 🔧 Technical Details

### **Why ncurses is Problematic:**

1. **Platform-specific**: Linux/Unix have native support, Windows doesn't
2. **Terminal diversity**: Hundreds of terminal emulators, varying support
3. **Environment-dependent**: Requires `$TERM`, `$LINES`, `$COLUMNS` set correctly
4. **TTY requirement**: Doesn't work in pipes, background, or non-interactive shells
5. **Python curses module**: Wrapper around C library, inherits all limitations

### **Why Web Dashboard is Reliable:**

1. **HTTP protocol**: Universal, standardized
2. **Browser diversity**: All modern browsers work the same
3. **localhost binding**: Works on every OS
4. **WSL2 auto-forwarding**: Windows can access WSL `localhost` directly
5. **Pure Python**: No C dependencies, no platform-specific code

---

## 📋 Summary

### **Status**: Terminal UI is **experimental** and **not recommended**

### **Primary Interface**: Web Dashboard (http://localhost:8080)

### **Error Handling**: ✅ Comprehensive
- Pre-flight checks before starting
- Automatic fallback to Web Dashboard
- Helpful error messages with solutions
- Platform compatibility warnings

### **When Terminal UI Fails**:
- User sees clear error message
- Directed to use Web Dashboard
- Step-by-step instructions provided

### **Recommendation**:
**Always use Web Dashboard unless you have a specific reason to use Terminal UI (like SSH into headless server).**

---

## 🚀 Quick Commands

```bash
# Recommended: Start with Web Dashboard
python cobaltgraph.py
# Select: 1 (Web Dashboard)
# Open: http://localhost:8080

# Experimental: Try Terminal UI (may fail)
python cobaltgraph.py
# Select: 2 (Terminal UI)
# If fails: Automatically uses Web Dashboard

# Direct Web Dashboard (skip prompt)
./start.sh  # Always uses Web Dashboard

# Force Web Dashboard
python cobaltgraph.py --mode device  # Future: Add --web flag
```

---

## 📚 Related Documentation

- **LAUNCHER_COMPARISON.md** - All launcher methods explained
- **ARCHITECTURE.md** - System design and data flow
- **FINAL_STATUS.md** - Complete feature overview
- **PLATFORM_SUPPORT.md** - Cross-platform compatibility matrix

---

**Bottom Line**: Terminal UI exists for specialized use cases (SSH, headless servers), but **Web Dashboard is the primary, recommended interface** for CobaltGraph. Use it! 🌐
