# Archived Launchers

**Archive Date**: November 11, 2025
**Reason**: Replaced by unified launcher system (Phase 4)

---

## 📦 **Archived Files**

These launcher files have been archived and replaced with the new unified launcher system:

### **From bin/ directory:**
1. **cobaltgraph** (14KB)
   - Original interactive bash launcher
   - Replaced by: `start.sh` (root)

2. **cobaltgraph.py** (2.1KB)
   - Python wrapper for bin/cobaltgraph
   - Replaced by: `start.py` (root)

3. **cobaltgraph.bat** (328B)
   - Windows batch launcher
   - Replaced by: `start.py` (cross-platform)

### **From root directory:**
4. **start_supervised.sh** (1.3KB)
   - Supervisor wrapper script
   - Replaced by: `start.py --supervised`

5. **cobaltgraph_startup.sh** (14KB)
   - Alternative startup script
   - Replaced by: `start.sh` + `src/core/launcher.py`

6. **cobaltgraph_supervisor.sh** (4.3KB)
   - Supervisor implementation
   - Replaced by: `src/core/supervisor.py` (to be implemented)

---

## 🎯 **Why These Were Archived**

**Problems with old launchers:**
- ❌ Too many entry points (7 different launchers!)
- ❌ Duplicated functionality across files
- ❌ Inconsistent behavior
- ❌ Hard to maintain
- ❌ Confusing for users

**Benefits of new unified system:**
- ✅ Only 2 entry points: `start.py` and `start.sh`
- ✅ All logic centralized in `src/core/launcher.py`
- ✅ Consistent behavior across platforms
- ✅ Easy to maintain
- ✅ Professional architecture
- ✅ Comprehensive CLI with 9 options
- ✅ Cross-platform support (Windows, WSL, Linux, macOS)

---

## 🚀 **New Unified Launcher System**

### **Use these instead:**

```bash
# Interactive mode
./start.sh
python3 start.py

# CLI mode with flags
python3 start.py --mode network --interface web
./start.sh --supervised
```

### **Available options:**
- `--mode {network,device,auto}` - Monitoring mode
- `--interface {web,terminal}` - User interface
- `--port PORT` - Dashboard port (default: 8080)
- `--config CONFIG` - Configuration path
- `--supervised` - Auto-restart on crash
- `--no-disclaimer` - Skip legal disclaimer
- `--show-disclaimer` - Display legal terms
- `--health` - Run health check
- `--version` - Show version

---

## 📚 **Migration Guide**

### **Old → New command mapping:**

```bash
# OLD:
bin/cobaltgraph
→ NEW: ./start.sh (interactive)

# OLD:
bin/cobaltgraph.py
→ NEW: python3 start.py

# OLD:
start_supervised.sh
→ NEW: python3 start.py --supervised

# OLD:
cobaltgraph_startup.sh
→ NEW: ./start.sh

# OLD:
cobaltgraph_supervisor.sh
→ NEW: Integrated into src/core/supervisor.py
```

---

## 📖 **Documentation**

For more information, see:
- `PHASE4_LAUNCHER_DESIGN.md` - Design and architecture
- `PHASE4_COMPLETE.md` - Implementation summary
- `README.md` - Project documentation
- `start.py --help` - Command-line reference

---

## ⚠️ **Important Notes**

1. **These files are preserved for reference only**
   - Do not use these archived launchers
   - They may not work correctly with the new modular architecture
   - Use `start.py` or `start.sh` instead

2. **Can be safely deleted**
   - After verifying the new launcher system works
   - These files are no longer maintained
   - All functionality has been migrated

3. **Restoration not recommended**
   - The new system is more maintainable
   - Old launchers have compatibility issues
   - Use the unified system going forward

---

**Archive created as part of**: Phase 4 - Unified Launcher System
**See**: `PHASE4_COMPLETE.md` for full details
