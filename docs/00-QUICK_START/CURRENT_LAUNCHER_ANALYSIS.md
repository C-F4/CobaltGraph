# Current Launcher Analysis - TOO COMPLEX!

## 📊 Current State: 9+ Launcher Files

| File | Type | Purpose | Platform | Status |
|------|------|---------|----------|--------|
| **bin/cobaltgraph** | Bash | Full-featured launcher (legal, config, UI choice) | Linux/WSL/Mac | Working |
| **bin/cobaltgraph.py** | Python | Wrapper that calls `bin/cobaltgraph` | ALL | Broken? |
| **bin/cobaltgraph.bat** | Batch | Windows launcher | Windows | Untested |
| **cobaltgraph.py** → bin/cobaltgraph.py | Symlink | Root-level access | ALL | Broken? |
| **cobaltgraph.bat** → bin/cobaltgraph.bat | Symlink | Root-level access | Windows | Untested |
| **cobaltgraph_startup.sh** | Bash | DUPLICATE of bin/cobaltgraph | Linux/WSL/Mac | Working |
| **start.sh** | Bash | Legacy simple launcher | Linux/WSL/Mac | Working |
| **start_supervised.sh** | Bash | Wrapper for supervisor | Linux/WSL/Mac | Working |
| **cobaltgraph_supervisor.sh** | Bash | Auto-restart watchdog | Linux/WSL/Mac | Working |

**Total**: 9 launcher-related files 😱

---

## 🔍 Analysis

### **What Actually Works:**

1. **bin/cobaltgraph** - Full bash launcher with all features (legal, config, UI selection)
2. **cobaltgraph_startup.sh** - Exact duplicate of bin/cobaltgraph (why???)
3. **start.sh** - Simple bash launcher (no prompts, just starts)
4. **start_supervised.sh + cobaltgraph_supervisor.sh** - Auto-restart capability

### **What's Broken:**

1. **bin/cobaltgraph.py** - Python wrapper can't find startup script
2. **cobaltgraph.py** (symlink) - Broken because bin/cobaltgraph.py is broken
3. **cobaltgraph.bat** - Untested, likely broken

### **What's Redundant:**

1. **cobaltgraph_startup.sh** vs **bin/cobaltgraph** - IDENTICAL (0 byte diff)
2. **start_supervised.sh** - Just calls cobaltgraph_supervisor.sh (thin wrapper)

---

## 🎯 Problem Statement

- **Too many files** - User doesn't know which to use
- **Path issues** - Scripts can't find each other
- **Cross-platform goal not met** - Python wrapper broken, Windows untested
- **Maintenance nightmare** - Changes need to be duplicated across files

---

## 💡 Proposed Simplification: TWO SCRIPTS

Before I propose, I need to understand your requirements...
