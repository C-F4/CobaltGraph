# CobaltGraph Launch Methods - All Platforms
## Cross-Platform Compatibility Guide

CobaltGraph works on **Windows**, **WSL**, **Linux**, and **macOS**. Here are ALL the ways to launch it:

---

## 🚀 Universal Method (Works Everywhere)

```bash
python cobaltgraph.py
# OR on Linux/macOS/WSL:
python3 cobaltgraph.py
```

**This is the recommended method** - it works identically across all platforms.

---

## 🪟 Windows-Specific Methods

### Method 1: Double-Click (Easiest)
1. Navigate to CobaltGraph folder in File Explorer
2. Double-click **`cobaltgraph.bat`**
3. Follow on-screen prompts

### Method 2: Command Prompt (CMD)
```cmd
cd path\to\CobaltGraph
python cobaltgraph.py
```

### Method 3: PowerShell
```powershell
cd path\to\CobaltGraph
python cobaltgraph.py
```

### Method 4: Batch File
```cmd
cobaltgraph.bat
```

### For Network-Wide Monitoring (Admin Required):
1. Right-click PowerShell → "Run as Administrator"
2. Navigate to CobaltGraph folder
3. Run: `python cobaltgraph.py`

---

## 🐧 WSL (Windows Subsystem for Linux)

### Device-Only Mode:
```bash
# Any of these work:
python3 cobaltgraph.py
python cobaltgraph.py
bash bin/cobaltgraph
./bin/cobaltgraph
```

### Network-Wide Mode (Recommended for Demo):
```bash
# Requires sudo for promiscuous mode:
sudo python3 cobaltgraph.py

# OR
sudo bash bin/cobaltgraph

# OR
sudo ./bin/cobaltgraph
```

---

## 🐧 Linux (Native)

### Device-Only Mode:
```bash
python3 cobaltgraph.py
# OR
./bin/cobaltgraph
```

### Network-Wide Mode (Recommended for Demo):
```bash
sudo python3 cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

---

## 🍎 macOS

### Device-Only Mode:
```bash
python3 cobaltgraph.py
# OR
./bin/cobaltgraph
```

### Network-Wide Mode (Requires root):
```bash
sudo python3 cobaltgraph.py
# OR
sudo ./bin/cobaltgraph
```

---

## 🔍 Health Check (All Platforms)

### Universal:
```bash
python cobaltgraph.py --health
```

### Platform-Specific:
```bash
# Linux/WSL/macOS:
./bin/cobaltgraph-health

# Windows:
bash bin/cobaltgraph-health
```

---

## 📋 Command Options

```bash
# Show help
python cobaltgraph.py --help

# Health check
python cobaltgraph.py --health

# Specify mode (auto, device, network)
python cobaltgraph.py --mode network

# Specify interface
python cobaltgraph.py --interface eth0
```

---

## 🔧 File Structure Explanation

```
CobaltGraph/
├── cobaltgraph.py         ← Universal Python launcher (RECOMMENDED)
├── cobaltgraph.bat        ← Windows batch launcher
├── bin/
│   ├── cobaltgraph        ← Bash script (Linux/WSL/macOS)
│   └── cobaltgraph-health ← Health check bash script
└── ...
```

**Why so many launch methods?**
- **`cobaltgraph.py`**: Universal Python launcher (works everywhere)
- **`cobaltgraph.bat`**: Convenience for Windows users (double-click)
- **`bin/cobaltgraph`**: Traditional Unix-style launcher for Linux purists
- **All do the same thing** - just different entry points for different platforms

---

## ❓ Which Should You Use?

| Platform | Recommended | Alternative |
|----------|------------|-------------|
| **Windows** | `python cobaltgraph.py` | `cobaltgraph.bat` (double-click) |
| **WSL** | `python3 cobaltgraph.py` | `./bin/cobaltgraph` |
| **Linux** | `python3 cobaltgraph.py` | `./bin/cobaltgraph` |
| **macOS** | `python3 cobaltgraph.py` | `./bin/cobaltgraph` |

**Best practice**: Use `python cobaltgraph.py` - it's consistent across all platforms.

---

## 🆘 Troubleshooting by Platform

### Windows

**"python is not recognized"**
```
Solution: Install Python from https://python.org
During install, check "Add Python to PATH"
```

**"Access is denied" for network mode**
```
Solution: Run PowerShell as Administrator
Right-click PowerShell → "Run as Administrator"
```

### WSL

**"Permission denied: ./bin/cobaltgraph"**
```bash
# Solution 1: Use python launcher
python3 cobaltgraph.py

# Solution 2: Make executable
chmod +x bin/cobaltgraph
./bin/cobaltgraph

# Solution 3: Use bash explicitly
bash bin/cobaltgraph
```

**"No such file or directory"**
```bash
# Make sure you're in CobaltGraph directory
cd /home/yourusername/CobaltGraph
pwd  # Should show /home/yourusername/CobaltGraph
```

### Linux/macOS

**"python: command not found"**
```bash
# Try python3 instead
python3 cobaltgraph.py

# OR install python3
sudo apt install python3  # Ubuntu/Debian
sudo yum install python3  # RedHat/CentOS
brew install python3      # macOS
```

**"Permission denied" for network mode**
```bash
# Use sudo
sudo python3 cobaltgraph.py
```

---

## 🎯 Quick Reference Card

### Start CobaltGraph (Device Mode):
```bash
python cobaltgraph.py
```

### Start CobaltGraph (Network Mode):
```bash
# Windows (as Admin):
python cobaltgraph.py

# WSL/Linux/macOS:
sudo python3 cobaltgraph.py
```

### Health Check:
```bash
python cobaltgraph.py --health
```

### Access Dashboard:
```
http://localhost:8080
```

### Stop CobaltGraph:
```
Press Ctrl+C in terminal
```

---

## 📊 What Gets Launched?

When you run `python cobaltgraph.py`, here's what happens:

1. **Legal Disclaimer** - Interactive acceptance required
2. **Configuration Check** - Validates settings
3. **Network Detection** - Tests for network-wide capability
4. **Threat Intel Status** - Shows configured services
5. **UI Selection** - Choose web dashboard or terminal
6. **Startup** - Launches capture → intelligence → dashboard
7. **Dashboard Access** - http://localhost:8080

**Timeline**: ~5-10 seconds from launch to dashboard

---

## 🔗 Related Documentation

- **[START_HERE.md](START_HERE.md)** - Platform-specific quick start
- **[QUICKSTART.txt](QUICKSTART.txt)** - Fast-path guide
- **[README.md](README.md)** - Full documentation
- **[SHOWCASE.md](SHOWCASE.md)** - Demo and portfolio guide

---

**The bottom line**: Use `python cobaltgraph.py` on any platform. It just works. 🚀
