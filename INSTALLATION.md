# CobaltGraph Installation Guide

**Updated**: November 2025
**Python Version**: 3.8+ (3.10+ recommended)

---

## Quick Start (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd CobaltGraph

# Install dependencies
pip3 install -r requirements.txt

# Run CobaltGraph
python3 start.py
```

---

## Installation Options

### Option 1: Full Installation (Recommended)

Installs all features including Enhanced Terminal UI, geolocation, and data processing.

```bash
pip3 install -r requirements.txt
```

**Includes**:
- ✅ Enhanced Terminal UI (Textual + Rich)
- ✅ Network packet capture (scapy)
- ✅ IP geolocation (geoip2/maxminddb)
- ✅ Data processing (numpy/pandas)
- ✅ Development tools (pytest/black/pylint)

**Size**: ~200MB installed

---

### Option 2: Minimal Installation (Lightweight)

Installs only essential packages for Enhanced Terminal UI.

```bash
pip3 install -r requirements-minimal.txt
```

**Includes**:
- ✅ Enhanced Terminal UI (Textual + Rich)
- ✅ HTTP requests (for threat intelligence APIs)
- ✅ Device-only monitoring (no packet capture)

**Size**: ~50MB installed

**What's Missing**:
- ❌ Network-wide monitoring (needs scapy)
- ❌ IP geolocation (needs geoip2/maxminddb)
- ❌ Advanced data processing (needs numpy/pandas)

You can add these later with:
```bash
pip3 install scapy geoip2 maxminddb numpy pandas
```

---

### Option 3: Manual Installation

Install packages one by one:

```bash
# Essential packages
pip3 install requests>=2.32.0
pip3 install rich>=13.9.0
pip3 install textual>=0.86.0

# Optional: Network monitoring
pip3 install scapy>=2.5.0

# Optional: Geolocation
pip3 install geoip2>=4.8.0 maxminddb>=2.6.0

# Optional: Data processing
pip3 install numpy>=1.26.0 pandas>=2.2.0
```

---

## System-Specific Installation

### Ubuntu/Debian

```bash
# Update package manager
sudo apt update

# Install Python 3 and pip (if not already installed)
sudo apt install python3 python3-pip

# Install CobaltGraph
pip3 install -r requirements.txt

# For network-wide monitoring, install libpcap
sudo apt install libpcap-dev
```

### Fedora/RHEL/CentOS

```bash
# Install Python 3 and pip
sudo dnf install python3 python3-pip

# Install CobaltGraph
pip3 install -r requirements.txt

# For network-wide monitoring
sudo dnf install libpcap-devel
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Install CobaltGraph
pip3 install -r requirements.txt

# libpcap is included with macOS
```

### Windows (WSL Recommended)

**Method 1: WSL (Recommended)**

```powershell
# Install WSL2
wsl --install

# Inside WSL Ubuntu:
pip3 install -r requirements.txt
```

**Method 2: Native Windows**

```powershell
# Install Python 3 from python.org
# Then in PowerShell:
pip install -r requirements.txt

# Note: Network-wide monitoring requires Npcap
# Download from: https://npcap.com/
```

---

## Troubleshooting Installation Issues

### Issue 1: "externally-managed-environment" Error

**Error Message**:
```
error: externally-managed-environment

× This environment is externally managed
```

**Solution A: Use Virtual Environment (Recommended)**

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install packages
pip3 install -r requirements.txt
```

**Solution B: User Installation**

```bash
# Install to user directory (no sudo needed)
pip3 install --user -r requirements.txt
```

**Solution C: System Override (Not Recommended)**

```bash
# Only use if you understand the risks
pip3 install --break-system-packages -r requirements.txt
```

---

### Issue 2: Permission Denied

**Error**: `Permission denied` when installing

**Solution**:

```bash
# Use user installation (no sudo)
pip3 install --user -r requirements.txt

# Or use virtual environment (see above)
```

---

### Issue 3: scapy Installation Fails

**Error**: `Failed to build scapy`

**Solution**:

```bash
# Install libpcap development files
sudo apt install libpcap-dev  # Ubuntu/Debian
sudo dnf install libpcap-devel  # Fedora/RHEL
brew install libpcap  # macOS

# Then retry
pip3 install scapy>=2.5.0
```

**Alternative**: Skip scapy for device-only mode

```bash
# Install without scapy
pip3 install requests rich textual

# Run in device-only mode
python3 start.py --mode device
```

---

### Issue 4: numpy/pandas Installation Slow

**Issue**: numpy/pandas take a long time to install

**Solution**: Use pre-built wheels

```bash
# Install from PyPI (has pre-built wheels)
pip3 install numpy pandas

# Or skip for minimal installation
pip3 install -r requirements-minimal.txt
```

---

### Issue 5: textual/rich Version Conflicts

**Error**: Dependency version conflicts

**Solution**: Update pip and install latest versions

```bash
# Update pip
pip3 install --upgrade pip

# Install with latest versions
pip3 install -r requirements.txt
```

---

## Verifying Installation

### Check Python Version

```bash
python3 --version
# Should show: Python 3.8.0 or higher
```

### Check Installed Packages

```bash
pip3 list | grep -E "(requests|rich|textual|scapy)"
```

Should show:
```
requests      2.32.x or higher
rich          13.9.x or higher
textual       0.86.x or higher
scapy         2.5.x or higher (optional)
```

### Run System Health Check

```bash
python3 start.py --health
```

Should show all checks passing:
```
✓ Python 3.x.x ✓
✓ requests available ✓
✓ scapy available ✓
✓ Configuration System ✓
✓ Terminal Interface ✓
...
Passed: 24/24
```

---

## Post-Installation

### 1. Configure Threat Intelligence APIs (Optional)

```bash
# Create config directory
mkdir -p config

# Add API keys to config/threat_intel.conf
cat > config/threat_intel.conf << EOF
[VirusTotal]
api_key = YOUR_VT_API_KEY_HERE

[AbuseIPDB]
api_key = YOUR_ABUSEIPDB_API_KEY_HERE
EOF

# Secure the file
chmod 600 config/threat_intel.conf
```

### 2. First Run

```bash
# Launch CobaltGraph
python3 start.py

# Select:
#   - Monitoring Mode: 1) Device-Only (recommended)
#   - Interface: 1) Enhanced Terminal UI (recommended)
```

### 3. Test Enhanced Terminal UI

```bash
# Quick demo without full system
python3 demo_enhanced_ui.py
```

---

## Updating Dependencies

To update all packages to latest versions:

```bash
# Update pip first
pip3 install --upgrade pip

# Update all packages
pip3 install --upgrade -r requirements.txt

# Or update specific packages
pip3 install --upgrade rich textual requests
```

---

## Uninstalling

To completely remove CobaltGraph dependencies:

```bash
# Uninstall packages
pip3 uninstall -r requirements.txt -y

# Or if using virtual environment, just delete it
rm -rf venv/
```

---

## Package Versions Summary

| Package | Minimum | Recommended | Purpose |
|---------|---------|-------------|---------|
| Python | 3.8.0 | 3.10+ | Runtime |
| requests | 2.32.0 | Latest | HTTP API calls |
| rich | 13.9.0 | Latest | Terminal formatting |
| textual | 0.86.0 | Latest | TUI framework |
| scapy | 2.5.0 | Latest | Packet capture (optional) |
| geoip2 | 4.8.0 | Latest | Geolocation (optional) |
| maxminddb | 2.6.0 | Latest | GeoIP database (optional) |
| numpy | 1.26.0 | 1.26.x | Arrays (optional) |
| pandas | 2.2.0 | Latest | Data processing (optional) |

---

## Support

If you encounter installation issues:

1. **Check Python version**: `python3 --version` (must be 3.8+)
2. **Update pip**: `pip3 install --upgrade pip`
3. **Use virtual environment**: Recommended to avoid conflicts
4. **Try minimal installation**: `pip3 install -r requirements-minimal.txt`
5. **Check system health**: `python3 start.py --health`

For specific errors, search the error message or create an issue.

---

## Development Installation

For contributing to CobaltGraph:

```bash
# Clone repository
git clone <repository-url>
cd CobaltGraph

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies including dev tools
pip3 install -r requirements.txt

# Run tests
pytest tests/

# Format code
black src/

# Lint code
pylint src/
```

---

**Installation complete! Run `python3 start.py` to begin.**
