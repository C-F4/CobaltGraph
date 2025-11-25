#!/bin/bash
#
# CobaltGraph - Unified Startup Script
# Geo-Spatial Watchfloor System
#
# This script:
# - Shows legal disclaimer
# - Detects available capture methods
# - Shows configured threat intelligence services
# - Allows user to choose interface (web/terminal)
# - Starts CobaltGraph with appropriate configuration
#

set -e

# Get script directory (should already be in project root)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Logging
INIT_LOG="/tmp/cobaltgraph_startup_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo -e "$1" | tee -a "$INIT_LOG"
}

log_section() {
    echo "" | tee -a "$INIT_LOG"
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BLUE}  $1${NC}"
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "" | tee -a "$INIT_LOG"
}

# Banner
clear
log_section "CobaltGraph Geo-Spatial Watchfloor"

log "${CYAN}Passive Reconnaissance & Network Intelligence System${NC}"
log "${CYAN}Version: 1.0.0-MVP${NC}"
echo "" | tee -a "$INIT_LOG"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LEGAL DISCLAIMER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "⚖️  LEGAL DISCLAIMER"

log "${YELLOW}${BOLD}IMPORTANT: READ BEFORE PROCEEDING${NC}"
echo "" | tee -a "$INIT_LOG"

log "${RED}This tool is designed for AUTHORIZED network monitoring ONLY.${NC}"
echo "" | tee -a "$INIT_LOG"

log "You may ONLY use CobaltGraph to monitor networks where you have:"
log "  • ${GREEN}Explicit written authorization from the network owner${NC}"
log "  • ${GREEN}Legal ownership of the network${NC}"
log "  • ${GREEN}Proper consent from all parties being monitored${NC}"
echo "" | tee -a "$INIT_LOG"

log "${RED}Unauthorized network monitoring may violate:${NC}"
log "  • Computer Fraud and Abuse Act (CFAA) - United States"
log "  • Computer Misuse Act - United Kingdom"
log "  • Similar laws in other jurisdictions"
echo "" | tee -a "$INIT_LOG"

log "${YELLOW}The authors and contributors of CobaltGraph:"
log "  • Assume NO liability for misuse"
log "  • Do NOT condone illegal activity"
log "  • Are NOT responsible for your actions${NC}"
echo "" | tee -a "$INIT_LOG"

log "${BOLD}By proceeding, you acknowledge that:${NC}"
log "  1. You have legal authorization to monitor this network"
log "  2. You understand the legal implications"
log "  3. You accept full responsibility for your actions"
echo "" | tee -a "$INIT_LOG"

# Require explicit acceptance
read -p "$(echo -e ${GREEN}Do you accept these terms? [yes/no]: ${NC})" ACCEPT

if [[ ! "$ACCEPT" =~ ^[Yy][Ee][Ss]$ ]]; then
    log ""
    log "${RED}❌ Terms not accepted. Exiting.${NC}"
    exit 1
fi

log ""
log "${GREEN}✅ Terms accepted. Proceeding with startup...${NC}"
sleep 1

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOAD CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "⚙️  Configuration"

# Check if config exists
if [ ! -f "config/cobaltgraph.conf" ]; then
    log "${YELLOW}⚠️  Configuration not found. Using defaults.${NC}"
    log "${CYAN}ℹ️  Run 'nano config/cobaltgraph.conf' to customize.${NC}"
fi

# Load and display configuration status
log "${CYAN}Loading configuration...${NC}"
python3 -c "
from config_loader import load_config
config = load_config(verbose=False)
print('✅ Configuration loaded successfully')
" 2>&1 | tee -a "$INIT_LOG"

if [ $? -ne 0 ]; then
    log "${RED}❌ Configuration error. Please fix config files and restart.${NC}"
    exit 1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DETECT NETWORK MONITORING MODE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "📡 Network Monitoring Mode"

MONITOR_MODE="device"  # Default
CAPTURE_SCRIPT="tools/network_capture.py"

# Check if new network_monitor.py exists
if [ -f "network_monitor.py" ]; then
    log "${CYAN}Checking network monitoring capabilities...${NC}"

    # Test if we can create raw sockets (requires root)
    if python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" 2>/dev/null; then
        log "${GREEN}✅ Raw socket capability available (running as root/sudo)${NC}"
        log "${GREEN}✅ Network-wide monitoring ENABLED${NC}"
        log "${BOLD}   Mode: NETWORK SECURITY PLATFORM${NC}"
        log "${CYAN}   → Monitoring entire network segment${NC}"
        log "${CYAN}   → Device discovery and tracking${NC}"
        log "${CYAN}   → Promiscuous mode packet capture${NC}"
        MONITOR_MODE="network"
        CAPTURE_SCRIPT="network_monitor.py --mode network"
    else
        log "${YELLOW}⚠️  Not running as root - network-wide monitoring unavailable${NC}"
        log "${CYAN}   Mode: DEVICE MONITORING (this machine only)${NC}"
        log "${CYAN}   ℹ️  For network-wide: sudo ./cobaltgraph_startup.sh${NC}"
        MONITOR_MODE="device"
        CAPTURE_SCRIPT="network_monitor.py --mode device"
    fi
else
    log "${YELLOW}⚠️  network_monitor.py not found, using legacy capture${NC}"

    # Fallback to legacy grey_man/ss
    if [ -f "tools/grey_man.py" ] && python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" 2>/dev/null; then
        log "${GREEN}   Using: grey_man.py (raw packet capture)${NC}"
        MONITOR_MODE="device"
        CAPTURE_SCRIPT="tools/grey_man.py"
    else
        log "${CYAN}   Using: network_capture.py (socket statistics)${NC}"
        MONITOR_MODE="device"
        CAPTURE_SCRIPT="tools/network_capture.py"
    fi
fi

echo "" | tee -a "$INIT_LOG"
log "${BOLD}Monitoring Mode:${NC} ${GREEN}$MONITOR_MODE${NC}"
log "${BOLD}Capture Command:${NC} ${GREEN}$CAPTURE_SCRIPT${NC}"

if [ "$MONITOR_MODE" = "network" ]; then
    echo "" | tee -a "$INIT_LOG"
    log "${YELLOW}${BOLD}⚡ NETWORK MODE ACTIVE ⚡${NC}"
    log "${YELLOW}This instance will monitor ALL devices on the network segment${NC}"
    log "${YELLOW}Ensure you have authorization to monitor this network!${NC}"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SHOW THREAT INTELLIGENCE STATUS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "🔍 Threat Intelligence"

python3 <<'PYEOF' 2>&1 | tee -a "$INIT_LOG"
from config_loader import load_config

config = load_config(verbose=False)

# Check threat intel services
services = []

if config.get('virustotal_enabled') and config.get('virustotal_api_key'):
    services.append('VirusTotal')
    print(f"  ✅ VirusTotal: CONFIGURED")
elif config.get('virustotal_enabled'):
    print(f"  ⚠️  VirusTotal: Enabled but no API key")
else:
    print(f"  ❌ VirusTotal: Disabled")

if config.get('abuseipdb_enabled') and config.get('abuseipdb_api_key'):
    services.append('AbuseIPDB')
    print(f"  ✅ AbuseIPDB: CONFIGURED")
elif config.get('abuseipdb_enabled'):
    print(f"  ⚠️  AbuseIPDB: Enabled but no API key")
else:
    print(f"  ❌ AbuseIPDB: Disabled")

if services:
    priority = config.get('threat_priority', '').split(',')
    print(f"\n  📊 Lookup Priority Chain:")
    for i, service in enumerate(priority, 1):
        print(f"     {i}. {service.strip()}")
else:
    print(f"\n  ⚠️  No external threat intel configured")
    print(f"  ℹ️  Using local threat scoring only")
    print(f"  ℹ️  Add API keys in config/threat_intel.conf")

if config.get('enable_ml_detection'):
    print(f"\n  ✅ ML Anomaly Detection: ENABLED")
PYEOF

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# USER INTERFACE SELECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "🖥️  User Interface Selection"

log "Choose your preferred interface:"
echo "" | tee -a "$INIT_LOG"
log "  ${GREEN}1${NC}) ${BOLD}Web Dashboard${NC} (http://localhost:8080) ${GREEN}[RECOMMENDED]${NC}"
log "     • Interactive map with Leaflet.js"
log "     • Real-time connection visualization"
log "     • REST API for integrations"
log "     • Cross-platform (Windows, WSL, Linux, macOS)"
log "     • Best for: Screenshots, demos, remote access"
echo "" | tee -a "$INIT_LOG"
log "  ${GREEN}2${NC}) ${BOLD}Terminal UI${NC} (ncurses-based) ${YELLOW}[EXPERIMENTAL]${NC}"
log "     • Text-based dashboard in terminal"
log "     • Real-time updates"
log "     • Low resource usage"
log "     • ${YELLOW}⚠️  Linux/macOS only (not compatible with Windows)${NC}"
log "     • ${YELLOW}⚠️  May fail in some terminal emulators${NC}"
log "     • Best for: SSH sessions, headless servers"
echo "" | tee -a "$INIT_LOG"

read -p "$(echo -e ${CYAN}Select interface [1/2]: ${NC})" UI_CHOICE

DASHBOARD_SCRIPT=""
UI_TYPE=""

case "$UI_CHOICE" in
    1)
        log ""
        log "${GREEN}✅ Selected: Web Dashboard${NC}"
        DASHBOARD_SCRIPT="cobaltgraph_minimal.py"
        UI_TYPE="web"
        ;;
    2)
        log ""
        log "${GREEN}✅ Selected: Terminal UI${NC}"
        log "${YELLOW}⚠️  EXPERIMENTAL: May not work in all terminals${NC}"

        # Check if ultrathink exists
        if [ -f "tools/ultrathink.py" ]; then
            # Test if we have a proper terminal
            if [ -t 0 ] && [ -t 1 ] && [ -n "$TERM" ] && [ "$TERM" != "dumb" ]; then
                log "${CYAN}✓ Terminal environment detected: $TERM${NC}"
                DASHBOARD_SCRIPT="tools/ultrathink.py"
                UI_TYPE="terminal"
            else
                log "${RED}❌ No interactive terminal detected${NC}"
                log "${YELLOW}   Terminal UI requires a proper TTY${NC}"
                log "${YELLOW}   Falling back to Web Dashboard${NC}"
                DASHBOARD_SCRIPT="cobaltgraph_minimal.py"
                UI_TYPE="web"
            fi
        else
            log "${RED}❌ Terminal UI (ultrathink.py) not found!${NC}"
            log "${YELLOW}Falling back to Web Dashboard${NC}"
            DASHBOARD_SCRIPT="cobaltgraph_minimal.py"
            UI_TYPE="web"
        fi
        ;;
    *)
        log ""
        log "${YELLOW}⚠️  Invalid selection. Defaulting to Web Dashboard.${NC}"
        DASHBOARD_SCRIPT="cobaltgraph_minimal.py"
        UI_TYPE="web"
        ;;
esac

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINAL SYSTEM CHECK
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "🔧 System Check"

# Clean up any existing processes
log "${YELLOW}→${NC} Cleaning up existing processes..."
pkill -f "network_capture.py" 2>/dev/null || true
pkill -f "grey_man.py" 2>/dev/null || true
pkill -f "cobaltgraph_minimal.py" 2>/dev/null || true
pkill -f "ultrathink.py" 2>/dev/null || true
pkill -f "cobaltgraph_supervisor.sh" 2>/dev/null || true
sleep 1

# Check port 8080 (if using web)
if [ "$UI_TYPE" = "web" ]; then
    if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
        log "${YELLOW}→${NC} Port 8080 in use - clearing..."
        kill $(lsof -t -i:8080) 2>/dev/null || true
        sleep 1
    fi
fi

# Create necessary directories
mkdir -p logs exports

log "${GREEN}✓${NC} System ready"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STARTUP SUMMARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log_section "🚀 Starting CobaltGraph"

log "${BOLD}Configuration Summary:${NC}"
log "  📡 Monitor Mode: ${GREEN}$MONITOR_MODE${NC}"
log "  🔧 Capture: ${GREEN}$CAPTURE_SCRIPT${NC}"
log "  🖥️  Interface: ${GREEN}$UI_TYPE${NC} ($DASHBOARD_SCRIPT)"

if [ "$UI_TYPE" = "web" ]; then
    log "  🌐 Dashboard: ${GREEN}http://localhost:8080${NC}"
fi

if [ "$MONITOR_MODE" = "network" ]; then
    log "  🌍 Scope: ${GREEN}NETWORK-WIDE${NC} (all devices on segment)"
else
    log "  💻 Scope: ${GREEN}DEVICE-ONLY${NC} (this machine)"
fi

log "  📝 Logs: ${GREEN}logs/cobaltgraph_$(date +%Y%m%d).log${NC}"
log "  📋 Init Log: ${GREEN}$INIT_LOG${NC}"
echo "" | tee -a "$INIT_LOG"

log "${YELLOW}Press Ctrl+C to stop${NC}"
echo "" | tee -a "$INIT_LOG"

# Wait a moment for user to read
sleep 2

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# START PIPELINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${GREEN}🟢 CobaltGraph ONLINE${NC}"
log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "" | tee -a "$INIT_LOG"

# Start the pipeline
# Note: $CAPTURE_SCRIPT may contain arguments (e.g., "network_monitor.py --mode network")
# Use eval to properly handle the arguments
if [[ "$CAPTURE_SCRIPT" == *" "* ]]; then
    # Contains arguments, use eval
    eval "python3 -u $CAPTURE_SCRIPT" 2>&1 | \
    python3 -u "$DASHBOARD_SCRIPT" 2>&1 | \
    tee -a "logs/cobaltgraph_$(date +%Y%m%d).log"
else
    # Simple script path, no eval needed
    python3 -u "$CAPTURE_SCRIPT" 2>&1 | \
    python3 -u "$DASHBOARD_SCRIPT" 2>&1 | \
    tee -a "logs/cobaltgraph_$(date +%Y%m%d).log"
fi
