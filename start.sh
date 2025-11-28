#!/bin/bash
#
# CobaltGraph - Unified Bash Launcher
# Interactive wrapper for start.py
#
# This script provides a user-friendly bash interface while
# delegating all logic to the unified Python launcher (start.py)
#
# Usage:
#   ./start.sh                    # Interactive mode
#   ./start.sh --help             # Show help
#   ./start.sh <args>             # Pass args to start.py
#

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ACTIVATE VIRTUAL ENVIRONMENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Check for and activate venv if it exists
# Use absolute path to venv python for sudo compatibility
VENV_PYTHON=""
if [ -f "venv/bin/python3" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/bin/python3"
    source venv/bin/activate 2>/dev/null || true
    USING_VENV=true
elif [ -f ".venv/bin/python3" ]; then
    VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
    source .venv/bin/activate 2>/dev/null || true
    USING_VENV=true
else
    VENV_PYTHON="python3"
    USING_VENV=false
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK PYTHON
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Error: python3 not found${NC}"
    echo ""
    echo "CobaltGraph requires Python 3.8 or higher."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Check Python version (use venv python if available)
PYTHON_VERSION=$("$VENV_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.8"

if ! "$VENV_PYTHON" -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${RED}❌ Error: Python $PYTHON_VERSION found, but 3.8+ required${NC}"
    echo ""
    echo "Please upgrade Python and try again."
    exit 1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK START.PY EXISTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if [ ! -f "start.py" ]; then
    echo -e "${RED}❌ Error: start.py not found${NC}"
    echo ""
    echo "Make sure you're running this script from the CobaltGraph directory."
    exit 1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HANDLE ARGUMENTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If any arguments provided, pass directly to start.py (non-interactive)
if [ $# -gt 0 ]; then
    exec "$VENV_PYTHON" start.py "$@"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTERACTIVE MODE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Clear screen for clean experience
clear

# Show banner
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                    CobaltGraph Geo-Spatial Watchfloor                      ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Passive Reconnaissance & Network Intelligence System${NC}"
echo -e "${CYAN}Version: 1.0.0-MVP${NC}"
echo ""

# Quick system info
echo -e "${CYAN}🔍 System Information:${NC}"
echo -e "  Python: ${GREEN}$PYTHON_VERSION${NC}"
echo -e "  Platform: ${GREEN}$(uname -s)${NC}"
if [ "$USING_VENV" = true ]; then
    echo -e "  Environment: ${GREEN}venv activated${NC}"
else
    echo -e "  Environment: ${YELLOW}system Python (no venv found)${NC}"
fi

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "  Privileges: ${GREEN}root/sudo (network-wide capture available)${NC}"
else
    echo -e "  Privileges: ${YELLOW}user (device-only mode)${NC}"
    echo -e "  ${CYAN}ℹ️  For network-wide capture: sudo ./start.sh${NC}"
fi

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Starting CobaltGraph in interactive mode...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Give user a moment to read
sleep 1

# Launch start.py in interactive mode (no arguments)
exec "$VENV_PYTHON" start.py
