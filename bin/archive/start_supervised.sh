#!/bin/bash
#
# CobaltGraph - Supervised startup (with auto-restart on crash)
# Use this when you want automatic recovery from crashes
#
# Usage:
#   ./start_supervised.sh    # Start with supervisor
#   Press Ctrl+C to stop (will NOT restart)
#
# The supervisor will automatically restart CobaltGraph if:
# - Network capture crashes
# - Dashboard crashes
# - Any unexpected error occurs
#
# The supervisor will NOT restart if:
# - You press Ctrl+C (clean shutdown)
# - You explicitly stop the process
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  CobaltGraph - Supervised Mode${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Features:${NC}"
echo "  ✓ Auto-restart on crash"
echo "  ✓ Health monitoring"
echo "  ✓ Clean shutdown on Ctrl+C"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop (supervisor will also stop)${NC}"
echo ""

# Run the supervisor
exec ./cobaltgraph_supervisor.sh
