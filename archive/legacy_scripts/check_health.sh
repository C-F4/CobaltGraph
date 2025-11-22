#!/bin/bash
#
# CobaltGraph Health Check - Quick status check
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  CobaltGraph Health Check${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if processes are running
CAPTURE_RUNNING=$(pgrep -f "network_capture.py" > /dev/null && echo "true" || echo "false")
DASHBOARD_RUNNING=$(pgrep -f "cobaltgraph_minimal.py" > /dev/null && echo "true" || echo "false")
SUPERVISOR_RUNNING=$(pgrep -f "cobaltgraph_supervisor.sh" > /dev/null && echo "true" || echo "false")

# Process status
echo -e "${GREEN}Process Status:${NC}"
if [ "$CAPTURE_RUNNING" = "true" ]; then
    echo -e "  📡 Capture:    ${GREEN}●${NC} RUNNING (PID: $(pgrep -f network_capture.py))"
else
    echo -e "  📡 Capture:    ${RED}●${NC} STOPPED"
fi

if [ "$DASHBOARD_RUNNING" = "true" ]; then
    echo -e "  📊 Dashboard:  ${GREEN}●${NC} RUNNING (PID: $(pgrep -f cobaltgraph_minimal.py))"
else
    echo -e "  📊 Dashboard:  ${RED}●${NC} STOPPED"
fi

if [ "$SUPERVISOR_RUNNING" = "true" ]; then
    echo -e "  🔄 Supervisor: ${GREEN}●${NC} RUNNING (PID: $(pgrep -f cobaltgraph_supervisor.sh))"
else
    echo -e "  🔄 Supervisor: ${YELLOW}●${NC} NOT RUNNING"
fi

echo ""

# Check dashboard API
echo -e "${GREEN}Dashboard API:${NC}"
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/health 2>/dev/null | grep -q "200"; then
    echo -e "  🌐 http://localhost:8080 ${GREEN}●${NC} REACHABLE"

    # Get API data
    API_DATA=$(curl -s http://localhost:8080/api/data 2>/dev/null)
    if [ $? -eq 0 ]; then
        CONN_COUNT=$(echo "$API_DATA" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('connections', [])))" 2>/dev/null)
        HEALTH=$(echo "$API_DATA" | python3 -c "import sys, json; data=json.load(sys.stdin); print(int(data.get('system_health', {}).get('overall', 0) * 100))" 2>/dev/null)

        echo -e "  📊 Connections: ${BLUE}$CONN_COUNT${NC}"
        echo -e "  ❤️  Health:     ${BLUE}$HEALTH%${NC}"

        # Component status
        echo ""
        echo -e "${GREEN}Component Status:${NC}"
        echo "$API_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
components = data.get('system_health', {}).get('components', {})
for name, info in components.items():
    status = info.get('status', 'UNKNOWN')
    age = info.get('last_beat_age', 0)
    if status == 'ACTIVE':
        print(f'  ✓ {name:20s} \033[0;32m●\033[0m {status} ({age}s ago)')
    elif status == 'DEGRADED':
        print(f'  ⚠ {name:20s} \033[1;33m●\033[0m {status} ({age}s ago)')
    else:
        print(f'  ✗ {name:20s} \033[0;31m●\033[0m {status} ({age}s ago)')
" 2>/dev/null
    fi
else
    echo -e "  🌐 http://localhost:8080 ${RED}●${NC} UNREACHABLE"
fi

echo ""

# Database check
echo -e "${GREEN}Database:${NC}"
if [ -f "/home/tachyon/CobaltGraph/cobaltgraph_minimal.db" ]; then
    DB_SIZE=$(du -h /home/tachyon/CobaltGraph/cobaltgraph_minimal.db | cut -f1)
    DB_AGE=$(stat -c %Y /home/tachyon/CobaltGraph/cobaltgraph_minimal.db)
    NOW=$(date +%s)
    AGE_MIN=$(( (NOW - DB_AGE) / 60 ))

    echo -e "  💾 Size: ${BLUE}$DB_SIZE${NC}"
    echo -e "  🕐 Last modified: ${BLUE}${AGE_MIN}m ago${NC}"

    # Count records
    DB_COUNT=$(python3 -c "import sqlite3; conn=sqlite3.connect('/home/tachyon/CobaltGraph/cobaltgraph_minimal.db'); print(conn.execute('SELECT COUNT(*) FROM connections').fetchone()[0])" 2>/dev/null)
    echo -e "  📊 Total connections: ${BLUE}$DB_COUNT${NC}"
else
    echo -e "  💾 Database: ${RED}NOT FOUND${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
