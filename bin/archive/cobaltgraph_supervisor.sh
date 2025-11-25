#!/bin/bash
#
# CobaltGraph Supervisor - Auto-restart watchdog for network monitoring
#
# Features:
# - Auto-restart on crash
# - Graceful shutdown handling
# - Log rotation
# - Health monitoring
#

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CAPTURE_SCRIPT="$SCRIPT_DIR/tools/network_capture.py"
DASHBOARD_SCRIPT="$SCRIPT_DIR/cobaltgraph_minimal.py"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/cobaltgraph.pid"
MAX_RESTARTS=10
RESTART_DELAY=5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Create tmp log file for initialization output
INIT_LOG="/tmp/cobaltgraph_supervisor_init_$(date +%Y%m%d_%H%M%S).log"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$INIT_LOG"
}

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$INIT_LOG"
}

log_warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$INIT_LOG"
}

# Cleanup function
cleanup() {
    log "🛑 Supervisor shutting down..."

    # Kill pipeline
    if [ -f "$PID_FILE" ]; then
        PIPELINE_PID=$(cat "$PID_FILE")
        if ps -p "$PIPELINE_PID" > /dev/null 2>&1; then
            log "Stopping pipeline (PID: $PIPELINE_PID)..."
            kill -TERM "$PIPELINE_PID" 2>/dev/null
            sleep 2

            # Force kill if still alive
            if ps -p "$PIPELINE_PID" > /dev/null 2>&1; then
                log_warn "Force killing pipeline..."
                kill -9 "$PIPELINE_PID" 2>/dev/null
            fi
        fi
        rm -f "$PID_FILE"
    fi

    # Kill any remaining processes
    pkill -f "network_capture.py" 2>/dev/null
    pkill -f "cobaltgraph_minimal.py" 2>/dev/null

    log "✅ Cleanup complete"
    exit 0
}

# Trap signals
trap cleanup SIGINT SIGTERM

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        log_error "❌ CobaltGraph already running (PID: $OLD_PID)"
        log_error "   Use 'pkill -f cobaltgraph_supervisor' to stop it first"
        exit 1
    else
        log_warn "⚠️  Stale PID file found, cleaning up..."
        rm -f "$PID_FILE"
    fi
fi

# Verify scripts exist
if [ ! -f "$CAPTURE_SCRIPT" ]; then
    log_error "❌ Capture script not found: $CAPTURE_SCRIPT"
    exit 1
fi

if [ ! -f "$DASHBOARD_SCRIPT" ]; then
    log_error "❌ Dashboard script not found: $DASHBOARD_SCRIPT"
    exit 1
fi

log "🌍 CobaltGraph Supervisor Starting..."
log "📂 Log directory: $LOG_DIR"
log "📝 Init log: $INIT_LOG"
log "🔄 Max restarts: $MAX_RESTARTS"
log ""

restart_count=0

# Main supervisor loop
while true; do
    log "🚀 Starting CobaltGraph pipeline (attempt $((restart_count + 1))/$MAX_RESTARTS)..."

    # Start pipeline in background with logging
    {
        python3 -u "$CAPTURE_SCRIPT" 2>&1 | \
        python3 -u "$DASHBOARD_SCRIPT" 2>&1 | \
        tee -a "$LOG_DIR/cobaltgraph_$(date +%Y%m%d).log"
    } &

    PIPELINE_PID=$!
    echo "$PIPELINE_PID" > "$PID_FILE"

    log "✅ Pipeline started (PID: $PIPELINE_PID)"
    log "🌐 Dashboard: http://localhost:8080"
    log ""

    # Wait for pipeline to exit
    wait "$PIPELINE_PID"
    EXIT_CODE=$?

    # Clean up PID file
    rm -f "$PID_FILE"

    # Distinguish between intentional shutdown vs crash
    if [ "$EXIT_CODE" -eq 0 ]; then
        # Exit code 0 = clean shutdown (user pressed Ctrl+C)
        log "✅ Pipeline stopped cleanly (exit 0)"
        log "👋 Supervisor exiting (no restart needed)"
        exit 0
    elif [ "$EXIT_CODE" -eq 130 ]; then
        # Exit code 130 = SIGINT (Ctrl+C)
        log "✅ Received interrupt signal (Ctrl+C)"
        log "👋 Supervisor exiting (no restart needed)"
        exit 0
    else
        # Non-zero exit = crash, should restart
        log_error "🔴 Pipeline crashed with code: $EXIT_CODE"

        # Check restart count
        restart_count=$((restart_count + 1))
        if [ "$restart_count" -ge "$MAX_RESTARTS" ]; then
            log_error "❌ Max restarts ($MAX_RESTARTS) reached. Giving up."
            log_error "   Check logs in: $LOG_DIR"
            exit 1
        fi

        # Delay before restart
        log_warn "⏳ Restarting in ${RESTART_DELAY}s... (attempt $restart_count/$MAX_RESTARTS)"
        sleep "$RESTART_DELAY"
    fi
done
