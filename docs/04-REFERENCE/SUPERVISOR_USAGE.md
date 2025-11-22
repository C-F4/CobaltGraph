# CobaltGraph Supervisor - Usage Guide

## Overview

CobaltGraph provides two startup modes:

1. **Direct Mode** (`start.sh`) - Manual control, no auto-restart
2. **Supervised Mode** (`start_supervised.sh`) - Auto-restart on crashes

## When to Use Each Mode

### Direct Mode: `./start.sh`
**Use when:**
- Testing and development
- You want full control
- Running temporarily
- You'll manually restart if needed

**Behavior:**
- Starts CobaltGraph pipeline
- Runs until you press Ctrl+C
- Stops completely on any exit
- No automatic restart

### Supervised Mode: `./start_supervised.sh`
**Use when:**
- Production deployment
- Long-term monitoring
- Unattended operation
- You want automatic crash recovery

**Behavior:**
- Starts CobaltGraph pipeline with supervisor
- **Auto-restarts on crashes** (exit code ≠ 0)
- **Stops cleanly on Ctrl+C** (exit code 0 or 130)
- Logs all restarts
- Limits: 10 restarts maximum

---

## How It Works

### Exit Code Detection

The supervisor distinguishes between intentional shutdown and crashes:

```bash
Exit Code 0   → Clean shutdown (Ctrl+C) → Supervisor STOPS
Exit Code 130 → SIGINT (Ctrl+C)        → Supervisor STOPS
Exit Code 1   → Crash (error)          → Supervisor RESTARTS
Any other     → Unexpected failure      → Supervisor RESTARTS
```

### Clean Shutdown Flow

```
User presses Ctrl+C
  ↓
SIGINT sent to pipeline
  ↓
cobaltgraph_minimal.py signal_handler() → sys.exit(0)
  ↓
Supervisor detects exit code 0
  ↓
Supervisor logs "Pipeline stopped cleanly"
  ↓
Supervisor exits (no restart)
```

### Crash Recovery Flow

```
Network capture dies unexpectedly
  ↓
Stdin closes in cobaltgraph_minimal.py
  ↓
Stdin thread detects closure → sys.exit(1)
  ↓
Supervisor detects exit code 1
  ↓
Supervisor logs "Pipeline crashed"
  ↓
Supervisor waits 5 seconds
  ↓
Supervisor restarts pipeline
  ↓
Repeats up to 10 times
```

---

## Resource Efficiency

The supervisor is **very lightweight**:

### Before (Concerns)
- **Worry**: "Supervisor eats up computational resources"
- **Reality**: Only uses resources during restart operations

### Actual Resource Usage

```
CPU:  ~0.0% (blocked in wait(), no polling)
Memory: ~2-3 MB (minimal bash process)
Disk I/O: Only on crash/restart (logging)
```

The supervisor uses `wait` (line 124), which:
- Blocks the process (no CPU usage)
- Wakes only when child exits
- No polling or active checking
- Extremely efficient

**Comparison**:
- Active polling: `while true; do ps -p $PID; sleep 1; done` ❌ (wasteful)
- Blocking wait: `wait $PID` ✅ (efficient)

CobaltGraph uses the efficient method.

---

## Usage Examples

### Start with Supervisor
```bash
./start_supervised.sh
```

Output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CobaltGraph - Supervised Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Features:
  ✓ Auto-restart on crash
  ✓ Health monitoring
  ✓ Clean shutdown on Ctrl+C

Press Ctrl+C to stop (supervisor will also stop)

[06:50:00] 🌍 CobaltGraph Supervisor Starting...
[06:50:00] 🚀 Starting CobaltGraph pipeline (attempt 1/10)...
[06:50:00] ✅ Pipeline started (PID: 12345)
[06:50:00] 🌐 Dashboard: http://localhost:8080
```

### Stop with Ctrl+C
```
^C
[06:55:00] 🛑 Supervisor shutting down...
[06:55:00] Stopping pipeline (PID: 12345)...
[06:55:00] ✅ Cleanup complete
[06:55:00] ✅ Pipeline stopped cleanly (exit 0)
[06:55:00] 👋 Supervisor exiting (no restart needed)
```

### Automatic Restart on Crash
```
[06:52:00] 🔴 Pipeline crashed with code: 1
[06:52:00] ⏳ Restarting in 5s... (attempt 1/10)
[06:52:05] 🚀 Starting CobaltGraph pipeline (attempt 2/10)...
[06:52:05] ✅ Pipeline started (PID: 12346)
```

---

## Configuration

Edit `cobaltgraph_supervisor.sh` to adjust:

```bash
MAX_RESTARTS=10      # Maximum restart attempts
RESTART_DELAY=5      # Seconds to wait before restart
```

**Recommended Settings**:
- **Development**: `MAX_RESTARTS=3` (fail fast)
- **Production**: `MAX_RESTARTS=10` (keep trying)
- **Testing**: `MAX_RESTARTS=1` (debug immediately)

---

## Troubleshooting

### Supervisor keeps restarting
**Symptom**: Pipeline crashes repeatedly
**Check**:
```bash
tail -100 logs/cobaltgraph_$(date +%Y%m%d).log
```
**Look for**: Error messages before each crash
**Fix**: Address the underlying error

### Supervisor won't stop
**Symptom**: Ctrl+C doesn't stop supervisor
**Cause**: Signal not propagating
**Fix**:
```bash
pkill -f cobaltgraph_supervisor.sh
pkill -f cobaltgraph_minimal.py
pkill -f network_capture.py
```

### Max restarts reached
**Symptom**: Supervisor gives up after 10 restarts
**Log**:
```
[06:55:00] ❌ Max restarts (10) reached. Giving up.
[06:55:00]    Check logs in: logs/
```
**Action**: Fix the underlying issue, then restart manually

### Stale PID file
**Symptom**: "CobaltGraph already running" but nothing is running
**Fix**:
```bash
rm -f logs/cobaltgraph.pid
./start_supervised.sh
```

---

## Monitoring

### Check if supervisor is running
```bash
ps aux | grep cobaltgraph_supervisor
```

### Check pipeline status
```bash
cat logs/cobaltgraph.pid
ps -p $(cat logs/cobaltgraph.pid)
```

### View live logs
```bash
tail -f logs/cobaltgraph_$(date +%Y%m%d).log
```

### Count restarts
```bash
grep "Pipeline crashed" logs/cobaltgraph_$(date +%Y%m%d).log | wc -l
```

---

## Comparison: Direct vs Supervised

| Feature | Direct (`start.sh`) | Supervised (`start_supervised.sh`) |
|---------|---------------------|-------------------------------------|
| Auto-restart | ❌ No | ✅ Yes (on crashes only) |
| Ctrl+C behavior | Stops immediately | Stops cleanly (no restart) |
| Resource usage | Minimal | Minimal (+2-3MB for supervisor) |
| Crash recovery | Manual | Automatic (up to 10 times) |
| Logging | Standard | Enhanced (restart tracking) |
| Best for | Development/testing | Production/unattended |

---

## Production Deployment

For long-term production use:

1. **Use supervised mode**:
   ```bash
   ./start_supervised.sh
   ```

2. **Set up systemd** (optional):
   ```bash
   # Create /etc/systemd/system/cobaltgraph.service
   [Unit]
   Description=CobaltGraph Geo Spatial Monitoring
   After=network.target

   [Service]
   Type=simple
   User=tachyon
   WorkingDirectory=/home/tachyon/CobaltGraph
   ExecStart=/home/tachyon/CobaltGraph/start_supervised.sh
   Restart=on-failure
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and start**:
   ```bash
   sudo systemctl enable cobaltgraph
   sudo systemctl start cobaltgraph
   ```

4. **Monitor**:
   ```bash
   sudo systemctl status cobaltgraph
   journalctl -u cobaltgraph -f
   ```

---

## Summary

✅ **Supervisor is efficient** - Uses `wait`, not polling
✅ **Smart restart logic** - Crashes restart, Ctrl+C stops
✅ **Resource minimal** - ~2-3MB overhead
✅ **Production ready** - Handles crashes automatically
✅ **User friendly** - Simple Ctrl+C to stop everything

**Recommendation**:
- Use `start.sh` for development
- Use `start_supervised.sh` for production
