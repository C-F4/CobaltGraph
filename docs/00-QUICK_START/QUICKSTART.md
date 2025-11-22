# CobaltGraph Quick Start Guide

## Current Status
- ✅ **Main Watchfloor**: Running
- ✅ **Database**: Active
- ✅ **Dashboard**: http://localhost:8080
- ⚠️ **Packet Capture**: Needs sudo
- ⚠️ **UltraThink**: Manual start
- ⚠️ **Neural Engine**: Not built yet

---

## Bring All Components Online

### Simple Method
```bash
# Full system with packet capture:
sudo ./start_all_services.sh

# Limited (no capture):
./start_all_services.sh
```

### Manual Method

**1. Start packet capture:**
```bash
sudo python3 tools/grey_man.py &
```

**2. Start UltraThink monitor:**
```bash
python3 tools/ultrathink.py &
```

**3. Start watchfloor:**
```bash
./start_watchfloor.sh
```

---

## Check Status
```bash
./check_services.sh
```

## Stop Everything
```bash
./stop_services.sh
```

## View Logs
```bash
tail -f logs/watchfloor_*.log
```

---

## Why Are Components Offline?

| Component | Reason | Solution |
|-----------|--------|----------|
| Packet Capture | Needs root for raw sockets | Run with `sudo` |
| UltraThink | Standalone tool | Launch separately |
| Neural Engine | Rust binary not compiled | Future feature |

---

## What Works Now Without Sudo

✅ Geographic intelligence tracking
✅ Database storage
✅ Web dashboard (port 8080)
✅ Heartbeat monitoring
✅ Self-healing system
✅ DNS monitoring
✅ Threat detection

## What Needs Sudo

⚠️ Passive packet capture (GreyMan)
⚠️ Raw socket access
⚠️ Low-level network monitoring

---

## Three Ways to Run

### 1. Basic (No Sudo) - 70% Features
```bash
./start_watchfloor.sh
```
- Geographic intelligence ✅
- Dashboard ✅
- Database ✅
- No packet capture ❌

### 2. Full (With Sudo) - 85% Features
```bash
sudo ./start_all_services.sh
```
- Everything from basic ✅
- Packet capture ✅
- UltraThink ✅
- No neural engine ❌

### 3. Complete (Future) - 100% Features
```bash
# Build neural engine first
sudo ./start_all_services.sh
```
- Everything ✅

---

## Quick Commands

| What | Command |
|------|---------|
| **Start** | `./start_watchfloor.sh` |
| **Start with capture** | `sudo ./start_all_services.sh` |
| **Check status** | `./check_services.sh` |
| **View dashboard** | http://localhost:8080 |
| **Stop** | `./stop_services.sh` |
| **Logs** | `tail -f logs/*.log` |

---

## Troubleshooting

**Q: "Port 8080 in use"**
A: `sudo kill $(lsof -t -i:8080)`

**Q: "Packet capture won't start"**
A: Needs `sudo` - run with `sudo ./start_all_services.sh`

**Q: "System health 35%"**
A: Expected - 3 components optional (neural, capture, ultrathink)

---

## Full Documentation

- **Integration Status**: `INTEGRATION_STATUS.md`
- **Component Guide**: `COMPONENT_ACTIVATION_GUIDE.md`
- **User Guide**: `README_GEOWATCHFLOOR.md`
- **Developer Guide**: `CLAUDE.md`
