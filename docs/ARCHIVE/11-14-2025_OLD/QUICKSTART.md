# CobaltGraph - Quick Start Guide

## 🚀 **Start the Full System**

### **Option 1: Interactive Mode (Recommended)**
```bash
./start.sh
```

This will:
1. Show legal disclaimer
2. Detect your system capabilities
3. Ask you to choose mode (network or device)
4. Start the FULL orchestrator system
5. Launch dashboard on http://localhost:8080

---

### **Option 2: Direct Command**

```bash
# Device mode (no root required)
python3 start.py --mode device

# Network mode (requires root)
sudo python3 start.py --mode network
```

---

## ✅ **Verify It's Working**

### **1. Check Dashboard**
Open browser: **http://localhost:8080**

You should see:
- 🗺️ Interactive world map
- 📊 Connection feed (real-time)
- 📈 Metrics (total connections, countries, threats)

### **2. Check API Endpoint**
```bash
curl http://localhost:8080/api/data | jq .
```

Should return JSON with:
```json
{
  "timestamp": ...,
  "connections": [ ... ],  # Recent connections
  "metrics": {
    "total_connections": ...,
    "buffer_size": ...,
    "uptime_seconds": ...,
    "mode": "device"
  },
  "integration_status": {
    "database": "ACTIVE",
    "geo_engine": "ACTIVE",
    "connection_monitor": "ORCHESTRATOR"
  }
}
```

### **3. Check Processes**
```bash
ps aux | grep -E "python.*orchestrator|grey_man|network_capture"
```

You should see:
- Main orchestrator process
- Capture subprocess (grey_man.py or network_capture.py)

### **4. Check Database**
```bash
sqlite3 data/cobaltgraph.db "SELECT COUNT(*) FROM connections"
```

Should show connection count (may be 0 initially, give it a minute to capture traffic)

### **5. Generate Test Traffic** (if no connections showing)
```bash
# In another terminal, generate some traffic
curl https://google.com
curl https://github.com
curl https://api.ipify.org

# Then refresh dashboard
```

---

## 🔧 **Troubleshooting**

### **Issue: No data in dashboard**

**Check 1**: Is capture running?
```bash
ps aux | grep -E "grey_man|network_capture"
```

**Check 2**: Is API returning data?
```bash
curl http://localhost:8080/api/data
```

**Check 3**: Any errors in logs?
```bash
# Check terminal output for error messages
```

---

### **Issue: "Permission denied" errors**

**Solution**: Use device mode (no root needed)
```bash
python3 start.py --mode device
```

Or run with sudo for network mode:
```bash
sudo python3 start.py --mode network
```

---

### **Issue: "Module not found" errors**

**Solution**: Make sure you're in the CobaltGraph directory
```bash
cd /home/tachyon/CobaltGraph
python3 start.py
```

---

### **Issue: Dashboard shows "No connections"**

**This is normal** if:
- System just started (give it 30 seconds)
- No network activity happening
- You're in device mode and haven't made any connections

**Generate test traffic**:
```bash
# Make some outbound connections
curl https://google.com
wget https://example.com
ping -c 3 8.8.8.8
```

Then refresh the dashboard.

---

## 📊 **What to Expect**

### **Device Mode**
- Captures **YOUR** machine's connections only
- Uses `ss` command (no root needed)
- Shows:
  - Outbound HTTPS connections
  - API calls
  - Web requests
  - App connections

### **Network Mode** (requires root)
- Captures **ALL** traffic on network segment
- Uses raw packet capture
- Shows:
  - All devices on network
  - All connections from all devices
  - Network topology
  - Device discovery

---

## 🎯 **Key Features**

### **Real-Time Dashboard**
- **Map**: Geographic view of connections
- **Feed**: Live connection stream
- **Metrics**: Total connections, countries, threats
- **Auto-refresh**: Every 5 seconds

### **Threat Intelligence**
- **Geo Enrichment**: IP → Country, City, Lat/Lon, Organization
- **Reputation Scoring**: Threat score (0.0 - 1.0)
- **Threat Details**: Malware, botnet, blacklist checks

### **Data Storage**
- **SQLite Database**: `data/cobaltgraph.db`
- **Historical Data**: All connections stored
- **Query Support**: SQL queries for analysis

---

## 🛑 **Stopping the System**

Press **Ctrl+C** in the terminal

The system will:
1. Stop capture subprocess
2. Stop dashboard server
3. Close database connections
4. Clean shutdown

---

## 📝 **Next Steps**

1. **Run the system**: `./start.sh`
2. **Open dashboard**: http://localhost:8080
3. **Generate traffic**: Browse the web, use apps
4. **Watch the data flow**: Real-time connections appear on map
5. **Explore the database**: `sqlite3 data/cobaltgraph.db`

---

## 🎉 **Success Criteria**

You'll know it's working when:
- ✅ Dashboard loads at http://localhost:8080
- ✅ `/api/data` returns JSON with connections
- ✅ Map shows connection markers
- ✅ Database has rows in `connections` table
- ✅ Metrics show non-zero counts

---

## 🆘 **Need Help?**

### **Still not working?**

1. Check the **FULL_SYSTEM_ARCHITECTURE.md** for detailed architecture
2. Look for error messages in terminal output
3. Verify Python 3.8+ is installed: `python3 --version`
4. Check dependencies are installed: `pip3 install requests`

### **Want to understand the system?**

Read **FULL_SYSTEM_ARCHITECTURE.md** - it explains:
- How components work together
- Data flow diagrams
- API response formats
- Troubleshooting guides

---

**Ready? Let's go! 🚀**

```bash
./start.sh
```
