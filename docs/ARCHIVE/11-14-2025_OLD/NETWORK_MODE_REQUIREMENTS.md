# CobaltGraph Network Mode - Requirements & Limitations

## 📋 **Requirements**

### **For Network-Wide Monitoring (--mode network)**

✅ **Required:**
- **Root privileges** (sudo)
- **Linux operating system** (kernel 2.2+)
- **Network interface** (auto-detected, or specify with --interface)

❌ **NOT Required:**
- No special configuration files
- No network interface setup beyond what's already on your system
- No external dependencies (uses Python standard library)

---

## 🖥️ **Operating System Support**

### **Linux** ✅ FULLY SUPPORTED
- Uses `AF_PACKET` raw sockets (built into Linux kernel)
- Network mode: ✅ Works with sudo
- Device mode: ✅ Works without sudo
- **Tested on:**
  - Ubuntu 20.04+
  - Debian 11+
  - Kali Linux
  - WSL2 (Windows Subsystem for Linux)
  - Raspberry Pi OS

### **macOS** ⚠️ PARTIAL SUPPORT
- Network mode: ❌ Not yet implemented (requires BPF)
- Device mode: ⚠️ May work with modifications (needs testing)
- **Future:** Will add BPF (Berkeley Packet Filter) support

### **Windows** ⚠️ PARTIAL SUPPORT
- Network mode: ❌ Not yet implemented (requires WinPcap/Npcap)
- Device mode: ⚠️ May work with modifications (needs netstat parsing)
- **Future:** Will add WinPcap/Npcap support
- **Current workaround:** Use WSL2 (Linux kernel on Windows)

---

## 🚀 **Quick Start**

### **Network Mode (Full Network Capture)**
```bash
# Must use sudo!
sudo ./start.sh

# Select "network" mode when prompted
# OR
sudo python3 start.py --mode network
```

**What it does:**
- Captures ALL traffic on the network segment
- Discovers all devices on the network
- Maps network topology
- Requires root to create raw sockets

### **Device Mode (This Machine Only)**
```bash
# No sudo needed!
./start.sh

# Select "device" mode when prompted
# OR
python3 start.py --mode device
```

**What it does:**
- Captures only YOUR machine's connections
- Uses `ss` command (socket statistics)
- No root required
- Works immediately

---

## 🔍 **Why Sudo is Required for Network Mode**

### **Raw Socket Creation**
Network mode uses **AF_PACKET** sockets to capture packets at layer 2 (Ethernet).

Creating raw sockets requires **CAP_NET_RAW** capability, which is restricted to root:

```python
# This line REQUIRES root:
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
```

Without sudo:
```
PermissionError: [Errno 1] Operation not permitted
```

### **Promiscuous Mode**
To see ALL traffic on the network (not just traffic to/from this machine), the network interface must be put into **promiscuous mode**:

```python
# This also REQUIRES root:
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
```

---

## ⚙️ **How It Works (Self-Contained)**

### **No Configuration Files Needed**

CobaltGraph automatically:

1. **Detects network interfaces:**
   ```python
   # Auto-discovery via /sys/class/net/
   interfaces = os.listdir('/sys/class/net/')
   ```

2. **Selects best interface:**
   - Prefers: eth0, wlan0, en0
   - Skips: lo (loopback), docker0, veth*
   - User can override with `--interface`

3. **Captures packets:**
   - No pcap files needed
   - No tcpdump required
   - Pure Python implementation

4. **Outputs JSON:**
   ```json
   {
     "type": "connection",
     "src_ip": "192.168.1.100",
     "dst_ip": "1.2.3.4",
     "dst_port": 443
   }
   ```

### **Cross-Machine Compatibility**

✅ **Works out-of-the-box on ANY Linux machine:**
- No /etc/ configuration
- No systemd setup
- No kernel modules
- No iptables rules
- No network bridge configuration

Just:
```bash
sudo ./start.sh
```

And it works!

---

## 🔒 **Security Considerations**

### **Why Root is Safe Here**

CobaltGraph only needs root for:
- Creating raw sockets
- Reading network packets

It does **NOT**:
- Modify network configuration
- Change firewall rules
- Install kernel modules
- Modify system files
- Send packets (passive only)

### **Least Privilege Alternative**

If you don't want to run with sudo, use **device mode**:
```bash
./start.sh  # No sudo
# Select "device" mode
```

Or give specific capabilities (Linux only):
```bash
# One-time setup (instead of sudo every time)
sudo setcap cap_net_raw+ep $(which python3)

# Then run without sudo:
./start.sh  # Network mode now works without sudo
```

---

## 🌐 **Network Interface Detection**

### **Automatic Detection**

CobaltGraph detects the best interface automatically:

```python
Priority order:
1. First active Ethernet: eth0, ens33, enp0s3
2. First active WiFi: wlan0, wlp2s0, wlo1
3. First active interface (excluding loopback)
```

### **Manual Selection**

Override with `--interface`:
```bash
sudo python3 start.py --mode network --interface eth0
sudo python3 start.py --mode network --interface wlan0
```

Check available interfaces:
```bash
ip link show
# OR
ifconfig
# OR
ls /sys/class/net/
```

---

## 🐛 **Troubleshooting**

### **"Permission denied" in network mode**

**Cause:** Not running with sudo

**Solution:**
```bash
sudo ./start.sh
# OR
sudo python3 start.py --mode network
```

### **No packets captured**

**Check 1:** Is interface active?
```bash
ip link show eth0  # Should show "UP"
```

**Check 2:** Is there actual traffic?
```bash
# Generate test traffic:
ping google.com
curl https://example.com
```

**Check 3:** Is capture running?
```bash
ps aux | grep -E "grey_man|network_monitor"
```

### **Works on one machine, not another**

**Likely cause:** Different interface names

**Solution:** Let auto-detection work, or specify:
```bash
# Find your interface:
ip link show

# Specify it:
sudo python3 start.py --mode network --interface YOUR_INTERFACE
```

---

## ✅ **Summary**

### **What You Need:**
- ✅ Linux (any distribution)
- ✅ Python 3.8+
- ✅ `sudo` for network mode (OR use device mode without sudo)
- ✅ Active network interface

### **What You DON'T Need:**
- ❌ Configuration files
- ❌ Network setup
- ❌ tcpdump/wireshark
- ❌ pcap libraries
- ❌ Kernel modules
- ❌ iptables rules

### **Cross-Platform Status:**
- **Linux**: ✅ Fully supported (network + device mode)
- **macOS**: ⚠️ Device mode only (future: BPF support)
- **Windows**: ⚠️ Device mode only (future: WinPcap support)
- **WSL2**: ✅ Fully supported (Linux kernel)

---

## 🚀 **Ready to Go!**

```bash
# Network mode (full capture, needs sudo):
sudo ./start.sh

# Device mode (this machine only, no sudo):
./start.sh
```

**It's that simple - fully self-contained and cross-machine compatible!** 🎉
