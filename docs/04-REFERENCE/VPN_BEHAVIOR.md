# CobaltGraph and VPN Behavior

**Last Updated**: November 11, 2025

## Overview

When running CobaltGraph while connected to a VPN, you'll see different types of connections. This document explains what you're seeing and why.

---

## 🔍 What CobaltGraph Sees

### Connection Types

Your analysis shows:
```
📊 Connection Breakdown:
   Total Connections: 43
   VPN DNS Protection: 32 (74.4%)  ← Most connections
   Real External: 11 (25.6%)
   Other Local: 0 (0.0%)
```

---

## 🔒 Type 1: VPN DNS Protection (74% of traffic)

### What You're Seeing
```json
{
  "src_ip": "10.255.255.254",
  "dst_ip": "10.255.255.254",  ← Same IP!
  "dst_port": 53,              ← DNS
  "protocol": "UDP"
}
```

### What's Actually Happening

```
Application needs to resolve "anthropic.com"
         ↓
    DNS Query
         ↓
VPN Interface (10.255.255.254) ← Intercepts here
         ↓
    [Encrypts query]
         ↓
   VPN Tunnel (encrypted)
         ↓
   VPN Server
         ↓
  Real DNS Server
         ↓
[Response travels back same path]
```

**From CobaltGraph's perspective** (using `ss` command):
- Connection appears to be: `10.255.255.254 → 10.255.255.254:53`
- Looks like talking to itself!
- This is a **virtual network interface** artifact

**Purpose**: **DNS Leak Prevention**
- Without this, your DNS queries would go directly to your ISP's DNS servers
- ISP could see what websites you're looking up (even if traffic is encrypted)
- VPN intercepts DNS at the interface level and routes through VPN tunnel

### Why So Many?

Every time any application looks up a domain name:
- `claude.ai` → DNS query
- `api.anthropic.com` → DNS query
- `fonts.googleapis.com` → DNS query
- Each subdomain needs a lookup
- DNS queries are frequent!

---

## 🌍 Type 2: Real Internet Connections (26% of traffic)

### What You're Seeing
```json
{
  "src_ip": "172.22.158.173",     ← Your local IP
  "dst_ip": "160.79.104.10",      ← Real destination
  "dst_port": 443,
  "dst_country": "United States",
  "dst_org": "Anthropic, PBC"
}
```

### What's Actually Happening

These are your **actual internet connections** - the real traffic your applications are generating:

```
Claude App
    ↓ HTTPS to api.anthropic.com
    ↓ (sees plain connection)
    ↓
← CobaltGraph captures here ←
    ↓
VPN Software
    ↓ [Encrypts everything]
    ↓
VPN Tunnel
    ↓
VPN Server
    ↓ [Decrypts]
    ↓
Anthropic Servers (160.79.104.10)
```

**CobaltGraph sees**: The application-level connection **after VPN has decrypted it for the app**

**Your Applications See**:
- ✅ `api.anthropic.com` (160.79.104.10)
- ✅ `cloudflare.com` (104.16.x.x)
- ✅ `googleapis.com` (34.36.57.103)

**Your Applications DON'T See**:
- ❌ VPN server IP
- ❌ Encrypted packets
- ❌ VPN tunnel details

---

## 🚫 What CobaltGraph Does NOT See

### The VPN Tunnel Itself

**Missing from your data**: Connection to VPN server

Why? The VPN operates at a **lower network layer**:

```
Network Stack Layers:

Application Layer  ← CobaltGraph captures here (via ss)
    ↓
Transport Layer (TCP/UDP)
    ↓
Network Layer (IP)
    ↓
VPN Software Layer ← VPN operates here
    ↓
Physical Layer
```

**`ss` command shows**: Application-level socket connections
**VPN operates**: Below that, at kernel level

### What You Would See Without VPN

If you disconnected VPN and ran CobaltGraph:

```
Before (With VPN):
172.22.158.173 → 160.79.104.10:443 (Anthropic)

After (No VPN):
172.22.158.173 → 160.79.104.10:443 (Anthropic)
                                  ↑ Same!
```

**Destination wouldn't change!** Because VPN is transparent to applications.

**What WOULD change**:
- Your **public IP** seen by Anthropic's servers
- Your **DNS queries** would go to ISP (no 10.255.255.254 connections)
- ISP could see your traffic metadata

---

## 📊 Your Specific VPN Configuration

Based on your data:

### VPN Type: **DNS Leak Protection Enabled**
```
VPN DNS Server: 10.255.255.254
DNS Queries: 32 captured (74% of traffic)
```

### Real Traffic Captured
```
Destinations:
- Anthropic, PBC (5 connections)
- Cloudflare, Inc. (4 connections)
- Google Cloud (1 connection)
- Google LLC (1 connection)
```

### Network Configuration
```
Your Local IP: 172.22.158.173 (WSL2 adapter)
VPN Interface: 10.255.255.254
Environment: WSL2 on Windows
```

---

## 🛠️ Filtering VPN Noise

### Option 1: Use VPN Analysis Tool

```bash
# Show breakdown
python3 tools/vpn_analysis.py

# Output:
# VPN DNS Protection: 32 (74.4%)
# Real External: 11 (25.6%)
```

### Option 2: Query Real Connections Only

```bash
# Get only external connections (skip VPN DNS)
sqlite3 data/device.db "
  SELECT dst_ip, dst_port, dst_org, dst_country
  FROM connections
  WHERE dst_country IS NOT NULL
  ORDER BY timestamp DESC;
"
```

### Option 3: Dashboard Filter (Future Enhancement)

Add toggle to dashboard:
- [ ] Show VPN DNS queries (default: hide)
- [x] Show only real internet connections

---

## 🎯 Why This Behavior is GOOD

### You're Seeing Actual Application Behavior

**Good**: You see what your apps are actually connecting to
- Claude → Anthropic servers ✅
- Browser → Cloudflare ✅
- System → Google services ✅

**Better than**: Just seeing "connection to VPN server" repeatedly

### VPN is Working Correctly

**Evidence of proper VPN security**:
1. ✅ DNS leak prevention active (10.255.255.254)
2. ✅ All DNS routed through VPN
3. ✅ Real connections show correct destinations

If you saw **no** DNS protection queries, your DNS might be leaking!

---

## 📈 Connection Frequency Explained

### Why So Many DNS Queries?

Modern applications are DNS-heavy:

```
Loading claude.com might cause:
1. claude.com                    → DNS
2. api.claude.com                → DNS
3. assets.claude.com             → DNS
4. cdn.cloudflare.com            → DNS
5. fonts.googleapis.com          → DNS
6. analytics.google.com          → DNS
...15+ DNS queries for one page load!
```

**Each query** → Captured as connection to 10.255.255.254:53

### TTL and Caching

DNS responses have TTL (Time To Live):
- Short TTL = More frequent re-queries
- VPN may set shorter TTLs for security
- Result: More DNS queries captured

---

## 🔬 Advanced: Identifying VPN Software

Based on your patterns, possible VPN software:

### Characteristics Detected
```
DNS Server IP: 10.255.255.254
Pattern: Loopback DNS interception
Interface: Virtual adapter
```

### Likely Candidates
1. **OpenVPN** (10.x.x.x range common)
2. **WireGuard** (clean interface)
3. **ProtonVPN** (known for 10.255.255.254)
4. **NordVPN** (similar pattern)
5. **Tailscale** (if configured)

### Check VPN Type
```bash
# Check network interfaces
ip addr show

# Check routing
ip route show

# Check VPN processes
ps aux | grep -E "(openvpn|wireguard|vpn)"
```

---

## 🚀 Recommendations

### 1. Add Dashboard Filter

Create option to hide VPN DNS noise:
```python
# In dashboard API
if hide_vpn_dns:
    connections = [c for c in connections
                  if not (c['src_ip'] == c['dst_ip'] and c['dst_port'] == 53)]
```

### 2. Add VPN Detection Badge

Show VPN status in dashboard:
```
🔒 VPN Active: DNS Leak Protection Enabled
```

### 3. Separate View for VPN Diagnostics

Create dedicated page:
- VPN DNS query count
- DNS servers used
- Potential DNS leaks
- VPN performance metrics

### 4. Alert on DNS Leaks

If DNS queries go to non-VPN servers:
```
⚠️ ALERT: DNS query to 8.8.8.8 (Google) - potential leak!
Expected: All DNS through 10.255.255.254
```

---

## 📚 Further Reading

### DNS Leak Testing
- https://dnsleaktest.com/
- https://ipleak.net/

### VPN Transparency
- Why you see decrypted traffic
- How VPN routing works
- Network layer vs application layer

### Privacy Implications
- What your ISP sees (with VPN): Encrypted blob to VPN server
- What websites see (with VPN): VPN server's IP, not yours
- What CobaltGraph sees: Your application behavior (but through VPN)

---

## Summary

✅ **Your connections breakdown**:
- 74% VPN DNS protection (expected noise)
- 26% Real internet traffic (what you care about)

✅ **VPN is working correctly**:
- DNS leak prevention active
- All traffic routed through VPN
- CobaltGraph shows actual application behavior

✅ **What you should monitor**:
- Real external connections (Anthropic, Cloudflare, etc.)
- Unusual destinations
- High threat scores (when implemented)

❌ **Don't worry about**:
- High count of 10.255.255.254:53 connections
- "Loopback" DNS patterns
- Missing VPN server IP in logs

**Your VPN privacy is intact** - CobaltGraph is just seeing the application-level view! 🔒
