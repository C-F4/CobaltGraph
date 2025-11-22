# CobaltGraph Revised Roadmap - Summary
**Date:** 2025-11-17
**Status:** ✅ Complete - Ready for Implementation

---

## 🎯 THE BREAKTHROUGH

You asked: **"When I ran sudo, I couldn't see other devices. Is it really just device-specific monitoring?"**

**Discovery:** No! The problem wasn't the architecture - it was the *missing piece*.

CobaltGraph needs **passive ARP monitoring** in addition to packet capture to discover devices network-wide. ARP broadcasts are visible to all devices on the L2 segment (completely passive, zero scanning).

---

## 📋 WHAT CHANGED

| Aspect | Old Understanding | New Reality |
|--------|-------------------|-------------|
| **Device Discovery** | Active scanning needed | Passive ARP broadcasts work |
| **Network Visibility** | Requires agent on every device | Works naturally on edge router |
| **Implementation** | Complex agent architecture | Simple ARP monitoring thread |
| **Deployment** | Single machine only | Multi-site via edge routers |
| **Timeline** | 60+ weeks | 30-45 weeks |

---

## ✅ THE SOLUTION

Deploy CobaltGraph on **edge routers/firewalls** with:

1. **Passive ARP Monitoring** (new)
   - Listen to ARP broadcasts on L2
   - Extract device MAC, IP, vendor automatically
   - Zero active scanning, completely passive

2. **Passive Packet Capture** (existing)
   - See traffic flowing through edge
   - Extract connection details
   - Enrich with threat intelligence

3. **Unified Intelligence**
   - Know WHICH device (from ARP)
   - Connected WHERE (from packets)
   - WHEN (timestamps)
   - Whether it's MALICIOUS (threat scoring)

---

## 📊 NEW ROADMAP: 5 Phases (30-45 weeks)

### **Phase 0: Passive Device Discovery** (2-3 weeks)
- ARP monitoring thread in grey_man.py
- Device inventory database
- OUI vendor lookup
- Basic device list in dashboard

### **Phase 1: Device-Aware Dashboard** (3-4 weeks)
- Device inventory UI
- Per-device connections
- Threat summary per device
- **MVP Ready** (7-9 weeks from start)

### **Phase 2: Forensic Intelligence** (4-6 weeks)
- Full connection history search
- Advanced filtering
- Timeline visualization
- CSV/JSON export

### **Phase 3: Origin Tracing & DNS** (5-8 weeks)
- Reverse DNS lookup
- Hostname resolution
- DNS-to-IP correlation
- Proxy/VPN detection

### **Phase 4: Multi-Site Enterprise** (8-12 weeks)
- Central aggregation dashboard
- Agent reporting from edge devices
- Cross-site threat correlation
- SIEM integration
- Alert rules engine

### **Phase 5: Security & Production** (3-5 weeks)
- Security patches
- Performance hardening
- High availability setup
- Compliance mapping

---

## 🎁 YOUR REQUIREMENTS ADDRESSED

| Requirement | Solution | Status |
|-----------|----------|--------|
| "Mix of both (edge + gateway)" | Deploy on edge routers | ✅ Designed |
| "See both per-device AND inter-device" | ARP gives devices, packets show connections | ✅ Designed |
| "Network-wide device detection" | Passive ARP monitoring | ✅ Designed |
| "Completely passive, sudo enables it" | ARP/packet capture need raw sockets | ✅ Designed |
| "Just by connecting to network" | ARP broadcasts automatic discovery | ✅ Designed |

---

## 📈 TIMELINE & RESOURCES

- **Total Time:** 30-45 weeks (6-9 months for full vision)
- **MVP Time:** 7-10 weeks (Phases 0-1 + partial Phase 2)
- **Team Size:** 1-2 engineers full-time
- **Additional:** Part-time security/DevOps for Phases 4-5

---

## 🚀 NEXT IMMEDIATE STEPS

**This Week:**
- [ ] Review INDEX_STRATEGIC_ANALYSIS.md (detailed roadmap)
- [ ] Confirm Phases 0-1 are priority
- [ ] Identify 2 engineers for Phase 0

**Next Week:**
- [ ] Create Phase 0 technical spec
- [ ] Design device database schema
- [ ] Prototype ARP packet parsing
- [ ] Mock up device inventory UI

**Week 3:**
- [ ] Begin Phase 0 implementation
- [ ] First ARP packets captured
- [ ] Commit device discovery to GitHub

---

## 📚 DOCUMENTATION

This folder contains:

- **INDEX.md** - High-level overview and quick facts
- **INDEX_STRATEGIC_ANALYSIS.md** - Detailed architecture, phases, code changes
- **README.md** - This file

When ready to start development:
- Create PHASE0_ARP_MONITORING.md (technical spec)
- Create PHASE1_DASHBOARD.md (UI/API design)
- Create MULTI_SITE_ARCHITECTURE.md (enterprise design)

---

## 💡 WHY THIS WORKS

**The Insight:** ARP broadcasts are Layer 2 (not Layer 3)
- **Layer 2 = All devices on segment hear it**
- **Layer 3 = Routed, devices only see their paths**

Traditional network monitoring tries to work at L3 (active scanning). CobaltGraph now leverages L2 (passive ARP) for automatic device discovery.

**No scanning signatures. No active probing. Completely passive.**

---

## ✨ KEY FEATURES BY PHASE

**After Phase 0 (3 weeks):**
- ✅ All LAN devices discovered automatically
- ✅ Device database with MACs, IPs, vendors
- ✅ Basic device list in dashboard

**After Phase 1 (7 weeks):**
- ✅ Device-aware dashboard
- ✅ See which device connects where
- ✅ Per-device threat summary
- ✅ **MVP Ready for production use**

**After Phase 2 (13 weeks):**
- ✅ Full forensic search/investigation
- ✅ Timeline visualization
- ✅ Export for incident reports

**After Phase 3 (21 weeks):**
- ✅ Hostname resolution
- ✅ Origin tracing through proxies
- ✅ Deep forensic investigation

**After Phase 4 (33 weeks):**
- ✅ Multi-site monitoring
- ✅ Enterprise threat correlation
- ✅ SIEM integration

**After Phase 5 (38 weeks):**
- ✅ Production-ready system
- ✅ Hardened for security
- ✅ Enterprise compliance ready

---

## 🔐 SECURITY NOTE

The 8 security vulnerabilities (SEC-001 to SEC-008) identified in the Nov 14 audit are acceptable during Phases 0-2 (testing). They must be patched in Phase 5 before production deployment.

---

## ❓ QUESTIONS FOR YOUR TEAM

Before starting development:

1. **Deployment:** Will this run on edge router/firewall? What Linux OS?
2. **Network Size:** How many devices to monitor?
3. **Timeline:** Can you wait 6-9 months for full vision or need MVP in 8 weeks?
4. **Integration:** Existing SIEM to integrate with?
5. **Budget:** Any constraints on infrastructure?

---

## 🎯 CONFIDENCE LEVEL

- **Architecture:** 95% (based on deep code review + requirements clarification)
- **Timeline Estimates:** 80% (Phase durations are realistic)
- **Resource Requirements:** 75% (depends on team skill level)
- **Feasibility:** 99% (architecture is sound, technology proven)

---

**This is your revised, corrected, better roadmap.**

**Ready to start Phase 0 implementation whenever your team is ready.**

---

*Read INDEX_STRATEGIC_ANALYSIS.md for the complete detailed roadmap with code changes, database schemas, and implementation details.*
