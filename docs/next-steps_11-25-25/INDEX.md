# CobaltGraph Revised Architecture & Roadmap
**Corrected Analysis: Passive Edge Device Monitoring**

**Date:** 2025-11-17 (Revised)
**Status:** Ready for Implementation
**Architecture:** Edge Device Deployment with Passive ARP + Traffic Analysis

---

## 🎯 EXECUTIVE SUMMARY: The Revised Vision

### **What Changed**
Original assumption: CobaltGraph needed to do active network scanning
**Reality:** Completely passive ARP monitoring solves network discovery

### **The Better Solution**
Deploy CobaltGraph on **edge routers/firewalls** with:
1. **Passive ARP monitoring** → Discovers all devices on network segment
2. **Passive packet capture** → Sees all traffic crossing edge
3. **Threat intelligence** → Enriches with geolocation + reputation

**Result:** Complete network visibility with ZERO active scanning

---

## 📋 QUICK FACTS

| Aspect | Details |
|--------|---------|
| **Deployment** | Edge routers/firewalls (not endpoints) |
| **Monitoring Type** | Completely passive (ARP + packet sniffing) |
| **Device Discovery** | Via ARP broadcasts (automatic) |
| **Connection Intelligence** | From traffic flowing through edge device |
| **Scalability** | Multi-site aggregation via central dashboard |
| **Privileges Required** | sudo (for raw socket access) |
| **Implementation Time** | Phase 0: 2-3 weeks, Full vision: 30-45 weeks |

---

## 📚 Quick Navigation

## 🏗️ HOW IT WORKS: Two-Layer Passive Architecture

### **Layer 1: Passive ARP Monitoring**
Broadcasts are visible to all devices on the L2 segment (completely passive, zero scanning):
```
Device joins network
  ↓
Sends ARP: "Who has [gateway IP]?"
  ↓
CobaltGraph hears the broadcast
  ↓
Extracts: MAC, IP, Vendor
  ↓
Records device (no scanning, no signatures)
```

### **Layer 2: Passive Packet Capture**
All traffic flowing through edge device is naturally visible:
```
Device A → External IP:Port
  ↓
Packet flows through edge router
  ↓
CobaltGraph captures packet headers
  ↓
Extracts connection + enriches with threat intel
  ↓
Knows: Which device (from ARP) connected where (from packet)
```

---

## 📊 DEPLOYMENT MODEL

```
┌─ Edge Router/Firewall ─────────────────┐
│                                         │
│  CobaltGraph running with sudo               │
│  ├─ ARP Monitor (passive discovery)    │
│  └─ Packet Capture (traffic analysis)  │
│                                         │
│  Sees all LAN devices + their threats  │
└─ Flows traffic normally ────────────────┘
         │
         ├─→ Local devices (MAC/IP/vendor)
         └─→ All outbound/inbound connections
```

**Multi-site: Each edge device reports to central dashboard**

---

## 📈 REVISED 5-PHASE ROADMAP (30-45 weeks)

### **Phase 0: ARP Device Discovery** (2-3 weeks)
- Passive ARP monitoring in grey_man.py
- Device inventory tracking
- OUI vendor lookup
- Initial database schema

### **Phase 1: Device-Aware Dashboard** (3-4 weeks)
- Show discovered devices
- Link connections to devices
- Per-device threat summary
- Device activity timeline

### **Phase 2: Forensic Intelligence** (4-6 weeks)
- Full connection history search
- Advanced filtering (date, threat, location)
- Timeline visualization
- CSV export for incidents

### **Phase 3: Origin Tracing & DNS** (5-8 weeks)
- Reverse DNS integration
- Hostname resolution
- DNS-to-IP correlation
- Proxy detection

### **Phase 4: Multi-Site Enterprise** (8-12 weeks)
- Central aggregation dashboard
- Agent deployment across sites
- Cross-site threat correlation
- SIEM/alert integration

**Estimated Resources:** 1-2 engineers, 6-9 months full vision

---

## 🗂️ Directory Structure

```
docs/
├── INDEX.md                           # THIS FILE - Master index
├── README.md                          # Main project documentation
├── START_HERE.md                      # Platform-specific startup
│
├── 00-QUICK_START/                    # Getting started guides
│   ├── QUICKSTART.md
│   ├── LAUNCH_METHODS.md
│   ├── WINDOWS_INSTALL.md
│   ├── README_LAUNCHERS.txt
│   └── CURRENT_LAUNCHER_ANALYSIS.md
│
├── 01-ARCHITECTURE/                   # System design & architecture
│   ├── FULL_SYSTEM_ARCHITECTURE.md
│   ├── ARCHITECTURE.md
│   ├── PROJECT_STRUCTURE.md
│   ├── INTEGRATION_COMPLETE.md
│   ├── CROSS_PLATFORM_COMPLETE.md
│   ├── FINAL_CLEANUP_COMPLETE.md
│   ├── LAUNCHER_COMPARISON.md
│   ├── PIPELINE_ANALYSIS.md
│   └── REFACTOR_IMPLEMENTATION_PLAN.md
│
├── 02-CONFIGURATION/                  # Configuration & setup
│   ├── DATABASE_MANAGEMENT.md
│   ├── ENCRYPTED_SECRETS_GUIDE.md
│   ├── PLATFORM_SUPPORT.md
│   ├── NETWORK_MODE_REQUIREMENTS.md
│   └── PATH_FIXES.md
│
├── 03-TESTING/                        # Test reports & findings
│   ├── INTEGRATION_TEST_REPORT.txt
│   ├── INTEGRATION_TEST_FINDINGS_SUMMARY.txt
│   ├── INTEGRATION_TEST_QUICK_REFERENCE.txt
│   ├── INTEGRATION_TEST_METRICS.md
│   └── INTEGRATION_TEST_INDEX.txt
│
├── 04-REFERENCE/                      # API & feature reference
│   ├── API_REFERENCE.md
│   ├── MODULE_USAGE_ANALYSIS.md
│   ├── UNUSED_MODULES_FINAL.md
│   ├── SUPERVISOR_USAGE.md
│   ├── VPN_BEHAVIOR.md
│   ├── SHOWCASE.md
│   ├── TERMINAL_UI_EXPERIMENTAL.md
│   ├── TERMINAL_UI_CHANGES_SUMMARY.md
│   └── WORKER_QUEUE_EXPLANATION.md
│
├── 05-DEPLOYMENT/                     # Deployment & status
│   ├── DEPLOYMENT_SUMMARY_20251114.md
│   ├── VERIFICATION_REPORT.txt
│   ├── SYSTEM_STATE_BASELINE.md
│   └── HOW_TO_START.txt
│
├── 06-IMPLEMENTATION/                 # Patch & implementation notes
│   ├── SEC-001_IMPLEMENTATION_SUMMARY.txt
│   ├── SEC-001_PATCH_REPORT.md
│   ├── SEC_PATCHES_PHASE3_REPORT.md
│   └── PHASE3_COMPLETION_STATUS.txt
│
├── ARCHIVE/                           # Legacy & archived docs
│   ├── PHASE1_COMPLETE.md
│   ├── PHASE2_COMPLETE.md
│   ├── PHASE3_COMPLETE.md
│   ├── PHASE4_COMPLETE.md
│   ├── PHASE4_LAUNCHER_DESIGN.md
│   ├── PHASE6_COMPLETE.md
│   ├── PHASE6_ERROR_HANDLING_PLAN.md
│   ├── PHASE7_COMPLETE.md
│   ├── PHASE8_COMPLETE.md
│   ├── PHASE9_COMPLETE.md
│   ├── PHASE10_COMPLETE.md
│   ├── ARCHITECTURE_REFACTOR_PLAN.md
│   ├── REFACTOR_COMPLETE.md
│   ├── DEBUG_SESSION_SUMMARY.md
│   └── FINAL_STATUS.md
│
└── 11-14-2025/                        # Old dated folder (see ARCHIVE/)
    ├── FULL_SYSTEM_ARCHITECTURE.md
    ├── HOW_TO_START.txt
    ├── NETWORK_MODE_REQUIREMENTS.md
    ├── QUICKSTART.md
    └── SYSTEM_STATE_BASELINE.md
```

---

## 📖 Document Categories

### Setup & Installation (Start Here!)
1. **START_HERE.md** - Choose your platform
2. **README.md** - Feature overview and usage
3. **00-QUICK_START/QUICKSTART.md** - 5-minute quick start
4. **00-QUICK_START/LAUNCH_METHODS.md** - All launch methods

### Architecture & Design (For Developers)
1. **01-ARCHITECTURE/FULL_SYSTEM_ARCHITECTURE.md** - System design
2. **01-ARCHITECTURE/ARCHITECTURE.md** - Detailed architecture
3. **01-ARCHITECTURE/INTEGRATION_COMPLETE.md** - Module integration
4. **01-ARCHITECTURE/PIPELINE_ANALYSIS.md** - Data flow analysis

### Configuration (For Operations)
1. **02-CONFIGURATION/DATABASE_MANAGEMENT.md** - Database setup
2. **02-CONFIGURATION/PLATFORM_SUPPORT.md** - Platform compatibility
3. **02-CONFIGURATION/NETWORK_MODE_REQUIREMENTS.md** - Network setup
4. **02-CONFIGURATION/ENCRYPTED_SECRETS_GUIDE.md** - Secret management

### Testing & Quality Assurance
1. **03-TESTING/INTEGRATION_TEST_REPORT.txt** - Full test results
2. **03-TESTING/INTEGRATION_TEST_METRICS.md** - Test coverage metrics
3. **03-TESTING/INTEGRATION_TEST_FINDINGS_SUMMARY.txt** - Key findings

### API & Reference
1. **04-REFERENCE/API_REFERENCE.md** - REST endpoints
2. **04-REFERENCE/MODULE_USAGE_ANALYSIS.md** - Module usage patterns
3. **04-REFERENCE/SUPERVISOR_USAGE.md** - Auto-restart mechanism
4. **04-REFERENCE/VPN_BEHAVIOR.md** - VPN detection details

### Security
All security documents are in **[../security/](../security/)**:
- **FINAL_SECURITY_AUDIT_20251114.md** - Latest security audit
- **SECURITY_AUDIT_INDEX.md** - Master vulnerability index
- **findings/** - Individual CVE/finding details

### Deployment & Status
1. **05-DEPLOYMENT/DEPLOYMENT_SUMMARY_20251114.md** - Latest status
2. **05-DEPLOYMENT/VERIFICATION_REPORT.txt** - System verification
3. **05-DEPLOYMENT/SYSTEM_STATE_BASELINE.md** - Baseline configuration

---

## 🎯 Common Use Cases

### "I'm new to CobaltGraph"
→ Read in order:
1. START_HERE.md
2. README.md
3. 00-QUICK_START/QUICKSTART.md

### "I need to set up CobaltGraph on my system"
→ Follow:
1. START_HERE.md (choose your platform)
2. 02-CONFIGURATION/PLATFORM_SUPPORT.md
3. 02-CONFIGURATION/NETWORK_MODE_REQUIREMENTS.md
4. 05-DEPLOYMENT/HOW_TO_START.txt

### "I want to understand the architecture"
→ Read:
1. 01-ARCHITECTURE/FULL_SYSTEM_ARCHITECTURE.md
2. 01-ARCHITECTURE/ARCHITECTURE.md
3. 04-REFERENCE/PIPELINE_ANALYSIS.md
4. 01-ARCHITECTURE/INTEGRATION_COMPLETE.md

### "I need to debug or troubleshoot"
→ Check:
1. README.md (Troubleshooting section)
2. 03-TESTING/INTEGRATION_TEST_FINDINGS_SUMMARY.txt
3. 05-DEPLOYMENT/VERIFICATION_REPORT.txt
4. ../security/ (for security-related issues)

### "I'm deploying to production"
→ Review:
1. 05-DEPLOYMENT/DEPLOYMENT_SUMMARY_20251114.md
2. 02-CONFIGURATION/PLATFORM_SUPPORT.md
3. ../security/ (all audit findings)
4. 02-CONFIGURATION/ENCRYPTED_SECRETS_GUIDE.md

### "I found a security issue"
→ See:
1. ../security/FINAL_SECURITY_AUDIT_20251114.md
2. ../security/findings/ (if specific issue exists)
3. ../security/PATCH_IMPLEMENTATION_REFERENCE.md

---

## 📊 Document Cross-Reference Map

| Document | References | Referenced By |
|----------|-----------|---------------|
| START_HERE.md | README.md, 00-QUICK_START/* | Main entry point |
| README.md | 01-ARCHITECTURE/*, 02-CONFIGURATION/* | All sections |
| FULL_SYSTEM_ARCHITECTURE.md | ARCHITECTURE.md, INTEGRATION_COMPLETE.md | Architecture docs |
| INTEGRATION_TEST_REPORT.txt | Module usage analysis, findings | Testing docs |
| API_REFERENCE.md | ARCHITECTURE.md, dashboard docs | Reference section |
| SECURITY docs | All implementation files | Every module |

---

## 🔄 How to Navigate

### Browse by Topic
- **Installation & Setup:** START_HERE.md → README.md → QUICKSTART.md
- **Architecture:** FULL_SYSTEM_ARCHITECTURE.md → ARCHITECTURE.md → INTEGRATION_COMPLETE.md
- **Configuration:** Platform setup → Database management → Secrets encryption
- **Troubleshooting:** README.md → Integration test reports → Security audit logs

### Search Strategy
- **Feature information:** Use README.md (Features section)
- **Architecture details:** Use 01-ARCHITECTURE/ directory
- **Configuration options:** Use 02-CONFIGURATION/ directory
- **Test results:** Use 03-TESTING/ directory
- **API endpoints:** Use 04-REFERENCE/API_REFERENCE.md
- **Security issues:** Use ../security/ directory

---

## 📝 Document Metadata

| Directory | File Count | Purpose | Last Updated |
|-----------|-----------|---------|--------------|
| 00-QUICK_START/ | 5 files | Startup guides | 2025-11-11 |
| 01-ARCHITECTURE/ | 9 files | System design | 2025-11-11 |
| 02-CONFIGURATION/ | 5 files | Setup docs | 2025-11-15 |
| 03-TESTING/ | 5 files | Test results | 2025-11-14 |
| 04-REFERENCE/ | 8 files | API & features | 2025-11-10 |
| 05-DEPLOYMENT/ | 4 files | Deployment | 2025-11-15 |
| 06-IMPLEMENTATION/ | 4 files | Patches | 2025-11-14 |
| ARCHIVE/ | 15 files | Legacy docs | 2025-11-11 |
| security/ | 22+ files | Audit reports | 2025-11-14 |

**Total Documentation:** 77+ files organized in 9 sections

---

## 🚀 Getting Started Path

```
You are here: docs/INDEX.md
    ↓
Choose your path:
    ├→ I'm new: START_HERE.md → README.md
    ├→ I need to set up: QUICKSTART.md → PLATFORM_SUPPORT.md
    ├→ I want to understand: FULL_SYSTEM_ARCHITECTURE.md → INTEGRATION_COMPLETE.md
    └→ I found an issue: ../security/FINAL_SECURITY_AUDIT_20251114.md
```

---

## 💡 Tips

- **Each document has a purpose** - Read the headers to understand scope
- **Use the cross-reference map** - Jump between related documents
- **ARCHIVE/ is for legacy** - Most recent info in main folders
- **security/ is critical** - Review before production deployment
- **Start simple, go deep** - Begin with START_HERE.md, drill down as needed

---

## 📞 Quick Links

- **Main README:** [README.md](./README.md)
- **Start Here:** [START_HERE.md](./START_HERE.md)
- **Quick Start:** [00-QUICK_START/QUICKSTART.md](./00-QUICK_START/QUICKSTART.md)
- **Architecture:** [01-ARCHITECTURE/FULL_SYSTEM_ARCHITECTURE.md](./01-ARCHITECTURE/FULL_SYSTEM_ARCHITECTURE.md)
- **Security:** [../security/FINAL_SECURITY_AUDIT_20251114.md](../security/FINAL_SECURITY_AUDIT_20251114.md)
- **Testing:** [03-TESTING/INTEGRATION_TEST_REPORT.txt](./03-TESTING/INTEGRATION_TEST_REPORT.txt)

---

**Master Index Created:** 2025-11-17
**Status:** Ready for navigation
**Version:** 1.0
