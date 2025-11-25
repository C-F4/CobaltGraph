# CobaltGraph Security Directory Manifest
**Generated:** 2025-11-14 19:16:32 UTC
**Last Updated:** 2025-11-14 19:16:32 UTC
**Status:** ACTIVE INVENTORY

---

## Complete File Inventory

### Core Audit Documents (ROOT)

| File | Type | Size | Created | Updated | Purpose |
|------|------|------|---------|---------|---------|
| `README.md` | Guide | 9.8 KB | 2025-11-14 | 2025-11-14 | Directory overview and quick start |
| `SECURITY_AUDIT_INDEX.md` | Index | 5.8 KB | 2025-11-14 | 2025-11-14 | Master audit tracker (all reports) |
| `SECURITY_AUDIT_CONFIG_20251114.md` | Report | 17.5 KB | 2025-11-14 | 2025-11-14 | CONFIG component security audit |
| `SECURITY_AUDIT_TEMPLATE.md` | Template | 6.5 KB | 2025-11-14 | 2025-11-14 | Reusable audit report template |
| `CONFIG_DIRECTORY_SECURITY_SUMMARY.txt` | Summary | 7.0 KB | 2025-11-14 | 2025-11-14 | 5-liner + extended summary |
| `MANIFEST.md` | Inventory | (this file) | 2025-11-14 | 2025-11-14 | This document inventory |

**Total Core Documents:** 6 files (46.6 KB)

---

### Reports Directory Structure

```
reports/
└── 2025/
    └── 11/
        ├── SECURITY_AUDIT_CONFIG_20251114.md → (link to root)
        └── MASTER_INDEX.md → (link to SECURITY_AUDIT_INDEX.md)
```

**Purpose:** Organized by year/month for historical tracking and archival

**Scheduled Reports:**
- ✅ **2025-11-14** - CONFIG audit (COMPLETED)
- 📅 **2025-11-21** - ORCHESTRATOR audit (SCHEDULED)
- 📅 **2025-11-28** - CAPTURE audit (SCHEDULED)
- 📅 **2025-12-05** - DATABASE audit (SCHEDULED)
- 📅 **2025-12-12** - INTELLIGENCE audit (SCHEDULED)
- 📅 **2025-12-19** - DASHBOARD audit (SCHEDULED)

---

### Findings Directory Structure

```
findings/
├── CRITICAL/
│   ├── SEC-001_world_readable_config.md       (PLANNED)
│   ├── SEC-002_auth_header_logging.md         (PLANNED)
│   └── SEC-003_auth_exception_logging.md      (PLANNED)
├── HIGH/
│   ├── SEC-004_default_credentials.md         (PLANNED)
│   └── SEC-005_plaintext_storage.md           (PLANNED)
├── MEDIUM/
│   ├── SEC-006_credential_masking.md          (PLANNED)
│   ├── SEC-007_env_var_exposure.md            (PLANNED)
│   └── SEC-008_no_encryption.md               (PLANNED)
└── LOW/
    └── (None currently)
```

**Purpose:** Individual finding detail pages (to be populated from audit reports)

**Status:** Placeholders ready for detail expansion

---

### Patches Directory Structure

```
patches/
├── SEC-001_enforce_file_permissions.py        (PLANNED)
├── SEC-002_sanitize_auth_logging.py           (PLANNED)
├── SEC-003_redact_exceptions.py               (PLANNED)
├── SEC-004_validate_passwords.py              (PLANNED)
├── SEC-005_encrypted_secrets_guide.md         (PLANNED)
├── SEC-006_mask_credentials.py                (PLANNED)
├── SEC-007_clear_env_vars.py                  (PLANNED)
└── SEC-008_encryption_support.md              (PLANNED)
```

**Purpose:** Standalone patch implementation files

**Status:** Code snippets available in SECURITY_AUDIT_CONFIG_20251114.md

---

### Compliance Directory Structure

```
compliance/
├── OWASP_TOP_10_MAPPING.md                    (PLANNED)
├── NIST_SP_800_53_MAPPING.md                  (PLANNED)
├── CIS_CONTROLS_MAPPING.md                    (PLANNED)
├── PCI_DSS_MAPPING.md                         (PLANNED)
└── SOC2_MAPPING.md                            (PLANNED)
```

**Purpose:** Map findings to compliance frameworks

**Status:** Templates ready, content to be generated

---

## Quick Navigation

### 🔴 For Critical Issues
→ `SECURITY_AUDIT_CONFIG_20251114.md` (Lines: SEC-001, SEC-002, SEC-003)
→ `findings/CRITICAL/` (When expanded)

### 🟠 For High Severity
→ `SECURITY_AUDIT_CONFIG_20251114.md` (Lines: SEC-004, SEC-005)
→ `findings/HIGH/` (When expanded)

### 🟡 For Medium Issues
→ `SECURITY_AUDIT_CONFIG_20251114.md` (Lines: SEC-006, SEC-007, SEC-008)
→ `findings/MEDIUM/` (When expanded)

### 📊 For Audit History
→ `SECURITY_AUDIT_INDEX.md` (Master timeline)
→ `reports/2025/11/` (Historical reports)

### 🔧 For Patch Implementation
→ `SECURITY_AUDIT_CONFIG_20251114.md` (Full patch code)
→ `patches/` (When extracted)

### 📋 For Compliance
→ `compliance/` (When populated)

---

## File Permissions Summary

```
security/
  README.md                                 -rw-------  (600)
  SECURITY_AUDIT_*.md                       -rw-------  (600)
  CONFIG_DIRECTORY_SECURITY_SUMMARY.txt     -rw-------  (600)
  MANIFEST.md                               -rw-------  (600)

  subdirectories/                           drwxr-xr-x  (755)
  findings/CRITICAL/                        drwxr-xr-x  (755)
  findings/HIGH/                            drwxr-xr-x  (755)
  findings/MEDIUM/                          drwxr-xr-x  (755)
  findings/LOW/                             drwxr-xr-x  (755)
  patches/                                  drwxr-xr-x  (755)
  reports/                                  drwxr-xr-x  (755)
  compliance/                               drwxr-xr-x  (755)
```

**Security Note:** Document files are readable only by owner (600) due to sensitive content.

---

## Storage Statistics

| Category | Files | Size | Notes |
|----------|-------|------|-------|
| Core Audits | 6 | 46.6 KB | Main audit documents |
| Findings | 0 | 0 KB | Awaiting expansion |
| Patches | 0 | 0 KB | Awaiting extraction |
| Compliance | 0 | 0 KB | Awaiting generation |
| **TOTAL** | **6** | **46.6 KB** | Will grow weekly |

**Growth Projection:**
- +1 new audit report per week (~17 KB)
- +8 new findings per audit cycle (~3-5 KB each)
- +1 compliance mapping per quarter (~10 KB)
- Expected: ~50 KB/month growth

---

## Document Cross-References

### Within Security Directory
```
SECURITY_AUDIT_INDEX.md
  ├─ References → SECURITY_AUDIT_CONFIG_20251114.md
  ├─ References → SECURITY_AUDIT_TEMPLATE.md (for future audits)
  ├─ References → reports/2025/11/ (archived copies)
  └─ References → findings/ (when expanded)

SECURITY_AUDIT_CONFIG_20251114.md
  ├─ References → CONFIG_DIRECTORY_SECURITY_SUMMARY.txt
  ├─ References → src/core/config.py (in main codebase)
  ├─ References → config/auth.conf (in main codebase)
  ├─ References → config/threat_intel.conf (in main codebase)
  └─ References → src/dashboard/server.py (in main codebase)
```

### To Main Codebase
- `src/core/config.py` - Configuration system audit
- `src/dashboard/server.py` - Dashboard security audit
- `config/*.conf` - Configuration files
- `src/core/orchestrator.py` - Orchestrator security audit (2025-11-21)

---

## Version Control

### Audit Reports Versioning

All reports use timestamped naming: `SECURITY_AUDIT_[SCOPE]_[YYYYMMDD].md`

```
SECURITY_AUDIT_CONFIG_20251114.md        (2025-11-14 - Week 46)
SECURITY_AUDIT_ORCHESTRATOR_20251121.md  (2025-11-21 - Week 47) [PLANNED]
SECURITY_AUDIT_CAPTURE_20251128.md       (2025-11-28 - Week 48) [PLANNED]
SECURITY_AUDIT_DATABASE_20251205.md      (2025-12-05 - Week 49) [PLANNED]
SECURITY_AUDIT_INTELLIGENCE_20251212.md  (2025-12-12 - Week 50) [PLANNED]
SECURITY_AUDIT_DASHBOARD_20251219.md     (2025-12-19 - Week 51) [PLANNED]
```

### Index Updates

`SECURITY_AUDIT_INDEX.md` is updated with each new audit:
- ✅ Current: 1 report (CONFIG)
- 📅 Expected: 6+ reports by end of 2025

---

## Maintenance & Updates

### Weekly (Every Wednesday)

- [ ] Generate new audit report
- [ ] Add to SECURITY_AUDIT_INDEX.md
- [ ] Create symbolic link in `reports/[YYYY]/[MM]/`
- [ ] Update this MANIFEST.md

### Monthly (1st of month)

- [ ] Review all findings
- [ ] Check patch implementation status
- [ ] Archive completed audits (if >1 month old)
- [ ] Generate trend report

### Quarterly

- [ ] Comprehensive security review
- [ ] Compliance mapping update
- [ ] Vulnerability trend analysis
- [ ] Next quarter planning

---

## How to Use This Manifest

1. **Find Documents:** Look up file name in table above
2. **Understand Organization:** Check subdirectory structure
3. **Get Quick Answers:** Use "Quick Navigation" section
4. **Track Changes:** Note "Last Updated" timestamp
5. **Plan Work:** Review "Scheduled Reports" timeline

---

## Related Documentation

**In security/ directory:**
- `README.md` - Getting started guide
- `SECURITY_AUDIT_TEMPLATE.md` - Create new audits
- `SECURITY_AUDIT_INDEX.md` - Audit history

**In main codebase:**
- `/src/core/config.py` - Configuration system
- `/config/auth.conf` - Authentication settings
- `/config/threat_intel.conf` - API keys
- `/.gitignore` - Prevents credential commits

---

## Contact & Support

**Primary Contact:** Claude Code Security Analysis
**Update Frequency:** Weekly audits (Wednesday 1:00 AM UTC)
**Critical Issues:** Immediate escalation
**General Questions:** See `README.md`

---

## Audit Status Summary

**Current Status:** 🔴 RED - Critical issues pending remediation

| Category | Count | Status |
|----------|-------|--------|
| Critical Issues | 3 | UNPATCHED - Target 2025-11-14 19:00 UTC |
| High Issues | 2 | UNPATCHED - Target 2025-11-14 20:00 UTC |
| Medium Issues | 3 | UNPATCHED - Target 2025-11-15 12:00 UTC |
| Total Findings | 8 | AWAITING IMPLEMENTATION |

**Next Phase:** Patch implementation (Phase 1 CRITICAL - IMMEDIATE)

---

## Document Metadata

| Property | Value |
|----------|-------|
| Directory Created | 2025-11-14 19:14 UTC |
| Manifest Created | 2025-11-14 19:16 UTC |
| Total Files | 6 (core), 0 (subdirs) |
| Total Size | 46.6 KB |
| Permission Model | 600 (documents), 755 (directories) |
| Update Frequency | Weekly |
| Archive Strategy | Monthly (>30 days) |
| Retention Policy | 2 years minimum |

---

**Last Generated:** 2025-11-14 19:16:32 UTC
**Next Update:** 2025-11-21 (Weekly Audit)
**Status:** ACTIVE INVENTORY
