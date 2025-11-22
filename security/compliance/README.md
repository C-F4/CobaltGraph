# Compliance Directory

**Location:** `security/compliance/`
**Created:** 2025-11-14
**Status:** Ready for mapping generation

---

## Overview

This directory will contain **compliance framework mappings** that connect security findings to industry standards and regulations. Each mapping shows how CobaltGraph vulnerabilities relate to compliance requirements.

---

## Planned Compliance Documents

### OWASP Top 10 (2021)

**File:** `OWASP_TOP_10_MAPPING.md` [PLANNED]

Maps findings to:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging & Monitoring Failures
- A10: SSRF

### NIST SP 800-53 (Revision 5)

**File:** `NIST_SP_800_53_MAPPING.md` [PLANNED]

Maps findings to control families:
- AC: Access Control
- AT: Awareness and Training
- AU: Audit and Accountability
- CA: Assessment, Authorization, and Monitoring
- CM: Configuration Management
- CP: Contingency Planning
- IA: Identification and Authentication
- IR: Incident Response
- MA: Maintenance
- MP: Media Protection
- PS: Personnel Security
- RA: Risk Assessment
- SA: System and Services Acquisition
- SC: System and Communications Protection
- SI: System and Information Integrity

### CIS Controls (v8)

**File:** `CIS_CONTROLS_MAPPING.md` [PLANNED]

Maps findings to CIS Controls:
- 1: Inventory and Control of Enterprise Assets
- 2: Inventory and Control of Software Assets
- 3: Data Protection
- 4: Secure Configuration Management
- 5: Access Control Management
- 6: Secure Asset Management
- 7: Continuous Vulnerability Management
- 8: Audit Log Management
- 9: Email and Web Browser Protections
- 10: Malware Defenses
- 11: Data Recovery
- 12: Network Infrastructure Management
- 13: Network Monitoring and Defense
- 14: Security Awareness and Skills Training
- 15: Service Provider Management
- 16: Application Software Security
- 17: Secure Systems Development
- 18: Penetration Testing

### Additional Frameworks (Future)

- `PCI_DSS_MAPPING.md` - Payment Card Industry Data Security Standard
- `SOC2_MAPPING.md` - Service Organization Control 2
- `ISO_27001_MAPPING.md` - ISO/IEC 27001 Information Security
- `HIPAA_MAPPING.md` - Health Insurance Portability and Accountability Act
- `GDPR_MAPPING.md` - General Data Protection Regulation

---

## Example Mapping Format

```markdown
# OWASP Top 10 Mapping

## A02: Cryptographic Failures

Maps to findings:
- SEC-005: Plaintext credential storage
- SEC-008: No encryption at rest

Risk: API keys stored unencrypted on disk

Mitigation: Implement encrypted storage, use environment variables

## A07: Authentication Failures

Maps to findings:
- SEC-001: World-readable auth files
- SEC-004: Default credentials
- SEC-006: Credential masking

Risk: Dashboard authentication can be bypassed

Mitigation: Enforce strong passwords, secure file permissions

## A09: Logging and Monitoring Failures

Maps to findings:
- SEC-002: Authorization header in logs
- SEC-003: Auth exception logging

Risk: Sensitive data exposed in log files

Mitigation: Sanitize logging, mask credentials
```

---

## Current Findings Mapped

### SEC-001: World-Readable Config Files
- **OWASP:** A04 (Insecure Design), A05 (Security Misconfiguration)
- **NIST:** CM-5, CM-6 (Configuration Management)
- **CIS:** 2 (Inventory Software), 4 (Secure Config)

### SEC-002: Authorization Header in Logs
- **OWASP:** A09 (Logging and Monitoring), A02 (Cryptographic Failures)
- **NIST:** AU-2, AU-12 (Audit and Accountability)
- **CIS:** 8 (Audit Log Management)

### SEC-003: Auth Exception Logging
- **OWASP:** A09 (Logging and Monitoring)
- **NIST:** AU-2 (Audit Events)
- **CIS:** 8 (Audit Log Management)

### SEC-004: Default Credentials
- **OWASP:** A07 (Authentication Failures)
- **NIST:** IA-5 (Authentication Mechanisms)
- **CIS:** 5 (Access Control Management)

### SEC-005: Plaintext Credential Storage
- **OWASP:** A02 (Cryptographic Failures), A05 (Security Misconfiguration)
- **NIST:** SC-28 (Protection of Information at Rest)
- **CIS:** 3 (Data Protection)

### SEC-006: Credential Masking
- **OWASP:** A09 (Logging and Monitoring)
- **NIST:** AU-2, SI-4 (Logging)
- **CIS:** 8 (Audit Log Management)

### SEC-007: Environment Variable Exposure
- **OWASP:** A02 (Cryptographic Failures), A04 (Insecure Design)
- **NIST:** SC-7 (Boundary Protection)
- **CIS:** 6 (Secure Asset Management)

### SEC-008: No Encryption Support
- **OWASP:** A02 (Cryptographic Failures)
- **NIST:** SC-28 (Information Protection)
- **CIS:** 3 (Data Protection)

---

## How to Use Compliance Mapping

### For Auditors
1. Review applicable standards for organization
2. Check mapping documents
3. Verify patches implement controls
4. Document compliance status

### For Developers
1. Before coding: Check compliance requirements
2. During coding: Reference control mappings
3. After testing: Verify compliance met
4. On deployment: Update compliance tracker

### For Management
1. Understand regulatory impact
2. Prioritize high-compliance findings
3. Plan remediation timeline
4. Report to stakeholders

---

## Compliance Reporting

### Quarterly Compliance Report (Future)

Will include:
- Summary of findings vs. standards
- Control implementation status
- Risk assessment by framework
- Remediation timeline
- Executive summary

### Annual Compliance Assessment

Will include:
- Full standards coverage
- Audit trail documentation
- Gap analysis
- Improvement plan
- Certification readiness

---

## Standards Reference

- **OWASP:** https://owasp.org/www-project-top-ten/
- **NIST:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **CIS:** https://www.cisecurity.org/cis-controls/
- **PCI-DSS:** https://www.pcisecuritystandards.org/
- **SOC2:** https://www.aicpa.org/soc2
- **ISO 27001:** https://www.iso.org/standard/27001

---

## Next Steps

1. Generate OWASP mapping (Priority: HIGH)
2. Generate NIST mapping (Priority: HIGH)
3. Generate CIS mapping (Priority: MEDIUM)
4. Determine applicable standards for organization
5. Create quarterly compliance reports

---

**Last Updated:** 2025-11-14
**Status:** Template ready, content generation pending
**Priority:** Generate OWASP/NIST mappings before Phase 2 patches
