# CobaltGraph Security Audit Report - TEMPLATE
**Report ID:** SEC-AUDIT-[SCOPE]-[YYYYMMDD]
**Generated:** [DATE] ([TIME] UTC)
**Last Updated:** [DATE] [TIME] UTC
**Auditor:** Claude Code / Security Team
**Scope:** [COMPONENT/MODULE NAME]
**Severity Assessment:** CRITICAL / HIGH / MEDIUM / LOW
**Status:** ACTIVE | COMPLETED | ARCHIVED
**Previous Audit Date:** [YYYY-MM-DD] (if applicable)

---

## Quick Reference

| Metric | Value |
|--------|-------|
| Total Findings | [N] |
| Critical Issues | [N] |
| High Severity | [N] |
| Medium Severity | [N] |
| Low Severity | [N] |
| Audit Duration | [Xh Xm] |
| Lines of Code Reviewed | [N] |
| Coverage Percentage | [X]% |

---

## Executive Summary

[2-3 paragraph summary of audit scope, findings, and immediate risks]

**Audit Timeline:**
- **Initial Assessment:** [YYYY-MM-DD HH:MM UTC]
- **Issue Identification:** [YYYY-MM-DD HH:MM UTC]
- **Patch Development:** [YYYY-MM-DD HH:MM UTC]
- **Report Generated:** [YYYY-MM-DD HH:MM UTC]

---

## Findings Summary with Timestamps

| Finding ID | Issue | Severity | Location | Discovered | Status | Impact |
|-----------|-------|----------|----------|-----------|--------|--------|
| SEC-NNN | [Title] | [Level] | [File:Line] | [DateTime UTC] | UNPATCHED | [Impact] |
| SEC-NNN | [Title] | [Level] | [File:Line] | [DateTime UTC] | PATCHED | [Impact] |

---

## DETAILED FINDINGS WITH DATED ANALYSIS

### SEC-NNN: [SEVERITY] - [FINDING TITLE]
**Discovered:** [YYYY-MM-DD HH:MM:SS UTC]
**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]
**Status:** [UNPATCHED | PATCHED | VERIFIED | N/A]
**Risk Level:** [IMMEDIATE | HIGH | MEDIUM | LOW]
**Related Findings:** [Other SEC-NNN IDs, if applicable]

**Location:** `[file path]:[line numbers]`

**Current State (as of [YYYY-MM-DD]):**
```
[Code snippet showing the vulnerability]
```

**Timeline of Risk:**
- **[YYYY-MM-DD HH:MM]** - Initial discovery
- **[YYYY-MM-DD HH:MM]** - Risk assessment completed
- **[YYYY-MM-DD HH:MM]** - Impact analysis

**Vulnerability Details:**
- [Point 1]
- [Point 2]
- [Point 3]

**Affected Components:**
- Component A
- Component B

**Risk Assessment:**
- **Attack Vector:** [Local | Remote | Physical | Social Engineering]
- **Attack Complexity:** [Low | Medium | High]
- **Privileges Required:** [None | Low | High]
- **User Interaction:** [None | Required]
- **Scope:** [Unchanged | Changed]
- **Confidentiality Impact:** [None | Low | High]
- **Integrity Impact:** [None | Low | High]
- **Availability Impact:** [None | Low | High]
- **CVSS Score:** [X.X] (if applicable)

**Patch: [PATCH TITLE]** (PRIORITY [1|2|3])

```python
# [SEC-NNN PATCH] Implementation code with detailed comments
# Expected result and validation steps
```

Call in appropriate location:
```python
# Implementation location details
```

**Testing Procedures:**
```bash
# Test step 1
# Expected output: [X]

# Test step 2
# Expected output: [X]
```

**Expected Patch Date:** [YYYY-MM-DD] (IMMEDIATE | URGENT | SCHEDULED)

**Verification Checklist:**
- [ ] Patch code reviewed
- [ ] Tests pass locally
- [ ] No regressions introduced
- [ ] Documentation updated
- [ ] Deployed to staging
- [ ] Deployed to production
- [ ] Verified in production

---

## IMPLEMENTATION TIMELINE

### Phase 1: CRITICAL - [Target Date]
**Target Completion:** [YYYY-MM-DD HH:MM UTC]

- [ ] [SEC-NNN] [Description]
- [ ] [SEC-NNN] [Description]

### Phase 2: HIGH - [Target Date]
**Target Completion:** [YYYY-MM-DD HH:MM UTC]

- [ ] [SEC-NNN] [Description]
- [ ] [SEC-NNN] [Description]

### Phase 3: MEDIUM - [Target Date]
**Target Completion:** [YYYY-MM-DD HH:MM UTC]

- [ ] [SEC-NNN] [Description]
- [ ] [SEC-NNN] [Description]

---

## PATCH STATUS TRACKING

### Applied Patches
- ✅ [SEC-NNN] - [Title] ([YYYY-MM-DD HH:MM]) - APPLIED
  - Specific changes made
  - Verification completed
  - Deployment status

### Pending Patches
- ⏳ [SEC-NNN] through [SEC-NNN] - AWAITING REVIEW
  - Description of pending work
  - Dependencies blocking implementation
  - Estimated completion date

### Previous Audit Comparisons
- [Reference to previous audit if applicable]
- Improvements made since last audit
- New issues introduced

---

## Files Modified by This Audit

**Analysis Only (No Changes):**
- `[File path]` - [Description of analysis]
- `[File path]` - [Description of analysis]

**Proposed Changes (Not Yet Applied):**
- `[File path]` - [Description of proposed changes]
- `[File path]` - [Description of proposed changes]

**Previously Modified (This Session):**
- ✅ `[File path]` - [Description of changes already applied]
- ✅ `[File path]` - [Description of changes already applied]

---

## Risk Assessment & Prioritization

### CVSS v3.1 Scoring Framework
Each finding scored on attack vector, complexity, required privileges, and impact.

### Business Impact Analysis
- **Confidentiality Risk:** [Description of data exposure risk]
- **Integrity Risk:** [Description of data modification risk]
- **Availability Risk:** [Description of service disruption risk]

### Compliance Impact
- **OWASP Top 10:** [Applicable categories]
- **NIST Framework:** [Applicable controls]
- **CIS Controls:** [Applicable controls]
- **Industry Standards:** [PCI-DSS | HIPAA | SOC2 | etc.]

---

## References & Standards

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CVSS v3.1 Calculator:** https://www.first.org/cvss/v3.1/calculator
- **NIST SP 800-53:** Security and Privacy Controls
- **CIS Controls:** Critical Security Controls

---

## Document Version History

| Version | Date | Changes | Auditor |
|---------|------|---------|---------|
| 1.0 | [YYYY-MM-DD] | [Initial/Updated] audit - [N] findings | [Name] |
| [X.Y] | [YYYY-MM-DD] | [Changes made] | [Name] |

---

## Appendices

### Appendix A: Code Review Methodology
[Details on how code was reviewed, tools used, manual inspection scope]

### Appendix B: Testing Environment
[Details of testing environment, versions tested, limitations]

### Appendix C: Excluded Components
[Components not included in this audit and why]

### Appendix D: Future Audit Notes
[Notes for future audits, known limitations, areas needing follow-up]

---

## Next Audit Information

**Scheduled Next Audit:** [YYYY-MM-DD] ([Scope])
**Expected Scope Changes:** [What will be reviewed next]
**Follow-up Items:** [Items from this audit to verify in next cycle]

---

**Audit Status:** [ACTIVE | COMPLETED | PENDING PATCHES | ARCHIVED]
**Last Updated:** [YYYY-MM-DD HH:MM:SS UTC]
**Report Location:** [/path/to/report]
**Next Review:** [YYYY-MM-DD] (Auto-scheduled)
