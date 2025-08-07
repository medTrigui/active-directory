# Hardening Active Directory

---

## Table of Contents

1. [Introduction](#introduction)
2. [Step One: Document and Audit](#step-one-document-and-audit)
3. [People: Human-Focused Hardening](#people-human-focused-hardening)
4. [Protected Users Group](#protected-users-group)
5. [Processes: Policy and Procedure](#processes-policy-and-procedure)
6. [Technology: Technical Controls](#technology-technical-controls)
7. [Additional AD Auditing Techniques](#additional-ad-auditing-techniques)
    - [Active Directory Explorer (AD Explorer)](#active-directory-explorer-ad-explorer)
    - [PingCastle](#pingcastle)
    - [Group3r](#group3r)
    - [ADRecon](#adrecon)
8. [Protections by TTP (MITRE Mapping)](#protections-by-ttp-mitre-mapping)
9. [MITRE ATT&CK Framework Example](#mitre-attck-framework-example)
10. [Final Notes](#final-notes)

---

## Introduction

Active Directory (AD) hardening is essential to prevent lateral movement, privilege escalation, and unauthorized access to sensitive resources. The most effective defenses are often foundational: documentation, auditing, and basic security controls. These measures are more impactful than any EDR or SIEM if the basics are not in place.

---

## Step One: Document and Audit

**Regularly audit and document:**
- OU, computer, user, and group naming conventions
- DNS, network, and DHCP configurations
- All GPOs and their assignments
- FSMO role assignments
- Application inventory
- Enterprise host inventory and locations
- All trust relationships (internal and external)
- Users with elevated permissions

**Recommendation:** Perform a full audit at least annually, ideally every few months.

---

## People: Human-Focused Hardening

- Enforce strong password policies (disallow common words, use password filters, encourage password managers)
- Rotate service account passwords regularly
- Disallow local admin access on user workstations unless necessary
- Disable the default RID-500 local admin account; use LAPS for admin password rotation
- Implement tiered administration (separate admin accounts for admin tasks)
- Restrict privileged group membership to only those who need it
- Use the Protected Users group where appropriate
- Disable Kerberos delegation for admin accounts

---

## Protected Users Group

- **Purpose:** Restricts what privileged users can do and how their credentials are handled.
- **Protections:**
  - No delegation (constrained/unconstrained)
  - No plaintext credentials cached (CredSSP, Digest)
  - No NTLM, DES, or RC4 authentication
  - No TGT renewal beyond 4 hours
- **Caution:** Can cause authentication issues; test before broad deployment.

**View group members:**
```powershell
Get-ADGroup -Identity "Protected Users" -Properties Members
```

---

## Processes: Policy and Procedure

- Maintain and enforce AD asset management policies
- Use asset tags and periodic inventories
- Enforce access control policies (provisioning/de-provisioning, MFA)
- Use gold images and baseline security guidelines for new hosts
- Regularly clean up AD (remove stale/disabled accounts, decommission legacy systems)
- Schedule regular audits of users, groups, and hosts
- Define and test disaster recovery plans

---

## Technology: Technical Controls

- Periodically scan AD for misconfigurations (BloodHound, PingCastle, Grouper)
- Prevent password storage in AD description fields
- Review SYSVOL for scripts with credentials
- Use gMSA/MSA for service accounts (mitigates Kerberoasting)
- Disable unconstrained delegation
- Restrict direct DC access (use jump hosts)
- Set `ms-DS-MachineAccountQuota` to 0 to prevent user-created machine accounts
- Disable print spooler and NTLM on DCs if possible
- Require SSL and enable Extended Protection for Authentication on CA web services
- Enable SMB and LDAP signing
- Restrict anonymous access (set `RestrictNullSessAccess` to 1)
- Schedule regular penetration tests and AD security assessments
- Test backups and disaster recovery plans

---

## Additional AD Auditing Techniques

### Active Directory Explorer (AD Explorer)

- **Tool:** Sysinternals AD Explorer
- **Purpose:** Advanced AD viewer/editor, snapshotting, and offline analysis.
- **Usage:**
  1. Launch AD Explorer and connect with valid domain credentials.
  2. Browse and search AD objects, attributes, and permissions.
  3. Take a snapshot: `File → Create Snapshot` for offline or before/after comparison.
- **Benefits:** 
  - Visualize AD structure and permissions.
  - Compare changes over time.
  - Useful for reporting and incident response.

---

### PingCastle

- **Tool:** PingCastle.exe (Windows)
- **Purpose:** Rapid AD security assessment, risk scoring, and reporting.
- **Usage:**
  - Run interactively: `PingCastle.exe`
  - Healthcheck: `PingCastle.exe --healthcheck --server <DC>`
  - Export: `PingCastle.exe --export --server <DC>`
- **Features:**
  - Generates HTML reports with risk scores, maps, and anomaly tables.
  - Scanner options for ACLs, antivirus, local admin, null sessions, SMB, etc.
- **Benefits:**
  - Quick domain security overview.
  - Visualizes trusts, delegation, and vulnerabilities.
  - Useful for both red and blue teams.

---

### Group3r

- **Tool:** group3r.exe (Windows, domain-joined)
- **Purpose:** Audit GPOs for misconfigurations and vulnerabilities.
- **Usage:**
  - Output to file: `group3r.exe -f <output.log>`
  - Output to stdout: `group3r.exe -s`
  - Help: `group3r.exe -h`
- **Features:**
  - Finds weak GPO settings, registry keys, and user rights assignments.
  - Indented output for GPO → Policy → Finding.
- **Benefits:**
  - Identifies GPO paths and settings that may be missed by other tools.
  - Useful for both attack and defense.

---

### ADRecon

- **Tool:** ADRecon.ps1 (PowerShell)
- **Purpose:** Comprehensive AD data collection and reporting.
- **Usage:**
  - Run: `./ADRecon.ps1`
  - Output: HTML report and CSV files in a timestamped directory.
  - Generate Excel report: `./ADRecon.ps1 -GenExcel -InputFolder <report-folder>`
- **Features:**
  - Collects data on domains, trusts, users, groups, OUs, GPOs, DNS, printers, BitLocker, LAPS, etc.
  - Useful for both red and blue teams.
- **Benefits:**
  - One-stop shop for AD inventory and reporting.
  - Helps identify misconfigurations, stale objects, and privilege issues.

---

## Protections by TTP (MITRE Mapping)

| TTP                        | MITRE Tag   | Description & Defense Example                                                                 |
|----------------------------|-------------|----------------------------------------------------------------------------------------------|
| External Reconnaissance    | T1589       | Scrub public documents, control job postings, monitor public data exposure                   |
| Internal Reconnaissance    | T1595       | Monitor for network scans, use NIDS/SIEM, tune firewalls/EDR                                 |
| Poisoning                  | T1557       | Enforce SMB/LDAP signing, use strong encryption, block relays                                |
| Password Spraying          | T1110.003   | Monitor Event IDs 4624/4648, enforce lockout/MFA, strong password policies                   |
| Credentialed Enumeration   | TA0006      | Monitor for unusual CLI/RDP/file movement, use network segmentation, detect anomalous activity|
| Living Off The Land (LOTL) | N/A         | Baseline user/network behavior, use AppLocker, monitor for shell usage                       |
| Kerberoasting              | T1558.003   | Use strong Kerberos encryption, gMSA for services, audit group memberships                   |

---

## MITRE ATT&CK Framework Example

- **Tactic:** TA0006 Credential Access
- **Technique:** T1558 Steal or Forge Kerberos Tickets
- **Sub-technique:** T1558.003 Kerberoasting

The MITRE ATT&CK framework provides a mapping from high-level tactics to specific techniques and sub-techniques. Use it to understand, defend, and report on AD attack and defense scenarios.

---

## Final Notes

- These are foundational defenses; adapt and expand based on your environment.
- Understanding both attack and defense improves your effectiveness as a security professional.
- Always test changes in a lab before deploying to production.
- Regularly review, update, and practice your hardening and incident response procedures.
- Use auditing tools to provide evidence and support for remediation efforts.

---


