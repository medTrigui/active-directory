# Domain Trusts

---

## Overview

Domain trusts establish authentication relationships between domains/forests, allowing users to access resources across domain boundaries. Common in M&A scenarios, MSP relationships, and multi-domain environments.

**Key Security Risks:**
- Misconfigured trusts create unintended attack paths
- Transitive trusts extend access beyond intended scope
- Bidirectional trusts increase attack surface
- Trust relationships often overlooked in security reviews

---

## Trust Types & Properties

### Trust Types

| Trust Type    | Description                                              | Scope                    | Transitive |
|---------------|----------------------------------------------------------|--------------------------|------------|
| **Parent-Child** | Between domains in same forest                        | Intra-forest             | Yes        |
| **Cross-Link**   | Between child domains (speeds authentication)         | Intra-forest             | Yes        |
| **External**     | Between separate domains in different forests          | Inter-forest             | No         |
| **Tree-Root**    | Between forest root and new tree root                 | Intra-forest             | Yes        |
| **Forest**       | Between two forest root domains                        | Inter-forest             | Yes        |
| **ESAE**         | Bastion forest for AD management                       | Administrative           | Varies     |

### Trust Properties

| Property        | Description                                              |
|-----------------|----------------------------------------------------------|
| **Transitive**  | Trust extends to domains the trusted domain trusts      |
| **Non-Transitive** | Trust limited to direct relationship only            |
| **One-Way**     | Users in trusted domain access trusting domain resources |
| **Bidirectional** | Users from both domains can access each other's resources |

---

## Trust Enumeration Commands

### Method 1: Built-in AD PowerShell Module

```powershell
# Import AD module
Import-Module ActiveDirectory

# Enumerate all trusts
Get-ADTrust -Filter *

# Get specific trust details
Get-ADTrust -Identity "DOMAIN.LOCAL"
```

### Method 2: PowerView

```powershell
# Basic trust enumeration
Get-DomainTrust

# Detailed trust mapping (shows both directions)
Get-DomainTrustMapping

# Enumerate users in trusted domain
Get-DomainUser -Domain TRUSTED.DOMAIN.LOCAL | select SamAccountName

# Enumerate groups in trusted domain
Get-DomainGroup -Domain TRUSTED.DOMAIN.LOCAL

# Find foreign group members
Get-DomainForeignGroupMember

# Find foreign users
Get-DomainForeignUser
```

### Method 3: netdom (Built-in Windows Tool)

```cmd
# Query domain trusts
netdom query /domain:DOMAIN.LOCAL trust

# Query domain controllers
netdom query /domain:DOMAIN.LOCAL dc

# Query workstations and servers
netdom query /domain:DOMAIN.LOCAL workstation
```

### Method 4: nltest (Built-in Windows Tool)

```cmd
# Display trust relationships
nltest /domain_trusts

# Display domain controllers
nltest /dclist:DOMAIN.LOCAL

# Test secure channel
nltest /sc_query:DOMAIN.LOCAL
```

---

## Trust Analysis

### Key Properties to Analyze

| Property                | Security Implication                                     |
|-------------------------|----------------------------------------------------------|
| **Direction**           | Bidirectional = higher risk, more attack paths          |
| **ForestTransitive**    | True = forest trust, can traverse entire forest         |
| **IntraForest**         | True = parent-child, False = external/forest trust      |
| **SIDFilteringQuarantined** | False = SID filtering disabled (high risk)         |
| **SelectiveAuthentication** | False = all users can authenticate (higher risk)   |

### Sample Analysis Output

```powershell
# Example Get-ADTrust output analysis
Direction               : BiDirectional          # ⚠️ Two-way access
DisallowTransivity      : False                  # ✅ Transitive allowed
ForestTransitive        : True                   # ⚠️ Forest trust
IntraForest             : False                  # ⚠️ External domain
SIDFilteringQuarantined : False                  # 🚨 SID filtering disabled
SelectiveAuthentication : False                  # ⚠️ All users can auth
```

---

## Cross-Domain Enumeration

### Enumerate Trusted Domain Users

```powershell
# PowerView - enumerate users in trusted domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName, Description

# Find privileged users in trusted domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL -AdminCount | select SamAccountName

# Find service accounts in trusted domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL -SPN | select SamAccountName, ServicePrincipalNames
```

### Enumerate Trusted Domain Groups

```powershell
# Get domain groups
Get-DomainGroup -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

# Find privileged groups
Get-DomainGroup -Domain LOGISTICS.INLANEFREIGHT.LOCAL -AdminCount | select SamAccountName

# Get group members
Get-DomainGroupMember -Domain LOGISTICS.INLANEFREIGHT.LOCAL -Identity "Domain Admins"
```

### Find Cross-Domain Permissions

```powershell
# Find foreign group members (users from other domains in local groups)
Get-DomainForeignGroupMember

# Find foreign users (users from other domains with local permissions)
Get-DomainForeignUser

# Find ACLs with foreign security principals
Find-DomainObjectPropertyOutlier
```

---

## BloodHound Trust Analysis

### Useful BloodHound Queries

```cypher
-- Map Domain Trusts (pre-built query)
MATCH (n:Domain)-[r:TrustedBy]->(m:Domain) RETURN n,r,m

-- Find shortest path across trusts to Domain Admins
MATCH (n:User {domain:"TRUSTED.LOCAL"}), (m:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}), 
p=shortestPath((n)-[*1..]->(m)) RETURN p

-- Find users with cross-domain admin rights
MATCH (u:User)-[r:AdminTo]->(c:Computer) 
WHERE u.domain <> c.domain RETURN u,r,c
```

---

## Attack Scenarios

### Common Trust Attack Paths

| Scenario | Description | Risk Level |
|----------|-------------|------------|
| **Child → Parent Escalation** | Compromise child domain → escalate to parent | High |
| **Forest Trust Abuse** | Compromise trusted forest → access trusting forest | High |
| **SID History Injection** | Inject SIDs from trusted domain | Critical |
| **Golden/Silver Tickets** | Cross-domain ticket attacks | Critical |
| **Cross-Domain Kerberoasting** | Kerberoast in trusted domains | Medium |

### Trust Security Best Practices

- **Minimize Trust Relationships**: Only create necessary trusts
- **Enable SID Filtering**: Prevent SID injection attacks  
- **Use Selective Authentication**: Limit which users can authenticate
- **Regular Trust Audits**: Review and remove unnecessary trusts
- **Monitor Cross-Domain Activity**: Log and alert on cross-domain authentication
- **Separate Administrative Accounts**: Don't use same admins across trusts

---

## Quick Reference Commands

```powershell
# Quick trust discovery
Get-DomainTrust
Get-ADTrust -Filter *
nltest /domain_trusts

# Cross-domain user enum
Get-DomainUser -Domain TRUSTED.LOCAL | select SamAccountName

# Find foreign permissions
Get-DomainForeignGroupMember
Get-DomainForeignUser

# BloodHound trust mapping
Map Domain Trusts (pre-built query)
```

---

## Notes

- **Always verify scope**: Ensure trusted domains are in scope before testing
- **Document all trusts**: Include in reports even if not exploited
- **Check trust age**: Old trusts may be forgotten and misconfigured
- **Test both directions**: Bidirectional trusts = double the attack surface
