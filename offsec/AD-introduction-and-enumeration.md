# Active Directory Introduction and Enumeration

Active Directory Domain Services, often referred to as Active Directory (AD), is a service that allows system administrators to update and manage operating systems, applications, users, and data access on a large scale. Active Directory is installed with a standard configuration; however, system administrators often customize it to fit the needs of the organization.

From a penetration tester's perspective, Active Directory is very interesting as it typically contains a wealth of information. If we successfully compromise certain objects within the domain, we may be able to take full control over the organization's infrastructure.

In this Learning Module, we will focus on the enumeration aspect of Active Directory. The information we will gather throughout the Module will have a direct impact on the various attacks we will do in the upcoming Attacking Active Directory Authentication and Lateral Movement in Active Directory Modules.

## Table of Contents

- [Introduction to Active Directory](#introduction-to-active-directory)
- [Active Directory Enumeration Using Manual Tools](#active-directory-enumeration-using-manual-tools)
- [Enumerating Active Directory Using Automated Tools](#enumerating-active-directory-using-automated-tools)

---

## Introduction to Active Directory

Active Directory (AD) is both a service and a management layer that stores critical information about an organization's environment—users, groups, computers, and their associated permissions. Each entity is an **object** with specific **attributes** that define its properties and capabilities within the domain.

### Core Components

**Domain Structure:**
- **Domain**: Fundamental AD unit (e.g., `corp.com`) containing all objects
- **Domain Controller (DC)**: Central hub storing all objects, OUs, and attributes
- **DNS Integration**: Critical dependency—DCs typically host authoritative DNS servers

**Object Organization:**
- **Organizational Units (OUs)**: Containers for organizing objects (similar to file system folders)
- **Computer Objects**: Domain-joined servers and workstations
- **User Objects**: Accounts for domain authentication
- **Group Objects**: Collections of users/computers for unified management

### AD Forest and Domain Structure

```mermaid
graph TD
    Forest["AD Forest"] --> Domain1["corp.com"]
    Forest --> Domain2["subsidiary.corp.com"]
    
    Domain1 --> DC1["Domain Controller"]
    Domain1 --> OU1["Sales OU"]
    Domain1 --> OU2["IT OU"]
    
    OU1 --> Users1["User Objects"]
    OU1 --> Computers1["Computer Objects"]
    OU2 --> Users2["User Objects"] 
    OU2 --> Computers2["Computer Objects"]
    
    DC1 --> DNS["DNS Service"]
    DC1 --> LDAP["LDAP Service"]
```

### Privilege Hierarchy

```mermaid
graph TB
    EA["Enterprise Admins<br/>(Forest-wide control)"] --> DA1["Domain Admins<br/>(corp.com)"]
    EA --> DA2["Domain Admins<br/>(subsidiary.corp.com)"]
    
    DA1 --> LA1["Local Admins<br/>(Servers/Workstations)"]
    DA1 --> PowerUsers["Power Users"]
    
    DA2 --> LA2["Local Admins<br/>(Servers/Workstations)"]
    
    LA1 --> DomainUsers1["Domain Users"]
    PowerUsers --> DomainUsers1
    LA2 --> DomainUsers2["Domain Users"]
    
    style EA fill:#ff6b6b
    style DA1 fill:#ffa500
    style DA2 fill:#ffa500
    style LA1 fill:#ffeb3b
    style LA2 fill:#ffeb3b
```

### Communication Protocols
- **LDAP**: Primary protocol for AD queries and enumeration
- **Kerberos**: Authentication protocol
- **DNS**: Name resolution and service location
- **SMB/CIFS**: File sharing and remote access

---

## Enumeration Goals and Methodology

### Scenario: corp.com Domain Assessment
- **Initial Access**: User `stephanie` with RDP permissions
- **Privilege Level**: Standard domain user (non-admin)
- **Target**: Full domain enumeration leading to domain administrator privileges
- **Scope**: corp.com domain within PWK labs

### Key Enumeration Targets
1. **High-Value Groups**: Domain Admins, Enterprise Admins, privileged service accounts
2. **Attack Paths**: User permissions, group memberships, ACLs, trusts
3. **Vulnerable Services**: Kerberoastable accounts, ASREPRoast targets
4. **Lateral Movement**: RDP/WinRM access, local admin rights

### Enumeration Strategy: Iterative Pivoting

```mermaid
flowchart LR
    Start["Initial User<br/>(stephanie)"] --> Enum1["Enumerate<br/>Domain"]
    Enum1 --> Attack1["Attack<br/>Vectors"]
    Attack1 --> NewAccess["Gain New<br/>Access"]
    NewAccess --> Enum2["Re-enumerate<br/>from New Position"]
    Enum2 --> Attack2["New Attack<br/>Vectors"]
    Attack2 --> Target["Domain Admin<br/>Goal"]
    
    Enum2 --> NewAccess2["Additional<br/>Access"]
    NewAccess2 --> Enum3["Continue<br/>Pivoting"]
    
    style Start fill:#e1f5fe
    style Target fill:#ff6b6b
    style Enum1 fill:#f3e5f5
    style Enum2 fill:#f3e5f5
    style Enum3 fill:#f3e5f5
```

### Critical Success Factors
- **Perspective Shifts**: Each compromised account provides unique permissions and access
- **Persistent Re-enumeration**: Repeat enumeration with every new account/computer access
- **Individual User Privileges**: Never dismiss seemingly identical accounts—each may have unique permissions
- **Large Organization Complexity**: More users/computers = more opportunities for privilege escalation

This methodology ensures comprehensive coverage and maximizes the chance of finding privilege escalation paths in complex AD environments.

---
