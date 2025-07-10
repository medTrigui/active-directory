# AD Users

This document covers Active Directory users.

## User and Machine Accounts

User accounts are created both locally and in Active Directory (AD) to allow people or services to log on and access resources. When a user logs in, the system verifies their password and creates an access token, which includes the user's identity and group memberships. Groups simplify administration by allowing privileges to be assigned collectively.

### Account Types in Windows Environments
| Account Type      | Description                                                                                 |
|------------------|---------------------------------------------------------------------------------------------|
| Local User       | Exists only on a specific host; rights apply only to that host.                              |
| Domain User      | Managed by AD; can log in to any domain-joined host and access domain resources.             |
| Service Account  | Used to run applications/services with specific privileges.                                  |
| Machine Account  | Represents computers in AD; has similar rights to a standard domain user.                    |
| Disabled Account | Deactivated but not deleted; often kept for audit purposes (e.g., FORMER EMPLOYEES OU).      |

### Default Local Accounts
| Account Name   | Description                                                                                   |
|---------------|-----------------------------------------------------------------------------------------------|
| Administrator | First account created; full control; cannot be deleted or locked, but can be disabled/renamed. |
| Guest         | Disabled by default; allows temporary login with limited rights.                               |
| SYSTEM        | Used by OS for internal functions; highest permission level; not visible in User Manager.      |
| Network Service | Runs Windows services; presents credentials to remote services.                              |
| Local Service | Runs Windows services with minimal privileges; presents anonymous credentials to network.      |

---

## Domain Users

Domain users are granted rights from the domain to access resources (file servers, printers, intranet, etc.) based on their account or group memberships. They can log in to any domain-joined host. Special accounts include:
- **KRBTGT**: Built-in service account for Kerberos Key Distribution; critical for domain authentication and a common attack target.

### User Naming Attributes
| Attribute         | Description                                                                                 |
|-------------------|--------------------------------------------------------------------------------------------|
| UserPrincipalName | Primary logon name (usually email address).                                                |
| ObjectGUID        | Unique identifier for the user; never changes.                                             |
| SAMAccountName    | Logon name for legacy Windows clients/servers.                                             |
| objectSID         | Security Identifier; identifies user and group memberships.                                |
| sIDHistory        | Previous SIDs for migrated users; used in domain migrations.                               |

### Example: Common User Attributes
```powershell
PS C:\htb> Get-ADUser -Identity htb-student

DistinguishedName : CN=htb student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : htb
Name              : htb student
ObjectClass       : user
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : htb-student
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname           : student
UserPrincipalName : htb-student@INLANEFREIGHT.LOCAL
```

---

## Domain-Joined vs. Non-Domain-Joined Machines

| Machine Type         | Description                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------|
| Domain-Joined       | Managed centrally; receives policies/updates from DC; users can log in from any domain host.   |
| Non-Domain-Joined   | Standalone/workgroup; managed locally; user accounts exist only on that host.                  |

- **Domain-joined**: Centralized management, easier resource sharing, and policy enforcement.
- **Non-domain-joined**: Local management, suitable for home/small business, no central policy.

---

## Visual: User and Machine Account Relationships in AD
```mermaid
flowchart TD
    subgraph Domain[Active Directory Domain]
        OU1[OU: Employees]
        OU2[OU: Service Accounts]
        OU3[OU: Former Employees]
        U1[User: Alice]
        U2[User: Bob]
        U3[User: ServiceApp]
        U4[User: DisabledUser]
        G1[Group: IT Admins]
        G2[Group: HR]
        M1[Machine: WIN-WS01]
        M2[Machine: WIN-SRV01]
        OU1 --> U1
        OU1 --> U2
        OU2 --> U3
        OU3 --> U4
        U1 --> G1
        U2 --> G2
        M1 --> OU1
        M2 --> OU2
    end
```

---

## Active Directory Groups

Groups are a fundamental object in Active Directory (AD) used to organize users, computers, and other objects for easier management and permission assignment. Groups can simplify administration, but if not managed carefully, can lead to excessive or unintended privileges.

### Groups vs. Organizational Units (OUs)
- **Groups:** Used to assign permissions to access resources. Membership determines access rights.
- **OUs:** Used to organize objects for management and apply Group Policy. Can delegate admin tasks without granting extra rights via group membership.

---

### Types of Groups
| Group Type      | Purpose                                                                                   |
|-----------------|------------------------------------------------------------------------------------------|
| Security        | Assign permissions/rights to users and computers for resources (files, printers, etc.).   |
| Distribution    | Used by email applications (e.g., Exchange) to distribute messages; not for permissions.  |

---

### Group Scopes
| Scope         | Description                                                                                 |
|---------------|--------------------------------------------------------------------------------------------|
| Domain Local  | Manage permissions to resources in the same domain; can include users from other domains.   |
| Global        | Can be used in any domain, but only contains users from its own domain.                     |
| Universal     | Used across multiple domains in a forest; can contain users/groups from any domain.         |

---

### Example: Group Scopes in AD
```powershell
PS C:\htb> Get-ADGroup  -Filter * |select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Domain Admins                                Global
Domain Users                                 Global
Domain Guests                                Global
```

---

### Built-in vs. Custom Groups
- **Built-in Groups:** Created by default for administrative purposes (e.g., Administrators, Users, Guests). Usually Domain Local scope.
- **Custom Groups:** Created by organizations for specific needs. Can be security or distribution, and any scope.

---

### Nested Group Membership
Groups can be members of other groups (nesting), which can lead to inherited privileges. This can make it difficult to audit effective permissions. Tools like BloodHound help visualize and analyze nested group relationships.

#### Visual: Nested Group Membership
```mermaid
flowchart TD
    DCorner[User: DCORNER]
    HelpDesk[Group: HELP DESK]
    HelpDeskL1[Group: HELP DESK LEVEL 1]
    Tier1Admins[Group: TIER 1 ADMINS]

    DCorner --> HelpDesk
    HelpDesk --> HelpDeskL1
    HelpDeskL1 --> Tier1Admins
```

---

### Important Group Attributes
| Attribute   | Description                                                      |
|-------------|------------------------------------------------------------------|
| cn          | Common-Name of the group                                         |
| member      | Users, groups, or contacts that are members of the group         |
| groupType   | Integer specifying group type and scope                          |
| memberOf    | Groups that contain this group as a member (nested membership)   |
| objectSid   | Security Identifier (SID) unique to the group                    |

---

Groups are essential for managing access and permissions in AD. Understanding group types, scopes, and nesting is critical for both administration and security assessment.

User and machine accounts are the foundation of AD security and administration. Proper management, naming, and group assignment are critical for both security and operational efficiency. 