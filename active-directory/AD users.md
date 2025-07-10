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

User and machine accounts are the foundation of AD security and administration. Proper management, naming, and group assignment are critical for both security and operational efficiency. 