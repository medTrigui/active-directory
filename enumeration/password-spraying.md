# Password Spraying in Active Directory Environments

## Overview
- **Password spraying** is an attack where a few common passwords are tried against many accounts, avoiding account lockouts.
- Targets weak, shared, or default passwords across large user bases.
- Common in both internal and external AD attacks.

## Real-World Scenarios
- Initial access by external attackers using breached credentials.
- Lateral movement by internal attackers after phishing or malware.
- Red teamers and penetration testers to identify weak accounts.

## Key Considerations
- Avoids lockouts by rotating usernames, not passwords.
- Often bypasses basic monitoring if thresholds are high.
- Can be noisy if not throttled; stealthier with longer intervals.
- Multi-factor authentication (MFA) and strong password policies reduce risk.

## Table
| Aspect                | Details                                                      |
|-----------------------|--------------------------------------------------------------|
| **Attack Vector**     | Remote (VPN, OWA, RDP, SMB, LDAP)                            |
| **Targets**           | User accounts, service accounts, admin accounts              |
| **Common Tools**      | CrackMapExec, Kerbrute, Hydra, Metasploit, custom scripts    |
| **Detection**         | Multiple failed logins from single IP, unusual login times   |
| **Prevention**        | MFA, lockout policies, monitoring, user education            |

## Example Attack Flow
```mermaid
graph TD
    A[Attacker] -->|List of usernames| B[AD Login Portal]
    A -->|Common password (e.g., Winter2024!)| B
    B -->|Success?| C{Valid Login?}
    C -- Yes --> D[Access Gained]
    C -- No --> E[Try Next User]
```

## Sample Command (CrackMapExec)
```bash
crackmapexec smb 10.0.0.0/24 -u users.txt -p "Winter2024!" --no-bruteforce
```

## References
- [Microsoft: Password spray attacks](https://learn.microsoft.com/en-us/security/compass/incident-response-password-spray)
- [SpecterOps: Password Spraying](https://posts.specterops.io/password-spraying-other-bad-password-hygiene-issues-in-ad-7b7c430aab06) 

# Enumerating & Retrieving Password Policies

## Why Enumerate Password Policy?
- Determines safe password spraying frequency and risk of account lockout.
- Reveals password complexity, length, and lockout settings.

## Methods Overview
| Method                | OS      | Credentialed | Tools/Commands                |
|-----------------------|---------|--------------|-------------------------------|
| SMB Authenticated     | Linux   | Yes          | CrackMapExec, rpcclient       |
| SMB NULL Session      | Linux   | No           | enum4linux, rpcclient         |
| LDAP Anonymous Bind   | Linux   | No           | ldapsearch, windapsearch.py   |
| Built-in Binaries     | Windows | Yes/No       | net.exe, PowerView, SharpView |

---

## Credentialed Enumeration (Linux)
**CrackMapExec Example:**
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
**Sample Output:**
```
Minimum password length: 8
Password history length: 24
Maximum password age: Not Set
Password Complexity Flags: 000001
Minimum password age: 1 day 4 minutes
Reset Account Lockout Counter: 30 minutes
Locked Account Duration: 30 minutes
Account Lockout Threshold: 5
```

---

## Anonymous/NULL Session Enumeration (Linux)
**rpcclient Example:**
```bash
rpcclient -U "" -N 172.16.5.5
rpcclient $> getdompwinfo
```
**Sample Output:**
```
min_password_length: 8
password_properties: 0x00000001
    DOMAIN_PASSWORD_COMPLEX
```

**enum4linux Example:**
```bash
enum4linux -P 172.16.5.5
```
**Sample Output:**
```
Minimum password length: 8
Password history length: 24
Maximum password age: Not Set
Password Complexity Flags: 000001
Account Lockout Threshold: 5
```

---

## LDAP Anonymous Bind (Linux)
**ldapsearch Example:**
```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
**Sample Output:**
```
minPwdLength: 8
pwdHistoryLength: 24
lockoutThreshold: 5
```

---

## Windows Methods
**Built-in net.exe:**
```cmd
net accounts
```
**Sample Output:**
```
Minimum password age (days): 1
Maximum password age (days): Unlimited
Minimum password length: 8
Length of password history maintained: 24
Lockout threshold: 5
Lockout duration (minutes): 30
```

**PowerView Example:**
```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

---

## Default Domain Policy (Reference)
| Policy                                 | Default Value |
|----------------------------------------|---------------|
| Enforce password history               | 24            |
| Maximum password age                   | 42 days       |
| Minimum password age                   | 1 day         |
| Minimum password length                | 7             |
| Password must meet complexity reqs     | Enabled       |
| Store passwords using reversible enc.  | Disabled      |
| Account lockout duration               | Not set       |
| Account lockout threshold              | 0             |
| Reset account lockout counter after    | Not set       |

---

## Key Takeaways
- Always enumerate the password policy before spraying.
- If policy cannot be retrieved, spray with extreme caution (low frequency, long intervals).
- Avoid account lockouts—especially in environments requiring manual unlocks.
- Use a combination of tools for redundancy and stealth. 