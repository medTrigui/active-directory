# Native Windows Enumeration

This document covers techniques for enumerating Active Directory environments using only native Windows tools and commands—no external binaries or scripts required. This approach is essential when tool uploads are blocked or for stealthier assessments.

## Scenario
Assume you are on a managed host with no internet access and cannot load external tools. The goal is to enumerate the AD environment using only what is built into Windows.

---

## Host & Network Recon with Native Commands

### Basic Enumeration Commands
| Command                                      | Description                                      |
|----------------------------------------------|--------------------------------------------------|
| `hostname`                                  | Prints the PC's name                             |
| `[System.Environment]::OSVersion.Version`    | OS version and revision                          |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Lists patches and hotfixes applied     |
| `ipconfig /all`                             | Network adapter state and configurations         |
| `set` (CMD)                                 | Lists environment variables                      |
| `echo %USERDOMAIN%` (CMD)                   | Displays the domain name                         |
| `echo %logonserver%` (CMD)                  | Shows the Domain Controller in use               |
| `systeminfo`                                | Prints a summary of host information             |

**Example:**
```powershell
hostname
[System.Environment]::OSVersion.Version
wmic qfe get Caption,Description,HotFixID,InstalledOn
ipconfig /all
set
systeminfo
```

---

## PowerShell for Recon & Evasion
- Use built-in cmdlets for environment, policy, and history checks.
- PowerShell can be downgraded to v2.0 to evade logging (if available).

| Cmdlet/Command                                         | Description                                      |
|--------------------------------------------------------|--------------------------------------------------|
| `Get-Module`                                           | Lists loaded modules                             |
| `Get-ExecutionPolicy -List`                            | Shows execution policy for each scope            |
| `Set-ExecutionPolicy Bypass -Scope Process`            | Temporarily bypasses execution policy            |
| `Get-ChildItem Env: | ft Key,Value`                    | Lists environment variables                      |
| `Get-Content $env:APPDATA\...\ConsoleHost_history.txt` | Shows PowerShell command history                 |
| `powershell.exe -version 2`                            | Launches PowerShell v2.0 (evades script block logging) |
| `whoami`                                               | Shows current user context                       |

**Example:**
```powershell
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
powershell.exe -version 2
whoami
```

---

## Firewall & Defender Checks
- Check Windows Firewall and Defender status/configuration.

| Command                                      | Description                                      |
|----------------------------------------------|--------------------------------------------------|
| `netsh advfirewall show allprofiles`         | Shows firewall status for all profiles            |
| `sc query windefend`                         | Checks if Windows Defender service is running     |
| `Get-MpComputerStatus` (PowerShell)          | Detailed Defender/AV status and config            |

**Example:**
```powershell
netsh advfirewall show allprofiles
sc query windefend
Get-MpComputerStatus
```

---

## User Session & Logon Checks
- See who is logged in and session details.

| Command      | Description                        |
|--------------|------------------------------------|
| `qwinsta`    | Lists user sessions on the host    |
| `query user` | Alternative to qwinsta             |

**Example:**
```powershell
qwinsta
query user
```

---

## Network Discovery
- Identify other hosts, routes, and network segments.

| Command           | Description                                 |
|-------------------|---------------------------------------------|
| `arp -a`          | Lists known hosts in the ARP table           |
| `route print`     | Shows routing table (IPv4 & IPv6)            |
| `net view`        | Lists computers in the domain/workgroup      |
| `net view /domain`| Lists all domains                            |
| `netstat -ano`    | Lists active network connections             |

**Example:**
```powershell
arp -a
route print
net view
net view /domain
netstat -ano
```

---

## WMI (Windows Management Instrumentation)
- Query system, user, and domain info with wmic.

| Command                                                    | Description                                 |
|------------------------------------------------------------|---------------------------------------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`    | Patch/hotfix info                           |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Host info |
| `wmic process list /format:list`                           | List all processes                          |
| `wmic ntdomain list /format:list`                          | Domain and DC info                          |
| `wmic useraccount list /format:list`                       | Local/domain user accounts                  |
| `wmic group list /format:list`                             | Local groups                                |
| `wmic sysaccount list /format:list`                        | System/service accounts                     |

**Example:**
```powershell
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
wmic useraccount list /format:list
```

---

## Net Commands for AD Enumeration
- Use net.exe (or net1.exe for evasion) to enumerate users, groups, shares, and more.

| Command                                      | Description                                      |
|----------------------------------------------|--------------------------------------------------|
| `net accounts /domain`                       | Password and lockout policy                      |
| `net group /domain`                          | List domain groups                               |
| `net group "Domain Admins" /domain`          | List domain admins                               |
| `net user /domain`                           | List all domain users                            |
| `net user <username> /domain`                | Info about a specific user                       |
| `net localgroup administrators`              | Local admin group members                        |
| `net share`                                  | List shares                                      |
| `net view`                                   | List computers                                   |
| `net view \\computer`                        | List shares on a computer                        |

**Example:**
```powershell
net accounts /domain
net group /domain
net group "Domain Admins" /domain
net user /domain
net user forend /domain
net localgroup administrators
net share
net view
net view \\ACADEMY-EA-DC01
```

---

## Dsquery for AD Object Search
- Use dsquery to find users, computers, and more (requires AD DS role).

| Command                                      | Description                                      |
|----------------------------------------------|--------------------------------------------------|
| `dsquery user`                               | List all users                                   |
| `dsquery computer`                           | List all computers                               |
| `dsquery * <OU_DN>`                          | List all objects in an OU                        |
| `dsquery * -filter <LDAP_FILTER>`            | Custom LDAP search                               |

**Example:**
```powershell
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```

---

## LDAP Filtering & UAC Bitmasks
- Use LDAP filters to search for specific AD object attributes.
- Common OIDs:
    - `1.2.840.113556.1.4.803` (exact match)
    - `1.2.840.113556.1.4.804` (any bit match)
    - `1.2.840.113556.1.4.1941` (DN/ownership match)
- Logical operators: `&` (and), `|` (or), `!` (not)

**Example:**
```powershell
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))"
dsquery * -filter "(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))"
```

---

**Tip:** All of these commands are native to Windows and require no external tools. Use them for stealthy enumeration or when tool uploads are blocked. 