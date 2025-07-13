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

**Example:**
```powershell
hostname
[System.Environment]::OSVersion.Version
wmic qfe get Caption,Description,HotFixID,InstalledOn
ipconfig /all
set
```

### System Summary
- `systeminfo` provides a summary of host information in one command.

**Example:**
```powershell
systeminfo
```

---

## PowerShell for Recon
- Use built-in cmdlets for environment, policy, and history checks.

| Cmdlet/Command                                         | Description                                      |
|--------------------------------------------------------|--------------------------------------------------|
| `Get-Module`                                           | Lists loaded modules                             |
| `Get-ExecutionPolicy -List`                            | Shows execution policy for each scope            |
| `Set-ExecutionPolicy Bypass -Scope Process`            | Temporarily bypasses execution policy            |
| `Get-ChildItem Env: | ft Key,Value`                    | Lists environment variables                      |
| `Get-Content $env:APPDATA\...\ConsoleHost_history.txt` | Shows PowerShell command history                 |

**Example:**
```powershell
Get-Module
Get-ExecutionPolicy -List
Get-ChildItem Env: | ft Key,Value
```

---

## More to Come
This file will be expanded with sections on PowerShell evasion, firewall/defender checks, user session checks, network discovery, WMI, net commands, dsquery, and LDAP filtering. 