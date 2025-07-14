# ACL Abuse in Active Directory (Nitty-Gritty)

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

## Typical Attack Flow
1. **Enumerate ACLs:** BloodHound, PowerView, ADExplorer
2. **Find abusable ACEs:** Look for above rights on users/groups/computers
3. **Exploit:** Use PowerView, BloodHound, or built-in tools to abuse rights
4. **Escalate/Move Laterally:** Reset passwords, add to groups, etc.

## Real-World Scenarios
- Helpdesk can reset Domain Admin passwords (ForceChangePassword)
- User can add self to privileged group (AddSelf)
- Service account has GenericWrite on another user (Kerberoasting, persistence)

## Blue Team Tip
- Regularly audit ACLs on sensitive objects (users, groups, computers, OUs)
- Use BloodHound's "Shortest Paths to High Value Targets"

---
**Note:** Some ACL attacks are destructive (e.g., password resets). Always get client approval and document changes during assessments. 