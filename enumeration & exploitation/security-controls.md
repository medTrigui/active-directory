# Enumerating Security Controls

After gaining a foothold, it's important to assess the defensive state of hosts and the domain. Understanding security controls helps inform tool choice, exploitation, and post-exploitation strategy.

> **Note:** This section provides an overview of possible security controls in a domain. Enumerating and bypassing controls are outside the scope of this module.

---

## Windows Defender (Microsoft Defender)
- Modern Defender blocks many offensive tools by default.
- Check status with PowerShell:
```powershell
Get-MpComputerStatus
```
**Key Output:**
- `RealTimeProtectionEnabled: True` means Defender is active.

---

## AppLocker
- Application whitelisting to control allowed executables/scripts.
- Often blocks PowerShell, cmd.exe, and write access to key directories.
- Policies may be bypassed if not applied to all PowerShell locations.
- Enumerate with:
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
**Sample Output:**
```
PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
Name                : Block PowerShell
Action              : Deny
...
```

---

## PowerShell Constrained Language Mode
- Restricts PowerShell features (COM objects, .NET types, etc.).
- Check mode with:
```powershell
$ExecutionContext.SessionState.LanguageMode
```
**Sample Output:**
```
ConstrainedLanguage
```

---

## LAPS (Local Administrator Password Solution)
- Randomizes/rotates local admin passwords to prevent lateral movement.
- Enumerate delegated groups and rights with LAPSToolkit:
```powershell
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```
**Sample Outputs:**
- Delegated groups for LAPS password read access
- Computers with LAPS enabled and password expiration

---

## Conclusion
- Enumerating security controls helps tailor your approach and avoid detection.
- Familiarize yourself with these tools and techniques to assess protections in AD environments. 