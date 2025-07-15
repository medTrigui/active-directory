# Internal Enumeration

This document covers tools commonly used for Active Directory enumeration, both from Windows and Linux environments. These tools include open-source scripts, precompiled binaries, and built-in utilities. Below is a table summarizing many of the tools covered in this module:

| Tool                | Description                                                                                                                        |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------|
| PowerView/SharpView | PowerShell/.NET tools for AD situational awareness, user/computer targeting, and quick wins (e.g., Kerberoasting, ASREPRoasting).  |
| BloodHound          | Visualizes AD relationships and attack paths; uses SharpHound or BloodHound.py for data collection and Neo4j for analysis.          |
| SharpHound          | C# data collector for BloodHound; gathers info on users, groups, computers, ACLs, GPOs, sessions, etc.                             |
| BloodHound.py       | Python-based BloodHound ingestor using Impacket; supports most collection methods from non-domain hosts.                            |
| Kerbrute            | Go tool for Kerberos Pre-Auth enumeration, password spraying, and brute-forcing.                                                   |
| Impacket toolkit    | Python tools for interacting with network protocols; includes scripts for AD enumeration and attacks.                               |
| Responder           | LLMNR, NBT-NS, and MDNS poisoning tool for credential capture and network spoofing.                                                |
| Inveigh.ps1         | PowerShell tool for network spoofing/poisoning attacks (similar to Responder).                                                     |
| InveighZero         | C# version of Inveigh with interactive console for captured data.                                                                  |
| rpcinfo             | Queries status of RPC programs/services on remote hosts.                                                                           |
| rpcclient           | Samba suite tool for AD enumeration via remote RPC service.                                                                        |
| CrackMapExec (CME)  | Enumeration, attack, and post-exploitation toolkit for AD; abuses SMB, WMI, WinRM, MSSQL, etc.                                    |
| Rubeus              | C# tool for Kerberos abuse.                                                                                                        |
| GetUserSPNs.py      | Impacket module for finding Service Principal Names tied to user accounts.                                                         |
| Hashcat             | Hash cracking and password recovery tool.                                                                                          |
| enum4linux          | Enumerates info from Windows and Samba systems.                                                                                    |
| enum4linux-ng       | Modern rework of enum4linux.                                                                                                       |
| ldapsearch          | Built-in LDAP query tool.                                                                                                          |
| windapsearch        | Python script for enumerating AD users, groups, and computers via LDAP queries.                                                    |
| DomainPasswordSpray.ps1 | PowerShell tool for password spray attacks against domain users.                                                              |
| LAPSToolkit         | PowerShell toolkit for auditing/attacking AD environments with LAPS deployed.                                                      |
| smbmap              | Enumerates SMB shares across a domain.                                                                                             |
| psexec.py           | Impacket tool for semi-interactive shell via SMB (Psexec-like functionality).                                                      |
| wmiexec.py          | Impacket tool for command execution over WMI.                                                                                      |
| Snaffler            | Finds sensitive info (e.g., credentials) on accessible file shares.                                                                |
| smbserver.py        | Simple SMB server for file transfer within a network.                                                                              |
| setspn.exe          | Adds, reads, modifies, and deletes SPNs for AD service accounts.                                                                  |
| Mimikatz            | Extracts plaintext passwords, hashes, Kerberos tickets; performs pass-the-hash and other attacks.                                 |
| secretsdump.py      | Impacket tool for dumping SAM and LSA secrets remotely.                                                                            |
| evil-winrm          | Interactive shell over WinRM protocol.                                                                                            |
| mssqlclient.py      | Impacket tool for interacting with MSSQL databases.                                                                                |
| noPac.py            | Exploit for CVE-2021-42278/42287 to impersonate DA from standard user.                                                            |
| rpcdump.py          | Impacket tool for RPC endpoint mapping.                                                                                            |
| CVE-2021-1675.py    | PrintNightmare PoC exploit in Python.                                                                                             |
| ntlmrelayx.py       | Impacket tool for SMB relay attacks.                                                                                              |
| PetitPotam.py       | PoC tool for CVE-2021-36942 (EFSRPC abuse for forced authentication).                                                             |
| gettgtpkinit.py     | Tool for manipulating certificates and TGTs.                                                                                      |
| getnthash.py        | Uses existing TGT to request a PAC for the current user (U2U).                                                                    |
| adidnsdump          | Enumerates/dumps DNS records from a domain (like DNS zone transfer).                                                              |
| gpp-decrypt         | Extracts credentials from Group Policy preferences files.                                                                         |
| GetNPUsers.py       | Impacket tool for ASREPRoasting (listing users with no Kerberos pre-auth).                                                        |
| lookupsid.py        | SID bruteforcing tool.                                                                                                            |
| ticketer.py         | Creates/customizes TGT/TGS tickets (Golden Ticket, trust attacks, etc.).                                                         |
| raiseChild.py       | Impacket tool for automated child-to-parent domain privilege escalation.                                                          |
| Active Directory Explorer | GUI tool for viewing/editing AD databases, snapshots, and comparing changes.                                               |
| PingCastle          | Audits AD security level based on risk assessment and maturity framework.                                                         |
| Group3r             | Audits and finds misconfigurations in AD Group Policy Objects (GPO).                                                             |
| ADRecon             | Extracts and summarizes AD data for security analysis.                                                                           |

---

More details and usage examples for these tools will be covered in the following sections. 

## External Recon and Enumeration Principles

Before starting a pentest, external reconnaissance helps validate scope, discover public information, and identify potential information leaks. The goal is to gather as much relevant data as possible to inform and guide the assessment.

### What Are We Looking For?
| Data Point         | Description                                                                                                   |
|--------------------|--------------------------------------------------------------------------------------------------------------|
| IP Space           | ASN, netblocks, cloud presence, DNS records, hosting providers.                                               |
| Domain Information | Domain ownership, subdomains, public services (mail, VPN, websites), defenses (SIEM, AV, IDS/IPS).           |
| Schema Format      | Email/username formats, password policies, info for building user lists.                                      |
| Data Disclosures   | Public files (PDF, DOCX, etc.), metadata, credentials in code repos, internal links in documents.             |
| Breach Data        | Publicly released usernames, passwords, or other sensitive info.                                              |

### Where Are We Looking?
| Resource Type                | Examples                                                                                             |
|-----------------------------|------------------------------------------------------------------------------------------------------|
| ASN / IP registrars          | IANA, ARIN, RIPE, BGP Toolkit                                                                        |
| Domain Registrars & DNS      | Domaintools, PTRArchive, ICANN, manual DNS queries, 8.8.8.8                                          |
| Social Media                 | LinkedIn, Twitter, Facebook, job sites, news articles                                                |
| Public-Facing Company Sites  | About/Contact pages, embedded docs, org charts, emails                                               |
| Cloud & Dev Storage          | GitHub, AWS S3, Azure Blob, Google Dorks                                                             |
| Breach Data Sources          | HaveIBeenPwned, Dehashed, credential dumps                                                           |

---

### Enumeration Process Principles
- Start with passive recon: gather public data, validate scope, and build a target profile.
- Use multiple sources to cross-validate findings (e.g., BGP Toolkit, viewdns.info, nslookup).
- Document everything: save files, screenshots, tool output, and findings for reference.
- Respect scope: never test or scan assets outside the agreed scope.
- Escalate questions about ambiguous scope or third-party infrastructure.

---

### Example Enumeration Process
1. Identify ASN/IP and domain data (BGP Toolkit, DNS records)
2. Validate findings with tools like viewdns.info and nslookup
3. Search for public documents (e.g., Google dorks: `filetype:pdf inurl:target.com`)
4. Harvest email addresses and usernames (contact pages, social media, tools like linkedin2username)
5. Hunt for credentials in breach data (Dehashed, HaveIBeenPwned)
6. Build wordlists and user lists for later use (password spraying, brute force, etc.)

---

### Sample Recon Output
```powershell
# DNS info for inlanefreight.com
A record: 134.209.24.248
Mail Server: mail1.inlanefreight.com
Nameservers: ns1.inlanefreight.com, ns2.inlanefreight.com

# nslookup for nameservers
ns1.inlanefreight.com -> 178.128.39.165
ns2.inlanefreight.com -> 206.189.119.186
```

---

### Example: Email and Credential Hunting
- Use Google dorks to find emails: `intext:"@target.com" inurl:target.com`
- Use Dehashed or similar to find leaked credentials:
```bash
sudo python3 dehashed.py -q target.local -p
# Output: emails, usernames, passwords, hashes
```

---

External recon is iterative and should be thorough, but always within scope. The information gathered here will inform your internal enumeration and attack planning. 

## Initial Enumeration of the Domain

After external recon, the next step is internal enumeration. This phase aims to identify users, hosts, services, and vulnerabilities to gain a foothold in the domain.

### Typical Internal Pentest Setups
- Pentest VM in internal network (SSH access via jump host)
- Physical device on-site (VPN callback)
- Corporate laptop or VDI (VPN or on-site)
- Linux VM in cloud (Azure/AWS) with internal access
- VPN access to internal network
- Managed workstation (Windows) with/without internet
- "Grey box" (some info provided) or "black box" (blind) testing

**Inlanefreight scenario:**
- Custom pentest VM in internal network (SSH access)
- Windows host for tool loading
- Start unauthenticated, but with a standard domain user account available
- Grey box, non-evasive, network range 172.16.5.0/23

---

### Key Data Points to Enumerate
| Data Point           | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| AD Users             | Enumerate valid user accounts for password spraying/attacks                  |
| AD Joined Computers  | Identify DCs, file servers, SQL servers, web servers, etc.                  |
| Key Services         | Kerberos, NetBIOS, LDAP, DNS                                                |
| Vulnerable Hosts     | Hosts/services with known vulnerabilities for quick wins                     |

---

### Enumeration Workflow
1. **Passive Host Discovery:**
   - Use Wireshark/tcpdump to capture ARP, MDNS, LLMNR, NBT-NS traffic
   - Identify live hosts and hostnames
   - Example:
     ```bash
     sudo -E wireshark
     sudo tcpdump -i ens224
     ```
2. **Passive Analysis:**
   - Use Responder in analyze mode to listen for LLMNR/NBT-NS/MDNS requests
     ```bash
     sudo responder -I ens224 -A
     ```
3. **Active Host Discovery:**
   - Use fping for ICMP sweep
     ```bash
     fping -asgq 172.16.5.0/23
     # Output: list of live hosts
     ```
4. **Service Enumeration:**
   - Use Nmap to scan live hosts for open ports/services
     ```bash
     sudo nmap -v -A -iL hosts.txt -oN host-enum
     # Focus on DNS, SMB, LDAP, Kerberos, RDP, MSSQL, etc.
     ```
5. **Identify Domain Controllers and Key Servers:**
   - Look for hosts running AD services (LDAP, Kerberos, DNS)
   - Example Nmap output:
     ```
     PORT     STATE SERVICE       VERSION
     53/tcp   open  domain        Simple DNS Plus
     88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
     389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
     445/tcp  open  microsoft-ds
     3389/tcp open  ms-wbt-server Microsoft Terminal Services
     ```
6. **User Enumeration:**
   - Use Kerbrute for Kerberos-based user enumeration
     ```bash
     kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
     # Output: list of valid usernames
     ```

---

### Example: Kerbrute Output
```bash
[+] VALID USERNAME: jjones@INLANEFREIGHT.LOCAL
[+] VALID USERNAME: sbrown@INLANEFREIGHT.LOCAL
[+] VALID USERNAME: tjohnson@INLANEFREIGHT.LOCAL
...
Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```

---

### Identifying Potential Vulnerabilities
- Look for legacy OS (e.g., Windows Server 2008, Windows 7)
- Outdated services (IIS, SQL Server, SMBv1)
- Exposed RDP, SMB, or other management ports
- SYSTEM-level access on a domain-joined host is nearly equivalent to a domain user

**Caution:**
- Always clarify scope and get approval before exploiting legacy or critical systems
- Use non-evasive techniques unless otherwise agreed

---

Initial enumeration sets the stage for deeper domain attacks. Document all findings, save outputs, and build a target list for further enumeration and exploitation. 