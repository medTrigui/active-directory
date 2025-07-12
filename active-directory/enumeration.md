# Enumeration

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