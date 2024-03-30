---
title: THM Valley Writeup
date: 2024-03-30 10:58 -0400
categories: [Writeups, TryHackMe]
tags: [valley, ctf]
---
# Intro
This box askes us to find a user and root flag, not much else in regards to direction or hints.

Let's start with
### Enumeration
##### Command
```{bash}
rustscan -a 10.10.2.80
```
*I like using rustscan initally as it is fast and works pretty well. We can run an nmap scan later to confirm services and look at all ports if we need to.*

#####  Output
```{bash}
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
37370/tcp open  unknown syn-ack
```
Three ports is enough to start, lets dig a bit deeper into the service versions and underyling OS with Nmap. Verbose flags can result in noisy output so lets save this to a file for later reference.
##### Command
```{bash}
nmap -sV -sC -A -O -vv -p 22,80,37370 10.10.2.80 > initNmapScan
```
#####  Output
```{bash}
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
37370/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
MAC Address: 02:E2:8A:01:FA:87 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.8 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.8 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.60%E=4%D=3/30%OT=22%CT=%CU=37485%PV=Y%DS=1%DC=D%G=N%M=02E28A%TM=6608523A%P=x86_64-pc-linux-gnu)
SEQ(SP=10A%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)
SEQ(SP=10A%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 49.420 days (since Sat Feb 10 07:50:45 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=266 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
```

So now we know we are working with a linux machine most likely. We have a few routes to enumerate from here, but I am lazy and like to go for the lowest hanging fruit first.
From the output we can see port 37370 is open and hosting an FTP service
##### Output
```{bash}
37370/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
```

Let's see if they allow for anonymous connections:
##### Command and Output
```{bash}
root@ip-10-10-253-34:~# ftp 10.10.2.80 37370
Connected to 10.10.2.80.
220 (vsFTPd 3.0.3)
Name (10.10.2.80:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```
Nope, well now lets move onto the webpage hosted on port 80.

Before I start looking around the website manually, I like to begin some enumeration with gobuster so it can run in the background if needed.
##### Command
```{bash}
gobuster dir -u http://10.10.2.80:80 -w /usr/share/wordlists/dirb/common.txt
```
These folders were available on the website
##### Output
```{bash}
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/gallery (Status: 301)
/index.html (Status: 200)
/pricing (Status: 301)
/server-status (Status: 403)
/static (Status: 301)
```
We want to look into the directories with a 301 response
##### Command
```{bash}
gobuster dir -u http://10.10.2.80:80/pricing -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x .html
```
##### Output
```{bash}
/pricing.html (Status: 200)
```
##### Command
```{bash}
gobuster dir -u http://10.10.2.80:80/gallery -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x .html
```
##### Output
```{bash}
/gallery.html (Status: 200)
```
##### Command
```{bash}
gobuster dir -u http://10.10.2.80:80/static -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x .html
```
##### Output
```{bash}
/1 (Status: 200)
/3 (Status: 200)
/5 (Status: 200)
/2 (Status: 200)
/4 (Status: 200)
/00 (Status: 200)
/10 (Status: 200)
/16 (Status: 200)
/12 (Status: 200)
/17 (Status: 200)
/13 (Status: 200)
/18 (Status: 200)
/14 (Status: 200)
/11 (Status: 200)
/15 (Status: 200)
/6 (Status: 200)
/8 (Status: 200)
/7 (Status: 200)
/9 (Status: 200)
```

Now we have a good reference of the site layout and what directories and files are available. Lets navigate to the page on our browser
![website-screenshot](assets/img/writeupscreenshots/valley-1.png)
