---
title: Threat Actor Report / Phishing Investigation - tchiktchik
date: 2024-08-31 11:02 -0400
categories: [phishing]
tags: [phishing, threat intelligence, threat actor, telegram]
---

## Introduction
This phishing campaign has been by far one of the more reactive ones I've personally run into. I even managed a few words out of the admin before he grew bored of me : ( 

There is a lot to go through as *tchiktchik* was changing the infrastructure live while I was doing my research. Let's start from the beginning.

## Phishing Email
I received a phishing email for SwissPass from the domain `support@koppaweb.gr` (Translation added)

![website-screenshot](assets\img\phishingscreenshots\Screenshot1.png)

Upon clicking the link you are redirected to `https://naturaldynamix.com/wp-content/bhaj.php"` and then redirected to `https://14548652-16-20171107105633.webstarterz.com/SBB/index/`... for the first 30 minutes that I was investigating. 

It then changed it's redirect to `https://koppaweb.gr/wp-content/plugins/qasaosl/SBB/index/` which initially presented a very well made SBB phishing login page. It presented  which attempted to gather login, CC, and SMS code. It now re-directs to this landing site which has several malicious scripts. They seem to be heavily obfuscated:

![website-screenshot](assets\img\phishingscreenshots\Screenshot2.png)

My Windows AV alerted me shortly after being on the site... yummy. Upon investigating the domain of the initial re-direct `naturaldynamix.com`, we are able to find another phishing site

![website-screenshot](assets\img\phishingscreenshots\Screenshot3.png)

I entered some information and started intercepting the requests. It looks like it was coded to initialize an API call client side to a Telegram bot to pass the information entered.

**Request captured client side to forward harvested data**

![website-screenshot](assets\img\phishingscreenshots\Screenshot4.png)

Lucky for me, a couple years back I found something similar so knew the Telegram API can betray you if not setup properly. Now that we have the *chat_id*, we can use it to gather information about the chat. Such as the administrator of the chat:

**Getting chat details using getChatAdministrators method with Telegram API**

![website-screenshot](assets\img\phishingscreenshots\Screenshot5.png)

Here we finally meet *tchiktchik* for the first time, I note the language code being `fr` so take an educated guess that they speak French. I tried to ask some questions but all the useful information I got was they confirmed speaking English, French, and Arabic. They were very hesitant to respond, however I did seem to get their attention quickly when mentioning Tunisia out of context. More on this later.

**Telegram Profile**

![website-screenshot](assets\img\phishingscreenshots\Screenshot6.png)

**User Pictures**

![website-screenshot](assets\img\phishingscreenshots\Screenshot7.png)


I also learned a little trick with bots, I had sufficient permissions so I ended up adding them to a chat owned by me and forwarding the messages. This works very well for data exfiltration.

**Forwarding messages using forwardMessage method with Telegram API**

![website-screenshot](assets\img\phishingscreenshots\Screenshot8.png)

Now we can see every forwardable message in the chat (note Telegram has some messages which can not be forwarded). I went through all of the messages available, and looking through the data it seemed to just be test data entered at that point. Caught him too early... After forwarding the messages the my own chat, I could see that there were multiple phishing campaigns happening at the same time. 

**SBB Login + CC Info**

![sbbchat-screenshot](assets\img\phishingscreenshots\Screenshot9.png)

**SBB SMS Code**

![smschat-screenshot](assets\img\phishingscreenshots\Screenshot10.png)

**Trust Wallet Password and Seed Words**

![website-screenshot](assets\img\phishingscreenshots\Screenshot11.png)

This was about the extent of the information I was able to grab from Telegram. I debated attempting to find some way to send a message via the bot in hopes the actor would interact with it and get further information on their whereabouts / identity. Some lines you don't cross. I ended up heading to the email headers for further analysis.

## Email Analysis

Do you remember when I mentioned Tunisia earlier? Well looking at the email headers we can get some more context:

**Our first group of notable headers:**

```
To: REMOVED
Subject: Aktualisieren Sie Ihre Dateninformationen
X-Php-Script: koppaweb.gr/wp-content/plugins/qasaosl/m.PhP7 for 102.106.214.42
X-Php-Originating-Script: 1168:m.PhP7(1) : eval()'d code(1) : eval()'d code(1) : eval()'d
 code
```

The **X-Php-Script** header indicates that the PHP script located at `koppaweb.gr/wp-content/plugins/qasaosl/m.PhP7` was executed to handle the request for the IP address 102.106.214.42. We can further investigate this IP with tools like AbuseIPDB:

**AbuseIPDB screenshot**

![website-screenshot](assets\img\phishingscreenshots\Screenshot12.png)

No malicious hits so this IP stays clean. We can check and see if it is a known proxy:

**Proxy/VPN check screenshot**
![website-screenshot](assets\img\phishingscreenshots\Screenshot13.png)

No known-proxy or VPN. Here is where I take a bit of a leap to come to my assumption this IP is at all relevant to our threat actor. This IP could very well be another compromised host, however, here is why I believe it is not. The IP has no DNS records that I could find, it also was used to trigger the email sent from the compromised host. I never like to underestimate the sophistication of people but they did leave the telegram bot client-side. I personally would have had a VPN or something even for doing that if I was them, but hey bad op-sec is pretty common.

**Our second group of notable headers:**

```
X-Antiabuse: This header was added to track abuse, please include it with any abuse report
X-Antiabuse: Primary Hostname - server170.happybyte.gr
X-Antiabuse: Original Domain - REMOVED
X-Antiabuse: Originator/Caller UID/GID - [1168 980] / [47 12]
X-Antiabuse: Sender Address Domain - koppaweb.gr
X-Get-Message-Sender-Via: server170.happybyte.gr: authenticated_id: efjeojcw/from_h
X-Authenticated-Sender: server170.happybyte.gr: support@koppaweb.gr
X-Source-Args: /opt/cpanel/ea-php73/root/usr/bin/php-cgi
 /home/efjeojcw/public_html/wp-content/plugins/qasaosl/m.PhP7
X-Source-Dir: koppaweb.gr:/public_html/wp-content/plugins/qasaosl
```

Here we can see where the more directory information as well as the server which sent the email. There are many more ends which need to be tied up. We can see some once we de-obfuscate the code from found on the `koppaweb.gr` domain earlier. Coming soon...
