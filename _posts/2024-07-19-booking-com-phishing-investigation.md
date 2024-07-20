---
title: Booking.com Phishing Investigation
date: 2024-07-19 22:32 -0400
categories: [phishing]
tags: [phishing, threat intelligence]
---

# Warning !
This campaign is ONGOING and you should visit the links below with caution!

# Intro
I like receiving phishing emails, let's investigate this specific campaign I stumbled upon. A friend of mine recently booked on booking\[.].com, and received a follow up message from within the booking\[.]com messaging service seemingly from the hotel or booking.

# First look
The email comes in impersonating the booking\[.]com website. It prompts for a reservation to be completed or it will be cancelled, and then provides an ID and a link to follow. 

Note: *I will not be providing my specific ID I received, but I figured out at least 4 digit  combinations seem to work*

# First Link

```
https[:]//forms[.]gle/RzYyDxqtxfU1u7vp6
```
The first link is to a google forms page, with the title: "Complete the bank card verification". The contents is a tricky hyperlink which does NOT direct to:
```
https[:]//booking[.]confirmation/s3v7838vf&keep_landing=1
``` 
but rather to 
```
https[:]//booking[.]guestconfirm7[.]com/reservation/
```

# Second Link
This is what we see upon navigating to the url:

![alt text](/assets/img/badbookingregistration.png)

I figured out that 2100 works as an id code, so lets put that in.

![alt text](/assets/img/badbooking2100.png)

Ahhh yes, here is where I will give all of my information!

Entering details will then move you to the next step... payment :)

![alt text](/assets/img/badbookingpayment.png)

I pulled a credit card from https://www.akto.io/tools/credit-card-generator , there are many sites which will do this, but they do have a verification process which this will be able to bypass.

![alt text](/assets/img/badbookingwait.png)

"We will let you know what to do in the support chat" 

Thats's a little weird, I'll wait.

![alt text](/assets/img/badbookingincorrectpayment.png)

Either they checked it was invalid, or this is the end of the attack. They now would have my card details and personal information.

# A deeper dive

This site is a bit annoying to enumerate as it has cloudflare protection and instead of 404 it will redirect to booking.com

They did a really good job with the visuals of the site, and my first guess is that the actors behind it are Russian. Comments left in custom JS file would indicate such:

```
  input.addEventListener("input", function () {
        // Получаем текущее значение в поле ввода
        var inputValue = input.value;

        // Используем регулярное выражение для удаления всех символов, кроме цифр
        var numericValue = inputValue.replace(/[^0-9]/g, "");

        // Обновляем значение в поле ввода только цифрами
        input.value = numericValue;
    });
```
This is also confirmed in the captcha file we can see:
/template/normal.html

```
<title>Один момент…</title>
```

In one of the css files (ecceda18eeb9f8bf9842.css), the text content was:
```
.containerMF__input-wrapper.error:after{position:absolute;content:"Можно вводить только русские буквы";left:0;bottom:-25px;font-size:13px;color:#e91717;font-weight:300}
```
meaning, "You can only enter Russian letters"

I have not seen this text anywhere, so I assume there is a page they have access on this server I have not yet found.

Looking through more css files like delivery.css we have links to resources which comes from seemingly another company website in Russia:
```
https://static.avito.ru/s/cc/resources/52c248704ee8.svg
https://static.avito.ru/s/cc/resources/b96531c287fc.svg
https://static.avito.ru/s/cc/resources/d44632371d30.svg
```
In the file 0f8d39705450fe02adb0.css, I see another possible directory:
```
background-image: url(/_nuxt/img/ac4d6d7.png);
```

Directory listing is available for these directories:
```
/css
/js
/dist
/ajax
```

These are all the interesting directories:
```
/template
/status
/reservation
/dist
/img
/confirmdata
/css
/js
/dist
/ajax
/acs/3dsecure
```
The /ajax directory contains some php functions:

```
captcha.php
image_upload.php # Haven't got this to work, although the error does show this directory which lets us known where the uploaded file will go: /var/www/www-root/data/images/p1721435971A9G14.png
manual_check_status.php
manual_push_confirm.php
manual_send_data.php
manual_send_sms.php
msg_check.php # Checks for new messages in chat
payment_card_status.php # Accepts code= as POST data and returns either a true or false status
send_msg.php # Used to send messages in chat
user_send_status.php
```

Investigation continues.... stay posted for updates!

## Email Analysis

The emails came from within the messaging portal of booking dot com, I can see there are many different places affected by enumerating the possible reservation codes, and correlating the address with an actual place reservable on booking dot com.

I looked at the headers and everything seemed normal. Within the chat on the booking dot come website the malicious message and link are visible as well, so this is not email spoofing. I am not sure exactly how booking dot com manages accounts for locations, and whether we are seeing an possible incident or just successful credential stuffing / multiple account compromise.


## Domain Analysis
There seems to be no historical data, and the first time the domain was registered.

```
Name: GUESTCONFIRM7.COM
Registry Domain ID: 2900438214_DOMAIN_COM-VRSN
Domain Status:
clientTransferProhibited
Nameservers:
MOLLY.NS.CLOUDFLARE.COM

TREVOR.NS.CLOUDFLARE.COM

Dates
Registry Expiration: 2025-07-18 18:36:11 UTC
Updated: 2024-07-18 18:38:06 UTC
Created: 2024-07-18 18:36:11 UTC
```
Looking at the naming convention, let's see what other domains have been registered:

```
Name: GUESTCONFIRM5.COM
Registry Domain ID: 2900420953_DOMAIN_COM-VRSN
Domain Status:
clientTransferProhibited
Nameservers:
MOLLY.NS.CLOUDFLARE.COM

TREVOR.NS.CLOUDFLARE.COM

Dates
Registry Expiration: 2025-07-18 18:32:09 UTC
Updated: 2024-07-18 18:33:25 UTC
Created: 2024-07-18 18:32:09 UTC
```

This was registered minutes before GUESTCONFIRM7

```
Name: GUESTCONFIRM4.COM
Registry Domain ID: 2900241807_DOMAIN_COM-VRSN
Domain Status:
clientTransferProhibited
Nameservers:
MOLLY.NS.CLOUDFLARE.COM

TREVOR.NS.CLOUDFLARE.COM

Dates
Registry Expiration: 2025-07-18 10:19:11 UTC
Updated: 2024-07-18 10:22:50 UTC
Created: 2024-07-18 10:19:11 UTC
```

This one registered 8 hours before GUESTCONFIRM5

```
Name: GUESTCONFIRM3.COM
Registry Domain ID: 2900192609_DOMAIN_COM-VRSN
Domain Status:
clientTransferProhibited
Nameservers:
MOLLY.NS.CLOUDFLARE.COM

TREVOR.NS.CLOUDFLARE.COM

Dates
Registry Expiration: 2025-07-17 22:53:39 UTC
Updated: 2024-07-17 22:56:44 UTC
Created: 2024-07-17 22:53:39 UTC
```
```
Name: GUESTCONFIRM2.COM
Registry Domain ID: 2899896660_DOMAIN_COM-VRSN
Domain Status:
clientTransferProhibited
Nameservers:
MOLLY.NS.CLOUDFLARE.COM

TREVOR.NS.CLOUDFLARE.COM

Dates
Registry Expiration: 2025-07-16 21:38:45 UTC
Updated: 2024-07-16 21:46:18 UTC
Created: 2024-07-16 21:38:45 UTC
```
```
Name: GUESTCONFIRM1.COM
Registry Domain ID: 2899896232_DOMAIN_COM-VRSN
Domain Status:
clientHold
clientTransferProhibitedDates
Registry Expiration: 2025-07-16 21:32:01 UTC
Updated: 2024-07-19 02:05:47 UTC
Created: 2024-07-16 21:32:01 UTC
```

I will not list all of the domains, but I have identified at least guestconfirm2-9

## Main domain enumeration
I was able to access `https[:]//guestconfirm2[.]com/index[.]html`
![alt text](assets/img/lspmanagerbadbooking.png)

Which then led me to more enumeration, finding a roundcube webmail server hosted on /roundcube/
![alt text](assets/img/badbookingroundcube.png)

Version is `rcversion:10415`
# Actions Taken

I reported the intial domain to the registrar it was registered under, Dynadot.

I am also in the process of recording all the properties available on the site, so I might be able to inform those who aren't already aware that their account may be compromised. 

## Related Articles

I did some digging to see if this was reported elsewhere, finding some articles from late 2023, and funny enough from kaspersky:

https://www.kaspersky.com/blog/booking-com-hacked-hotel-accounts-scam-customers/50109/
https://www.bbc.com/news/technology-67591310

## Live Affected Properties:
```
Booking: B&B HOTEL Bordeaux Centre Bègles
1 Place des Terres Neuves 33130 Bègles France

Booking: Hotel Twenty-Three Amsterdam Airport
1007 Kruisweg 2131 CR Hoofddorp Netherlands

Booking: Hotel Liautaud
2 avenue victor hugo 13260 Cassis France

Booking: Hôtel Montecristo
20 Rue Pascal 5th arr. 75005 Paris France

Booking: Brit Hotel Bordeaux Arena
27 Chemin dArcins 33360 Latresne France

Booking: Hôtel Le Cardinal
3 rue du Cardinal Mercier 9th arr. 75009 Paris France

Booking: Ki Space Hotel & Spa - près de Disneyland Paris
4 Avenue Johannes Gutenberg 77700 Serris France

Booking: Fairlawn House
42 High Street Amesbury SP4 7DL United Kingdom

Booking: Boutique Hotel Jardines de Palerm
CAN PUJOL DEN CARDONA 34 07830 San Jose Spain

Booking: Pension Absolut Berlin
Erich-Weinert-Straße 26 Pankow 10439 Berlin Germany

Booking: Carathotel Düsseldorf City
Oststraße 155 Stadtmitte 40210 Düsseldorf Germany

Booking: La Boule dOr - Auberge créative
Place de Bethléem 5 58500 Clamecy France

Booking: Hotel The Lodge Vilvoorde
Rondeweg 3 1800 Vilvoorde Belgien

Booking: Spring River Ebbsfleet by Marstons Inns
Talbot Lane Gravesend DA10 1AZ United Kingdom

Booking: Tulip Inn Heerlen City Centre
Wilhelminaplein 17 6411 KW Heerlen Niederlande

Booking: The Loft Hostel Lavapies
4 Calle de la Esperanza Centro 28012 Madrid Spain

Booking: De Twee Linden
Zandstraat 100 6658 CX Beneden-Leeuwen Netherlands

Booking: Aethos Sardinia
Via Monti Corru 07020 Cannigione Italy

Booking: Commander Hotel & Suites
1401 Atlantic Acenue Ocean City 21842 United States of America

```