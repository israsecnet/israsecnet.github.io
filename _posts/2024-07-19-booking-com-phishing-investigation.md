---
title: Booking.com Phishing Investigation
date: 2024-07-19 22:32 -0400
categories: [phishing]
tags: [phishing, threat intelligence]
---

# Warning !
This campaign is most likely still live and you should visit the links below with caution!

# Intro
I like receiving phishing emails, let's investigate this specific campaign I stumbled upon.

# First look
The email comes in impersonating the booking\[.]com website. They did a good job as it was able to get into my inbox! It prompts for a reservation to be completed or it will be cancelled, and then provides an ID and a link to follow. 

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
payment_card_status.php
send_msg.php # Used to send messages in chat
user_send_status.php
```

Investigation continues.... stay posted for updates!