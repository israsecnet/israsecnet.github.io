---
title: 'An Investigation into Google Ads as a Phishing Vector'
date: 2025-06-06 13:25 -0400
categories: [phishing]
tags: [phishing, threat intelligence]
---

# Background
In recent times, Google Ads has become a prime target for phishing attacks. Threat actors are leveraging the platform’s credibility to deceive users and gain unauthorized access to sensitive information. In this post, I will delve into a recent Google Ads phishing campaign, examining how it operates, its impact, and how to protect yourself from falling victim.

## How does it work?
Google Ads phishing involves creating deceptive advertisements that appear legitimate but are designed to trick users into disclosing personal information or credentials. These ads often lead to fraudulent websites or login pages that mimic genuine services, aiming to steal data or install malware.

## Why doesn't Google prevent this?
Google Ads is a powerful platform for advertisers, but it faces challenges in fully preventing phishing attacks. One of the key issues lies in how ads and tracking URLs are handled.

**The Role of Tracking URLs**
When advertisers create Google Ads, they often use tracking URLs to monitor ad performance and user interactions. These URLs can direct users to an intermediate page or analytic website before reaching the final destination. While this tracking is crucial for measuring ad effectiveness and optimizing campaigns, it inadvertently creates a window of opportunity for malicious actors.

**How Tracking URLs Facilitate Phishing**
1. **Intermediate Redirects**:
    - **Phishing Setup**: Phishers can exploit the redirect process by placing their phishing pages behind these tracking URLs. When a user clicks on an ad, they are first sent to a tracking URL controlled by the attacker. From there, they are redirected to a fake login page or malicious site.
    - **Delay in Detection**: This intermediate redirect can delay the detection of phishing content, as the malicious page is not immediately visible to ad review systems. The delay provides attackers with a period to harvest user credentials before their fraudulent activity is detected.

2. **Challenge of URL Validation**:
    - **Dynamic URLs**: The dynamic nature of tracking URLs makes it difficult for automated systems to validate the final destination effectively. While Google employs sophisticated algorithms to detect and block phishing sites, the intermediate URLs can complicate the detection process.
    - **False Positives**: Aggressive filtering of tracking URLs may lead to false positives, where legitimate ads and tracking links are mistakenly flagged as suspicious. This can impact legitimate advertisers and disrupt ad campaigns.

**Google’s Efforts and Limitations**
Google takes significant measures to combat phishing and malicious ads, including:

- **Ad Review Processes**: Google uses automated systems and manual reviews to detect and block harmful ads. However, the complexity of tracking URLs can sometimes obscure malicious content.
- **User Reporting Tools**: Google provides mechanisms for users to report suspicious ads, which helps identify and address threats more effectively.

Despite these efforts, the sheer volume of ads and the evolving tactics of attackers pose ongoing challenges. The use of tracking URLs, while essential for analytics, inadvertently creates vulnerabilities that can be exploited by phishers.

# Case Study: Google Ad -> AppMetrica (Yandex) -> Azure Site -> Azure Blob Storage

## Redirection Process

![alt text](/assets/img/Pastedimage20240809165013.png)

- **Tracking URL**: The ad link led to an intermediate analytics site. These sites are used by advertisers to gather data on ad performance and user engagement.
```
https://redirect.appmetrica.yandex.com/serve/677429353537089616?campaign_id=9&pub_id=2&url=https://www.youtube.com/YOUTUBE%3Fgad_source%3D1&id={source}&gclid=CjwKCAjw_Na1BhAlEiwAM-dm7Elzv8NWE--ley5GwbiGnrSGAn8sT3v_pSK2E0vjrOlRNYG2TpANUBoCDG4QAvD_BwE
```
- **Secondary Redirect URL (Attacker Owned):**
```
https://new-day-new-music-now-dtc8dee5bte4gycy.eastus-01.azurewebsites.net/?referrer=appmetrica_tracking_id%3D677429353537089616%26ym_tracking_id%3D8312903728687775088
```
- **Final destination (Attacker Owned) - Malware:**
```
https://ddfdfd7667ss.blob.core.windows.net/$web/index.html?ph0n=1-888-734-0548&referrer=appmetrica_tracking_id%3D677429353537089616%26ym_tracking_id%3D8312903728687775088
```

## The Illusion of Legitimacy
In this case, the search result is displayed with a reputable display URL (e.g., youtube.com). If a user hovers over the link to inspect the destination before clicking:

**The Status Bar View**: The browser often displays the initial tracking URL or even the intended display domain, which looks legitimate (e.g., googleadservices.com or redirect.appmetrica.yandex.com).

**The Visual Cue**: To the average user, the only distinguishing factor between a safe organic result and this malicious redirect is the small "Sponsored" tag above the headline.

Key Takeaway: If a search result is labeled as "Sponsored," you cannot trust the URL preview shown at the bottom of your browser. Attackers utilize the "Tracking Template" feature in Google Ads to ensure the hover-over text points to a trusted domain, while the actual click triggers a silent redirect to their infrastructure.
{: .prompt-warning }
