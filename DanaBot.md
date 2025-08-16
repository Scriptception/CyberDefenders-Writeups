# DanaBot

## Scenario

The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

## Questions

### 1. Which IP address was used by the attacker during the initial access?

Let's work out what the IP of the machine is, then filter for inbound connections to try and identify the attacker's address.

Looking at the PCAP, we see the IP `10.2.14.101` used a lot. Filtering on inbound traffic: `tshark -r 205-DanaBot.pcap -Y 'ip.dst==10.2.14.101' | less`, we can see the first connection in this PCAP is from `62.173.142.148`.

We can see this is inbound HTTP traffic ( `11   0.524731 62.173.142.148 → 10.2.14.101  HTTP 1482 HTTP/1.1 200 OK` ).

### 2. What is the name of the malicious file used for initial access?

We can inspect the HTTP response more closely with: `tshark -r 205-DanaBot.pcap -Y 'ip.src==62.173.142.148 && http.response' -V | less`.

Searching for 'filename' (type `/filename` to search), we can see the filename in the header: `allegato_708.js`.

Note that the request URI here is `login.php` which will be important in the next question.

### 3. What is the SHA-256 hash of the malicious file used for initial access?

We can grab the HTTP objects (files) from this pcap and export them using: `tshark -r 205-DanaBot.pcap -Y 'ip.src==62.173.142.148' --export-objects "http,./http_objects"`

Looking at the exports, we see the following list of files:

```
MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D
connecttest.txt
login.php
resources.dll
```

Note that there is no `allegato_708.js`, because tshark is saving as the request name, being `login.php`.

We can find the SHA256 sum using `sha256sum login.php`, giving us: `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

### 4. Which process was used to execute the malicious file?

This is obfuscated JavaScript. I used https://obf-io.deobfuscate.io/ to deobfuscate this code.

With the deobfuscate code, we can see it using `wscript`. Wscript is the Windows Script Host object that the malware uses to create COM components for downloading the payload, saving it to disk, and executing system commands.

The process is `wscript.exe`

### 5. What is the file extension of the second malicious file utilized by the attacker?

We can see the malware pull `http[:]//soundata[.]top/resources.dll`, so the extension is `.dll`

### 6. What is the MD5 hash of the second malicious file?

We already grabbed this from the PCAP earlier in question 3. We can run `md5sum resources.dll` to get the hash: `e758e07113016aca55d9eda2b0ffeebe`
