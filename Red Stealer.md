---
Type: CTF
tags:
  - Type/Atom
  - status/done
  - difficulty/Easy
  - ctf/writeup
  - platform/CyberDefenders
  - Threat_Intel
created: 2025-08-22T22:11
Status: Done
Platform: CyberDefenders
Category: Threat Intel
Tactics:
  - Execution
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Discovery
  - Collection
  - Impact
Tools:
  - WhoIs
  - VirusTotal
  - MalwareBazaar
  - ThreatFox
  - ANY.RUN
---

# Red Stealer

## Overview

You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection. Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

## Questions / Walkthrough

### 1. Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

We get a hash: `248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B`

We can look this up in [VirusTotal](https://www.virustotal.com/gui/file/248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b/detection).

On the detections tab, we get a list of vendors and their categorisations for this file. Searching for `Microsoft`, we can see that they categorise it as a `Trojan`

### 2. Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?

In the summary part at the top of the page we see the filename: `WEXTRACT`. More information about the file can be seen in the **Details** tab.

### 3. Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware's first submission to VirusTotal?

This can be found in the **Details** tab: `2023-10-06 04:41`

### 4. Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?

Under the **Behaviors** tab, in the **MITRE ATT&CK Tactics and Techniques** section, we can expand the the **Collection** tactic to see the techniques.

We can see the first one (**Data from Local System** `T1005`)  with a description of (Process #14) applaunch.exe searches for sensitive data of web browser "Comodo IceDragon" by file. Giving us our answer: `T1005`

### 5. Following execution, which social media-related domain names did the malware resolve via DNS queries?

Again in the **Behavior** tab, we can see in the **Network Communication** section that it calls to `facebook.com`.

### 6. Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?

Still in the same section we can scroll down to **IP Traffic**. We can identify the connection in question by ruling out the known hosts, leaving us with `77.91.124.55:19071`. It's useful to understand common ports and protocols to identify these standouts.

### 7. YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "`Varp0s`" that detects the identified malware?

We can find this out on [Malware Bazaar](https://bazaar.abuse.ch), hitting browse, and searching with the hash: `sha256:248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b`

Click on the result (click the hash hyperlink) to view details for this malware, including Yara signatures. We can see the auth is `varp0s` as mentioned in the question. And the name of said Yara rule: `detect_Redline_Stealer `

### 8. Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to **ThreatFox**?

This is asking us to use [ThreatFox](https://threatfox.abuse.ch/), an IOC database and sharing platform. We can run a search for the malicious IP we identified earlier like so: `ioc:77.91.124.55`. Again, click on the result to view the entry.

Inside, we can see details about this IOC, including an alias: `RECORDSTEALER`

### 9. By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

Jumping back into VirusTotal, we can have a look at the **Modules Loaded** section under the **Behavior** tab. Now this takes a bit of investigation and understanding of DLLs. But I'd recommend doing so as it's a good way to learn these. Usually I'd recommend using [LOLBAS](https://lolbas-project.github.io/), but this one actually doesn't show up here.

Going through the list, we see `advapi32.
Description of this DLL:
> advapi32.dll is the Advanced Windows 32 Base API Dynamic Link Library, a core Windows component that provides security features and functions for manipulating the Windows Registry, managing user accounts, controlling services, and enabling system shutdowns and restarts.

Advapi32.dll lets malware gain higher system rights by calling built-in Windows functions that open and tweak its own user access token, enabling actions usually reserved for privileged accounts, like running as the system administrator.


## References

- [CTF Link](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/)