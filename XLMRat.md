# XLMRat

## Scenario

A compromised machine has been flagged due to suspicious network traffic. Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

## Questions

### 1. The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

Run Tshark against the pcap to filter for HTTP requests:

```bash
tshark -r 236-XLMRat.pcap -Y http.request
    4   0.295141   10.1.9.101 → 45.126.209.4 HTTP 357 GET /xlm.txt HTTP/1.1
   12   1.585563   10.1.9.101 → 45.126.209.4 HTTP 127 GET /mdm.jpg HTTP/1.1
```

We see two. Let's get more details with `tshark -r 236-XLMRat.pcap -Y http.request -V`

We see the full request URI for the second call giving us the answer to question 1:

`[Full request URI: http://45.126.209.4:222/mdm.jpg]`


### 2. Which hosting provider owns the associated IP address?

We can use the `whois` command to quickly get this information.

```bash
➜  XLMRat whois 45.126.209.4 | grep -Ei 'org-name|OrgName|descr|netname|country'
netname:        RELIABLESITE-AP
descr:          ReliableSite.Net LLC
country:        SG
org-name:       ReliableSite.Net LLC
country:        US
country:        ZZ
country:        US
descr:          2115 NW 22nd St
```

### 3. By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

We can use tshark to capture a copy of the files from the HTTP requests in the PCAP: `tshark -r capture.pcap --export-objects "http,./http_files"`

These aren't executables. So we analyze the contents, and see that `mdm.jpg` contains a hex string which is decoded as an action of the malware.

So let's decode it ourselves. We grab that hex string and output it to a file: `grep -i hex_string -m1 mdm.jpg > hex`

Clean it up so it's just the hex string itself. Remove the underscores as well. (i.e. `sed s/_//g`)

And convert to a binary with `xxd -r -p hex > output.bin`

We can see we get a .net executable, and we can hash it for our flag:

```bash
➜  http_files file output.bin
output.bin: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
➜  http_files sha256sum output.bin
1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798  output.bin
```

### 4. What is the malware family label based on Alibaba?

Now that we have the hash, we can search it in VirusTotal

We can see that it's of the family `asyncrat`

### 5. What is the timestamp of the malware's creation?

Still in VirusTotal, under the details tab, we get more information, including the creation time: `2023-10-30 15:08`

### 6. Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

LOLBins (Living off the Land Binaries) are legitimate Windows executables that are abused to run malicious code, bypassing measures such as app whitelisting.

So we scan `mdm.jpg` for calls to such binaries, and we find

```
$AC = $NA + 'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe'-replace  '#', ''
```

Cleaning this up, we get:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
```

RegSvcs.exe is normally used to register .NET assemblies, but can be abused to load arbitrary assemblies without touching obvious execution paths.


### 7. The script is designed to drop several files. List the names of the files dropped by the script.

Again in the `mdm.jpg` file, we can see write actions:

```bash
➜  http_files grep -i WriteAll mdm.jpg
[IO.File]::WriteAllText("C:\Users\Public\Conted.ps1", $Content)
[IO.File]::WriteAllText("C:\Users\Public\Conted.bat", $Content)
[IO.File]::WriteAllText("C:\Users\Public\Conted.vbs", $Content)
```
