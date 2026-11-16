<img src="Images/Unit42%20-%20logo.png" width="277">

# Timeline

| Time (UTC) | Event | Artifact             | Action                                             | Process                      |
| ---------- | ----- | -------------------- | -------------------------------------------------- | ----------------------------- |
| 03:41:26   | 15    | FileCreateStreamHash | Payload downloaded, Zone.Identifier written (MotW) | `firefox.exe (4292)`         |
| 03:41:45   | 22    | DNS Query            | Dropbox domain resolved                            | `firefox.exe`                |
| 03:41:57   | 1     | Process Create       | Malicious binary executed                          | `Preventivo24.02.14.exe.exe` |
| 03:41:58   | 11    | File Create          | Dropped files incl. `once.cmd`                     | `Preventivo24.02.14.exe.exe` |
| 03:41:58   | 2     | FileCreateTime       | Timestomp (PDF + others)                           | `Preventivo24.02.14.exe.exe` |
| 03:41:58   | 22    | DNS Query            | Connectivity check (`www.example.com`)             | `Preventivo24.02.14.exe.exe` |
| 03:41:58   | 3     | Network Connect      | TCP to `93.184.216.34`                             | `Preventivo24.02.14.exe.exe` |
| 03:41:58   | 5     | Process Terminate    | Self-termination                                   | `Preventivo24.02.14.exe.exe` |

---
# Table of content

- [Scenario](#scenario)
- [Questions](#questions)
- [MITRE ATT&CK](#mitre-attck)

---
# Scenario

In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

To answer the questions in this lab, you will only need the Event Viewer, with VirusTotal as an optional supplement. Below are some important Sysmon Event IDs that can be utilized in your analysis:

- Event ID 1: Process Creation/Execution. Includes process path, parent process path, and command-line arguments.
- Event ID 2: File Creation Time Changed. Includes the file making the change, the file to which the change is being made, tampered timestamp, and original timestamp.
- Event ID 3: Network Connection. Includes the process making the connection, destination IP Address, and port.
- Event ID 5: Process Termination. Includes the name of the process that was killed or terminated itself.
- Event ID 11: File Created. Includes the process creating the file, the file being created, and its full path.
- Event ID 22: DNS Query. Includes the process querying the domain, the target domain name, and the IP Addresses they resolve to.

**Artifacts Provided**

unit42.zip: A ZIP file with SHA1 hash: 1D8AC45395551187EAF23793CE525056C4136D6E.

File can be downloaded [here](https://labs.hackthebox.com/api/v4/challenges/632/cdn/redirect?auth_user_id=2127339&expires=1791635781&signature=3ed965416000144f47c2af404005caeca6b959463c5f66980873e83b5184ba33).

# Questions

 1. **_How many Event logs are there with Event ID 11?_**

The number of events could be seen by converting the event log file to csv with `EvtxECmd.exe`.

```
.\EvtxECmd.exe -f "C:\Users\Makis\Desktop\Microsoft-Windows-Sysmon-Operational.evtx" --csv "C:\Users\Makis\Desktop\" --csvf sysmon.csv

<SNIP>

Event ID        Count
1               6
2               16
3               1
5               1
7               15
10              1
11              56
12              14
13              19
15              2
17              7
22              3
23              26
26              2

<SNIP>
```

**ANSWER** : `56`

2. **_Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?_**

Opening the outputed csv in **Timeline explorer**, and looking at the **Event ID 1** revealed that the user `CyberJunkie` executed the process `Preventivo24.02.14.exe.exe` on the victim system.

![Unit42 - Question 2](Images/Unit42%20-%20Question%202.png)

Taking the SHA1 hash of the process (`18A24AA0AC052D31FC5B56F5C0187041174FFC61`) and putting it in **Virus Total**, flagged it as malicious.

![Unit42 - Virus Total](Images/Unit42%20-%20Virus%20Total.png)

We also noticed the attacked used a masquerading technique (double `.exe`) to hide the malicious executable in explorer.

**ANSWER** : `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

**TIME** : `2024-02-14 03:41:57`

3. **_Which Cloud drive was used to distribute the malware?_**

We looked at the Event Id 22 which corresponds to the DNS query.

A query was made to **dropbox** at `2024-02-14 3:41:45`, before the process was launched. We can conclude the attacker used **dropbox** to distribute the malware.

![Unit42 - Question 3](Images/Unit42%20-%20Question%203.png)

Event 15 revealed the `Zone.Identifier` ADS: Firefox downloaded the payload from Dropbox (`ZoneId=3`, Mark of the Web) at 03:41:26 UTC

![Unit42 - firefox download](Images/Unit42%20-%20firefox%20download.png)

The full `HostUrl` in the Zone.Identifier stream confirms the download originated from `dl.dropboxusercontent.com`, directly tying this Event 15 artifact to Dropbox as the distribution service.

**ANSWER** : `dropbox`

**TIME** : `2024-02-14 03:41:45`

4. **_For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?_**

We can discover the old time along the new time set by the attacker by watching at the **Event Id 2** (File Creation Time Changed. Includes the file making the change, the file to which the change is being made, tampered timestamp, and original timestamp).

![Unit42 - Question 4](Images/Unit42%20-%20Question%204.png)

We noticed that the timestamp of several files, including pdf, were changed from `2024-02-14 03:41:58` to `2024-01-14 08:10:06`. Confirming the attacker used an anti-forensic technique.

**ANSWER** : `2024-01-14 08:10:06`

**TIME** : `2024-02-14 03:41:58`

5. **_The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename._**

Looking at **Event ID 11**, File Created. Includes the process creating the file, the file being created, and its full path.
And filtering the logs with file that contains `once.cmd`, revealed the full path of the filename.

![Unit42 - Question 5](Images/Unit42%20-%20Question%205.png)

**ANSWER** : `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`

**TIME** : `2024-02-14 03:41:58`

6. The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?

After checking the DNS query made after the attack started, revealed the following:

![Unit42 - Question 6](Images/Unit42%20-%20Question%206.png)

At `2024-02-14 03:41:58` a DNS query was done by `Preventivo24.02.14.exe.exe` to `www.example.com` to test for internet connection.

**ANSWER** : `www.example.com`

**TIME** : `2024-02-14 03:41:58`

7. Which IP address did the malicious process try to reach out to?

We looked at the Event ID 3, which concerns Network Connection and includes the process making the connection, destination IP Address, and port.

![Unit42 - Question 7](Images/Unit42%20-%20Question%207.png)

A connection attempt was done to `93.184.216.34` at `2024-02-14 03:41:58`.

**ANSWER** : `93.184.216.34`

**TIME** : `2024-02-14 03:41:58`

8. The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

We looked at the Event ID 5, process termination.

![Unit42 - Question 8](Images/Unit42%20-%20Question%208.png)

The process terminated at `2024-02-14 03:41:58` and concerned the process `Preventivo24.02.14.exe.exe` used by the attacker to execute his attack.

**ANSWER** : `2024-02-14 03:41:58`

**TIME** : `2024-02-14 03:41:58`

# MITRE ATT&CK

| Tactic                    | Technique (ID)                                                                        | Evidence in logs                                                                                     | Status                                               |
| ------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Initial Access / Delivery | Ingress Tool Transfer — **T1105**                                                     | Zone.Identifier ADS (Event 15, 3:41:26) exposes the Dropbox `HostUrl`; binary written by firefox.exe | Observed                                             |
| Execution                 | User Execution: Malicious File — **T1204.002**                                        | `CyberJunkie` runs `Preventivo24.02.14.exe.exe` (Event 1, 3:41:57)                                   | Observed                                             |
| Defense Evasion           | Masquerading: Double File Extension — **T1036.007**                                   | Double extension `.exe.exe` on the binary (Event 1)                                                  | Observed                                             |
| Execution                 | Command and Scripting Interpreter: Windows Command Shell — **T1059.003**              | `once.cmd` dropped (Event 11, 3:41:58)                                                               | Inferred (creation seen, execution not confirmed)    |
| Defense Evasion           | Indicator Removal: Timestomp — **T1070.006**                                          | PDF timestamp altered `2024-02-14 03:41:58` → `2024-01-14 08:10:06` (Event 2)                        | Observed                                             |
| Discovery                 | System Network Configuration Discovery: Internet Connection Discovery — **T1016.001** | Resolution of `www.example.com` (Event 22) + connection to `93.184.216.34` (Event 3), 3:41:58        | Observed                                             |
| Command and Control       | Remote Access Software — **T1219**                                                    | Backdoored UltraVNC variant dropped (scenario context)                                               | Inferred (payload not analyzed in the provided logs) |

![Unit42 - solved](Images/Unit42%20-%20solved.png)
