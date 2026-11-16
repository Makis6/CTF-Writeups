<img src="Images/Reaper%20-%20Logo.png" width="205">

# Timeline

| Time (UTC) | Source               | Event                                                                                                                                                                                            | ATT&CK    | Ref                                             |
| ---------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ----------------------------------------------- |
| 04:55:13   | pcap                 | NTLM exchange between `arthur.kyle` and the unknown host `172.17.79.135`: the user's NTLMv2 hash is captured                                                                                     | T1557.001 | [Task 3](#task-3) [Task 4](#task-4)                         |
| 04:55:16   | Security.evtx (4624) | Network logon (type 3) as `arthur.kyle` from `172.17.79.135`, presenting the workstation name `FORELA-WKSTN002` (the real WKSTN002 is `172.17.79.136`). Source port `40252`, Logon ID `0x64A799` | T1078.002 | [Task 6](#task-6) [Task 7](#task-7) [Task 8](#task-8) [Task 9](#task-9) |
| 04:55:16   | Security.evtx (5140) | Share `\\*\IPC$` accessed within the malicious session                                                                                                                                           | T1021.002 | [Task 10](#task-10)                                    |
| 04:55:28   | pcap                 | SMB2 connection attempt to `\\DC01\Trip` answered with `STATUS_BAD_NETWORK_NAME`                                                                                                                 | -         | [Task 5](#task-5)                                     |

---
# Table of Content

- [Intro](#intro)
- [Scenario](#scenario)
- [Tasks](#tasks)
	- [Task 1](#task-1)
	- [Task 2](#task-2)
	- [Task 3](#task-3)
	- [Task 4](#task-4)
	- [Task 5](#task-5)
	- [Task 6](#task-6)
	- [Task 7](#task-7)
	- [Task 8](#task-8)
	- [Task 9](#task-9)
	- [Task 10](#task-10)
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Remediation](#remediation)
	- [Immediate Actions](#immediate-actions)
	- [Hardening](#hardening)
	- [Detection](#detection)

---
# Intro

We started the challenge with two artefacts.

- `Security.evtx` (Event log)
- `ntlmrelay.pcapng` (Network capture)

# Scenario

Our SIEM alerted us to a suspicious logon event which needs to be looked at immediately . The alert details were that the IP Address and the Source Workstation name were a mismatch .You are provided a network capture and event logs from the surrounding time around the incident timeframe. Corelate the given evidence and report back to your SOC Manager.

# Tasks

## Task 1

**What is the IP Address for Forela-Wkstn001?**

Opening the given pcapng file with **Wireshark**. We searched for the string **Forela-Wkstn001**.

![Reaper - task 1](Images/Reaper%20-%20task%201.png)

**ANSWER** : `172.17.79.129`

## Task 2

**What is the IP Address for Forela-Wkstn002?**

Doing the same process as the task before revealed the answer.

![Reaper - task 2](Images/Reaper%20-%20task%202.png)

**ANSWER** : `172.17.79.136`

## Task 3

**What is the username of the account whose hash was stolen by attacker?**

To check the NTLM exchanges, we filtered the traffic for `ntlmssp`.

![Reaper - task 3](Images/Reaper%20-%20task%203.png)

The exchanges confirmed that the user `arthur.kyle` was targeted, and his hash was stolen on `07/31/2024` at `04:55:13` UTC.

The unknown host answered a name resolution request and received the victim's NTLMv2 challenge/response.

**ANSWER** : `arthur.kyle`

## Task 4

**What is the IP Address of Unknown Device used by the attacker to intercept credentials?**

We could find the answer on the screenshot in the previous task.

We noticed several connections between **172.17.79.135**, the unknown machine, and the 2 hosts.

**ANSWER** : `172.17.79.135`

## Task 5

**What was the fileshare navigated by the victim user account?**

We filtered the traffic for `smb2`, and searched for the string `BAD_NETWORK_NAME`.

![Reaper - Task 5](Images/Reaper%20-%20Task%205.png)

A connection to `\\DC01\Trip` was attempted on `2024-07-31 04:55:28`.

**ANSWER** : `\\DC01\Trip`

## Task 6

**What is the source port used to logon to target workstation using the compromised account?**

```
.\EvtxECmd.exe -f C:\Users\Makis\Desktop\Reaper\Security.evtx --csv C:\Users\Makis\Desktop\Reaper\ --csvf Reaper.csv
```

After converting the file to be read in **Timeline Explorer**, we filtered the event ID to **4624** (Logon successful), we noticed a line where the user `arthur.kyle` connected over the network (**Logon Type 3**).

![Reaper - Task 6 pt1](Images/Reaper%20-%20Task%206%20pt1.png)

When looking at the details, the IpPort was `40252`.

![Reaper - task 6 pt2](Images/Reaper%20-%20task%206%20pt2.png)

**ANSWER** : `40252`

## Task 7

**What is the Logon ID for the malicious session?**

The Logon ID was on the screenshot in the previous task.

**ANSWER** : `0x64A799`

## Task 8

**The detection was based on the mismatch of hostname and the assigned IP Address. What is the workstation name and the source IP Address from which the malicious logon occur?**

The answer was in the column **Remote Host**.

![Reaper - Task 8](Images/Reaper%20-%20Task%208.png)

**ANSWER** : `FORELA-WKSTN002, 172.17.79.135`

## Task 9

**At what UTC time did the malicious logon happen?**

The connection was made at `2024-07-31 04:55:16`.

![Reaper - Task 9](Images/Reaper%20-%20Task%209.png)

**ANSWER** : `2024-07-31 04:55:16`

## Task 10

**What is the share Name accessed as part of the authentication process by the malicious tool used by the attacker?**

We had to filter for event **5140 (network share object was accessed)**.

![Reaper - Task 10](Images/Reaper%20-%20Task%2010.png)

The share `\\*\IPC$` was accessed by the attacker at `2024-07-31 04:55:16`.

**ANSWER** : `\\*\IPC$`

---

# Indicators of Compromise

| Type        | Value             | Context                                                                                                                             |
| ----------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| IP address  | `172.17.79.135`   | Rogue device that intercepted the credentials                                                                                       |
| Account     | `arthur.kyle`     | Account whose NTLM hash was stolen                                                                                                  |
| Hostname    | `FORELA-WKSTN002` | Victim's workstation name, carried in the relayed NTLM message and therefore seen with the attacker's IP (legit IP `172.17.79.136`) |
| Logon ID    | `0x64A799`        | Malicious logon session                                                                                                             |
| Source port | `40252`           | Port used for the malicious logon                                                                                                   |
| Share       | `\\*\IPC$`        | Share accessed during authentication by the attacker's tool                                                                         |

# MITRE ATT&CK Mapping

|Tactic|Technique ID|Technique|Evidence|
|---|---|---|---|
|Credential Access|T1557.001|Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay|Unknown host `172.17.79.135` receives the NTLM authentication of `arthur.kyle` (pcap, `ntlmssp`)|
|Defense Evasion / Persistence|T1078.002|Valid Accounts: Domain Accounts|Successful type 3 logon with `arthur.kyle`'s credentials (event 4624)|
|Lateral Movement|T1021.002|Remote Services: SMB/Windows Admin Shares|`\\*\IPC$` accessed during the malicious session (event 5140)|

# Remediation

## Immediate Actions

|Priority|Action|Goal|
|---|---|---|
|1|Isolate `172.17.79.135` and locate the physical device (switch port, DHCP lease)|Stop the ongoing interception|
|2|Reset `arthur.kyle`'s password and terminate his active sessions, including Logon ID `0x64A799`|Invalidate the stolen credentials|
|3|Review all activity of the account after 04:55:16 (events 4624, 4672, 5140, 5145 across the domain)|Scope what the attacker did|
|4|Hunt for other NTLM authentications sent to `172.17.79.135`|Identify other compromised users|

## Hardening

|Measure|How|Counters|
|---|---|---|
|Disable LLMNR|GPO: `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution`|T1557.001|
|Disable NBT-NS|Network adapter settings (`Disable NetBIOS over TCP/IP`) or DHCP option|T1557.001|
|Require SMB signing|GPO: `Microsoft network server/client: Digitally sign communications (always)` on all hosts, not only DCs|T1557.001 (relay)|
|Reduce NTLM usage|Enforce NTLMv2 only (`LmCompatibilityLevel = 5`), audit NTLM, then restrict it in favour of Kerberos|T1557.001|
|Strengthen credentials|Long passwords (14+ characters), MFA|T1078.002|
|Network access control|802.1X / NAC, DHCP snooping, port security|T1557.001 (rogue device)|

## Detection

|Detection|Data Source|Event IDs|Technique|
|---|---|---|---|
|Type 3 logon where the workstation name and source IP do not match DNS/DHCP records|Windows Security logs|4624|T1078.002|
|LLMNR/NBT-NS responses from hosts not expected to answer them|Network traffic (UDP 5355 / 137)|-|T1557.001|
|Canary: periodic query for a non-existent name, alert if anyone answers|Custom script / honeytoken|-|T1557.001|
|Unusual access to `IPC$` or admin shares|Windows Security logs|5140, 5145|T1021.002|
|NTLM authentication anomalies|DC Security logs|4624, 4625, 4776|T1557.001, T1078.002|

![Reaper - solved](Images/Reaper%20-%20solved.png)
