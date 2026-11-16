<img src="Images/RomCom%20-%20Logo.png" width="240">

# Timeline

|Timestamp (UTC)|Event|Source|Task|
|---|---|---|---|
|2025-09-02 08:13:50|The archive `Pathology-Department-Research-Records.rar` was created in `C:\Users\susan\Documents\`|`$MFT` (`Created0x10`)|[Task 4](#task-4)|
|2025-09-02 08:14:04|The archive was opened by Susan, which triggered the exploitation of `CVE-2025-8088`|`$MFT` (`Last Modified`)|[Task 5](#task-5)|
|2025-09-02 08:14:18|The decoy document `Genotyping_Results_B57_Positive.pdf` was extracted into `C:\Users\susan\Documents\`|`$MFT` (`Created0x10`)|[Task 6](#task-6)|
|2025-09-02 08:14:18|The backdoor `ApbxHelper.exe` was dropped in `C:\Users\Susan\AppData\Local\`|`$MFT` (`Created0x10`)|[Task 7](#task-7)|
|2025-09-02 08:14:18|The persistence file `Display Settings.lnk` was dropped in the user's Startup folder|`$MFT` (`Created0x10`)|[Task 8](#task-8)|
|2025-09-02 08:15:05|Susan opened the decoy document (a `.lnk` file referencing it was created)|`$MFT` (`Created0x10` of the `.lnk`)|[Task 10](#task-10)|

# Table of Contents

- [Timeline](#timeline)
- [Introduction](#introduction)
    - [Scenario](#scenario)
    - [Artefacts](#artefacts)
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
- [MITRE ATT&CK](#mitre-attck)
- [Remediation](#remediation)

---

# Introduction

## Scenario

> Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the Software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.

## Artefacts

We started the Sherlock with the `RomCom.zip` file. It contained a file called `2025-09-02T083211_pathology_department_incidentalert.vhdx`, a hard disk image file (VHDX).

# Tasks

## Task 1

**What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?**

Searching online for a WinRAR vulnerability exploited by `RomCom` in 2025 led us to `CVE-2025-8088`. ESET researchers discovered it on July 18, 2025, when they saw RomCom exploiting it as a zero-day in spearphishing campaigns ([ESET research](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)).

**ANSWER:** `CVE-2025-8088`

## Task 2

**What is the nature of this vulnerability?**

`CVE-2025-8088` is a high-severity **path traversal** vulnerability (CVSS 8.8 under v3.1) affecting the Windows versions of **WinRAR** up to 7.12, as well as related components such as `UnRAR.dll`. It was patched in **WinRAR 7.13**, released on July 30, 2025.

The flaw comes from the way WinRAR handles **Alternate Data Streams (ADS)** during extraction. In a crafted archive, the names of these streams can contain relative paths, so the payloads they hold are written outside the extraction folder, in arbitrary locations such as the **Windows Startup folder** or `%TEMP%`. This led to arbitrary code execution with the privileges of the user who extracted the archive.

**ANSWER:** `Path Traversal`

## Task 3

**What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?**

We could only access a limited number of files in the hard disk image, but the `$MFT` was available at the root of the `C:` drive. We parsed it with Eric Zimmerman's `MFTECmd` to convert it to a CSV file:

```
.\MFTECmd.exe -f E:\C\$MFT --csv C:\Users\Makis\Desktop --csvf MFT_artefact.csv
```

We then loaded the CSV file into `Timeline Explorer` and filtered the `File Name` column for entries ending with `.rar`. This revealed the file `Pathology-Department-Research-Records.rar` in `susan`'s Documents folder.

![RomCom - Task 3](Images/RomCom%20-%20Task%203.png)

**ANSWER:** `Pathology-Department-Research-Records.rar`

## Task 4

**When was the archive file created on the disk?**

On the same line, the `Created0x10` column showed that the archive was created on `2025-09-02 08:13:50`. This is the moment the file was written to the disk of the machine.

![RomCom - Task 4](Images/RomCom%20-%20Task%204.png)

**ANSWER:** `2025-09-02 08:13:50`

## Task 5

**When was the archive file opened?**

The `$MFT` does not record an explicit "open" event. We therefore used the `Last Modified` field as the closest indicator, which showed `2025-09-02 08:14:04`. This is consistent with the rest of the timeline, since the files dropped by the exploit appeared 14 seconds later.

![RomCom - Task 5](Images/Romcom%20-%20Task%205.png)

**ANSWER:** `2025-09-02 08:14:04`

## Task 6

**What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?**

We filtered the `Parent Path` column on `susan\Documents` to list the files and directories in this folder. Looking at their timestamps, we noticed that `Genotyping_Results_B57_Positive.pdf` was created on `2025-09-02 08:14:18`, 14 seconds after the archive was opened. It was therefore most likely the decoy document used by the attacker to distract the user.

![RomCom - Task 6](Images/RomCom%20-%20Task%206.png)

**ANSWER:** `Genotyping_Results_B57_Positive.pdf`

## Task 7

**What is the name and path of the actual backdoor executable dropped by the archive file?**

We filtered for `.exe` files created from `2025-09-02 08:14:18` onwards.

![RomCom - Task 7](Images/RomCom%20-%20Task%207.png)

This revealed `ApbxHelper.exe` under `.\Users\susan\AppData\Local`, created at the exact same timestamp as `Genotyping_Results_B57_Positive.pdf`. Its creation time and its location, a user-writable folder that does not hold standard software installations, correlated with the backdoor dropped by the attacker. ESET also reported an identical `ApbxHelper.exe` in another archive exploiting `CVE-2025-8088`, which supports this finding.

**ANSWER:** `C:\Users\Susan\AppData\Local\ApbxHelper.exe`

## Task 8

**The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?**

We searched for files created at `2025-09-02 08:14:18` and found a file called `Display Settings.lnk` under `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`.

Items in this folder are executed automatically when the user logs on. Placing a shortcut there is a common technique used by attackers to keep persistence on the machine, as it makes sure the backdoor is launched at every logon.

![RomCom - Task 8](Images/RomCom%20-%20Task%208.png)

**ANSWER:** `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

## Task 9

**What is the associated MITRE Technique ID discussed in the previous question?**

The technique matching the previous task is [Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/), with the ID `T1547.009`. It covers shortcut files that an attacker creates or modifies in order to execute a program during system boot or user logon. The use of the Startup folder itself is also referenced by [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Registry Run Keys / Startup Folder).

**ANSWER:** `T1547.009`

## Task 10

**When was the decoy document opened by the end user, thinking it to be a legitimate document?**

After filtering by the name of the decoy document in `Timeline Explorer`, we saw that a `.lnk` file referencing it had been created on `2025-09-02 08:15:05`. Windows creates such a shortcut in the user's Recent folder when a file is opened, so this timestamp corresponds to the moment Susan opened the decoy document, about 47 seconds after it was extracted.

![RomCom - Task 10](Images/RomCom%20-%20Task%2010.png)

**ANSWER:** `2025-09-02 08:15:05`

# Indicators of Compromise

|Type|Indicator|Description|
|---|---|---|
|File path|`C:\Users\susan\Documents\Pathology-Department-Research-Records.rar`|Malicious RAR archive exploiting `CVE-2025-8088`|
|File path|`C:\Users\susan\Documents\Genotyping_Results_B57_Positive.pdf`|Decoy document extracted from the archive|
|File path|`C:\Users\Susan\AppData\Local\ApbxHelper.exe`|Backdoor executable dropped by the exploit|
|File path|`C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`|Shortcut dropped in the Startup folder for persistence|

# MITRE ATT&CK

|Tactic|Technique ID|Technique|Evidence|
|---|---|---|---|
|Initial Access|`T1566.001`|Phishing: Spearphishing Attachment|Susan received the malicious archive (see Scenario). The email delivery was not confirmed in the triage image, but ESET reported spearphishing for this campaign|
|Execution|`T1204.002`|User Execution: Malicious File|Susan opened the archive (`2025-09-02 08:14:04`) and the decoy document (`2025-09-02 08:15:05`)|
|Execution|`T1203`|Exploitation for Client Execution|Opening the archive exploited `CVE-2025-8088` in WinRAR, which caused the extraction errors reported by Susan|
|Defense Evasion|`T1564.004`|Hide Artifacts: NTFS File Attributes|The exploit hides its payloads in Alternate Data Streams of the archive (as reported by ESET)|
|Persistence|`T1547.009`|Boot or Logon Autostart Execution: Shortcut Modification|`Display Settings.lnk` was dropped to launch the backdoor|
|Persistence|`T1547.001`|Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder|The shortcut was written into the user's Startup folder|

# Remediation

|Phase|Action|Details|
|---|---|---|
|Containment|Isolate Susan's workstation|Cut the machine off from the network, for example through Microsoft Defender for Endpoint, as the backdoor ran in her user session. Keep the disk image for further analysis|
|Containment|Reset credentials|Reset Susan's password, revoke her active sessions and tokens, and review the accounts that were used from this machine|
|Eradication|Remove the payload and persistence|Delete `ApbxHelper.exe` and `Display Settings.lnk`. Reimaging the workstation is preferable, as the full extent of the compromise is unknown|
|Eradication|Hunt across the environment|Search every endpoint for the indicators listed above and for files created by `WinRAR.exe` in Startup folders or in `AppData`|
|Prevention|Update WinRAR|Upgrade all installations to version 7.13 or later (including `UnRAR.dll` based tools). WinRAR has no auto-update mechanism, so an inventory of installed versions is needed|
|Prevention|Filter email attachments|Block or detonate in a sandbox the RAR archives received from external senders|
|Prevention|Raise user awareness|Train staff to report unexpected archives and errors during extraction, like the ones Susan noticed|
|Detection|Monitor persistence locations|Alert on `.lnk` files created in the Startup folder and on `.exe` files written to `AppData\Local` by `WinRAR.exe` (EDR or Sigma rule)|
|Detection|Review network logs|Check proxy, firewall and EDR logs from `2025-09-02 08:14` onwards for outbound connections from this host, as the triage image does not show the backdoor's command and control|
