<img src="Images/Shellshock%20Attack%20-%20Logo.png" width="240">

# Timeline

| Packet | Event                                                                                                          |
| ------ | -------------------------------------------------------------------------------------------------------------- |
| 11     | HTTP request from `10.246.50.2` to `10.246.50.6` carrying the Shellshock payload (`/bin/ping -c1 10.246.50.2`) |
| 13     | ICMP echo request from `10.246.50.6` to `10.246.50.2`, triggered by the payload                                |
| 14     | ICMP echo reply from `10.246.50.2` to `10.246.50.6`                                                            |
| 15     | HTTP response from `10.246.50.6`, exposing the OS and the Apache version                                       |

# Table of Contents

- [Timeline](#timeline)
- [Introduction](#introduction)
- [Scenario](#scenario)
- [Artefacts](#artefacts)
- [Tasks](#tasks)
	- [Task 1](#task-1)
	- [Task 2](#task-2)
	- [Task 3](#task-3)
- [Indicators of Compromise](#indicators-of-compromise)
- [MITRE ATT&CK](#mitre-attck)
- [Remediation](#remediation)

---
# Introduction

# Scenario

> Use the provided log files to analyse ShellShock attacks

# Artefacts

We started the Sherlock with the `Shellshock_Attack.zip` file. It contained a network capture called `shellshock.pcap`.

# Tasks

## Task 1

**What is the server operating system?**

We found the operating system of the server by looking at packet 15, in the `Hypertext Transfer Protocol` section.

![Shellshock Attack - Task 1](Images/Shellshock%20Attack%20-%20Task%201.png)

The server operating system was `Ubuntu`.

**ANSWER:** `ubuntu`

## Task 2

**What is the application server and version running on the target system?**

In the same packet, we could see the application server and its version.

**ANSWER:** `apache/2.2.22`

## Task 3

**What is the exact command that the attacker wants to run on the target server?**

The command executed by the attacker on the server was in packet 11.

![Shellshock Attack - Task 3](Images/Shellshock%20Attack%20-%20Task%203.png)

The attacker ran the command `/bin/ping -c1 10.246.50.2`, and packets 13 and 14 show that it was successful, with a ping request and a reply.

**ANSWER:** `/bin/ping -c1 10.246.50.2`

# Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| IP address | `10.246.50.2` | Attacker: source of the malicious HTTP request, and destination of the ping triggered on the server |
| Command | `/bin/ping -c1 10.246.50.2` | Command injected through the Shellshock payload (packet 11) |
| String | `() { :; };` | Bash function-definition pattern that starts a Shellshock payload |

# MITRE ATT&CK

| Tactic | ID | Technique | Evidence |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Shellshock (CVE-2014-6271) exploited through an HTTP request to Apache 2.2.22 (packet 11) |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Bash executed the injected command `/bin/ping -c1 10.246.50.2` |

# Remediation

| Priority | Action | Detail |
|---|---|---|
| High | Patch Bash | Update Bash to a version fixing CVE-2014-6271 and the follow-up CVEs (for example CVE-2014-7169) |
| High | Remove or disable unneeded CGI | Disable `mod_cgi` if unused, and remove Bash-based CGI scripts exposed to users |
| High | Check for further compromise | The capture only shows a `ping`, so review web, auth and process logs for later commands, new accounts or persistence |
| Medium | Upgrade Apache | Apache 2.2.x is end-of-life; migrate to a supported 2.4.x release |
| Medium | Update the operating system | Move the server to a supported Ubuntu release that still receives security updates |
| Medium | Add detection | Create WAF/IDS rules (ModSecurity, Suricata, Snort) matching `() {` in HTTP headers and in request parameters |
| Medium | Restrict egress traffic | Block outbound ICMP and other unneeded connections from the web server |
| Low | Apply least privilege | Run Apache under an unprivileged account and confine it with AppArmor |
