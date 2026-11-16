<img src="Images/WordpressWebForensics%20-%20Logo.png" width="240">

# Timeline

| Time (UTC)            | Event                                                                                               |
| --------------------- | --------------------------------------------------------------------------------------------------- |
| `2024-08-28 03:15:23` | `203.101.190.116` started a WPScan enumeration against the WordPress site hosted on `13.201.30.245` |
| `2024-08-28 03:50:33` | First failed login attempt on `/wordpress/wp-login.php`, start of the brute-force                   |
| `2024-08-28 03:50:40` | `302` response on `wp-login.php`, valid credentials obtained                                        |
| `2024-08-28 03:51:30` | Attacker accessed the WordPress dashboard                                                           |
| `2024-08-28 03:57:30` | Attacker opened the Theme File Editor                                                               |
| `2024-08-28 04:00:46` | `patterns/hidden-404.php` of the `twentytwentyfour` theme opened in the Theme File Editor           |
| `2024-08-28 04:03:46` | First request to `hidden-404.php` in the `twentytwentyfour` theme                                   |
| `2024-08-28 04:03:51` | First command run through the web shell                                                             |
| `2024-08-28 04:05:26` | Last request to the web shell observed in the logs                                                  |

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

> You are a DFIR (Digital Forensics and Incident Response) Analyst working for a corporation. A recent server breach has caused significant disruption in your digital environment. You are provided with a Splunk instance loaded with Apache2 access and error logs to investigate how the incident occurred. Allow 1-2 minutes after spawning for the services to start and then connect to the SIEM using `http://<ip>:8000`

## Artefacts

We started the Sherlock by spawning the Splunk instance, which was loaded with the Apache2 access and error logs.

# Tasks

## Task 1

**What is the attacker's IP address from which the WPScan enumeration originated?**

When running the query `index=* "wpscan"`, we could find the attacker's IP address.

![WordpressWebForensics - Task 1](Images/WordpressWebForensics%20-%20Task%201.png)

Its IP was `203.101.190.116`, and the attacker started to brute force `wp-login.php`.

**ANSWER:** `203.101.190.116`

## Task 2

**When did the attacker begin reconnaissance activity?**

We used the query

```
index=main clientip=203.101.190.116 "wpscan"
|  sort _time
```

And found that the attacker used **WPScan** for the first time on `2024-08-28 03:15:23`.

![WordpressWebForensics - Task 2](Images/WordpressWebForensics%20-%20Task%202.png)

**ANSWER:** `2024-08-28 3:15:23`

## Task 3

**What is the name and version of the tool used by the attacker?**

From one of the previous captures, we could identify that the attacker used `WPScan v3.8.25`, which was mentioned in the User-Agent, to perform the attack.

**ANSWER:** `WPScan v3.8.25`

## Task 4

**The attacker performed a brute-force attack on the WordPress login form. How many seconds did this activity last for before successfully obtaining valid credentials?**

We ran the following query

```
index=main clientip=203.101.190.116 method=POST file=wp-login.php status=200
|  sort _time
```

This filtered the attacker's POST requests on `wp-login.php` that returned a `200` status code. On the WordPress login form, a `200` means a failed attempt: WordPress simply displays the login page again with an error message. A successful login instead returns a `302` redirect to `/wp-admin/`.

We noted the timestamp of the first failed attempt, which marked the beginning of the brute-force.

![WordpressWebForensics - Task 4 part1](Images/WordpressWebForensics%20-%20Task%204%20part1.png)

Then we went to the last log. The last failed attempt happened at `03:50:40`, the same second as the `302` response already visible in the Task 1 capture, which showed that the attacker obtained valid credentials.

![WordpressWebForensics - Task 4 part2](Images/WordpressWebForensics%20-%20Task%204%20part2.png)

The brute-force ran from `2024-08-28 03:50:33` to `2024-08-28 03:50:40`, so it lasted 7 seconds.

**ANSWER:** `7`

## Task 5

**The attacker manipulated a WordPress theme file to maintain persistent access by uploading a web shell. Which WordPress theme was targeted?**

We ran this query to find every file ending with `.php` in the `themes` folder.

```
index=main clientip=203.101.190.116 uri=/wordpress/wp-content/themes/* file=*.php
| sort _time
```

WordPress loads theme files itself, through its own PHP code: a visitor never needs to request them directly. Any client requesting a `.php` file inside `wp-content/themes/` is therefore suspicious, especially with POST requests.

![WordpressWebForensics - Task 5](Images/WordpressWebForensics%20-%20Task%205.png)

We could identify that the attacker targeted the `twentytwentyfour` theme, and more precisely the file `hidden-404.php`. This file is a legitimate block pattern shipped with the theme, which made it a discreet place to hide a web shell: what gave it away was not its name, but the fact that the attacker requested it directly. The attacker reached this file multiple times, on `2024-08-28 04:03:46`, `2024-08-28 04:03:51`, `2024-08-28 04:03:55`, `2024-08-28 04:04:03`, and `2024-08-28 04:05:26`.

**ANSWER:** `twentytwentyfour`

## Task 6

**What is the name of the PHP theme file the attacker edited and used as a web shell entry point?**

We could find the answer from the previous task: `hidden-404.php` was used by the attacker as a web shell.

To confirm that, we enumerated the access of the theme editor by running this query

```
index=main clientip=203.101.190.116 uri="*theme-editor*" status=200
| sort _time 
| table _time method uri status
```

![WordpressWebForensics - Task 6](Images/WordpressWebForensics%20-%20Task%206.png)

The attacker opened the Theme File Editor at `03:57:30` and browsed several files, including the `twentytwentytwo` theme. At `04:00:46`, they opened `patterns/hidden-404.php` from the `twentytwentyfour` theme. Three minutes later, the attacker started to request the file directly.

**ANSWER:** `hidden-404.php`

## Task 7

**We see few POST requests to the suspected PHP file that the attacker supposedly edited. The evidence suggests that this is a webshell because the access to the URI is done with few seconds between each attempt, which could be the attacker running commands. When did the attacker first run a command? Provide an answer based on the patterns in the log.**

We modified our previous query, and searched for POST requests targeting `hidden-404.php`.

```
index=main clientip=203.101.190.116 method=POST file=hidden-404.php
| sort _time
```

![WordpressWebForensics - Task 7](Images/WordpressWebForensics%20-%20Task%207.png)

We found out that the attacker ran a command for the first time on `2024-08-28 04:03:51`.

**ANSWER:** `2024-08-28 04:03:51`

## Task 8

**List the user-agent used to access the webshell.**

We modified the fields displayed by our previous query to show the User-Agent used by the attacker to access the web shell.

![WordpressWebForensics - Task 8](Images/WordpressWebForensics%20-%20Task%208.png)

The User-Agent was `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0`.

**ANSWER:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0`

# Indicators of Compromise

|Type|Indicator|Context|
|---|---|---|
|IP|`203.101.190.116`|Source of the enumeration, the brute-force and the web shell access|
|User-Agent|`WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)`|Enumeration and brute-force|
|User-Agent|`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0`|Web shell access (common browser UA, only meaningful combined with the IP)|
|URI|`/wordpress/wp-content/themes/twentytwentyfour/patterns/hidden-404.php`|Theme file turned into a web shell|
|Pattern|Burst of `POST /wordpress/wp-login.php` from a single IP|Brute-force of the login form|

# MITRE ATT&CK

|Tactic|ID|Technique|Evidence|
|---|---|---|---|
|Reconnaissance|T1595.002|Active Scanning: Vulnerability Scanning|Requests with the `WPScan v3.8.25` User-Agent from `03:15:23`|
|Credential Access|T1110.001|Brute Force: Password Guessing|Burst of failed `POST /wordpress/wp-login.php` (`200`) from `03:50:33` to `03:50:40`|
|Initial Access|T1078|Valid Accounts|`302` redirect to `/wp-admin/` at `03:50:40` after the brute-force|
|Persistence|T1505.003|Server Software Component: Web Shell|`hidden-404.php` of the `twentytwentyfour` theme edited and requested directly|
|Defense Evasion|T1036.005|Masquerading: Match Legitimate Name or Location|Web shell hidden in a legitimate file of the theme|
|Execution|T1059|Command and Scripting Interpreter|POST requests to the web shell a few seconds apart from `04:03:51` (commands not visible, as POST bodies are not logged)|

# Remediation

|Priority|Action|Detail|
|---|---|---|
|High|Remove the web shell|Restore `hidden-404.php` from a clean copy of `twentytwentyfour` (or reinstall the theme) and check the integrity of the core, themes and plugins (`wp core verify-checksums`)|
|High|Reset the credentials|Change the password of the compromised account and of every administrator, then renew the salts in `wp-config.php` to invalidate existing sessions|
|High|Block the attacker|Block `203.101.190.116` on the firewall or the WAF|
|High|Scope the compromise|Review the error logs and the system logs to find the commands run through the web shell and any additional persistence|
|Medium|Disable the theme editor|Add `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php` so that an admin account cannot modify PHP files from the dashboard|
|Medium|Protect the login form|Rate limiting or lockout on `wp-login.php` (e.g. Fail2ban), MFA for administrators, restrict `/wp-admin/` to trusted IPs or a VPN|
|Medium|Detection rules|Alert on the WPScan User-Agent, on bursts of POST requests to `wp-login.php` and on direct requests to `.php` files under `wp-content/themes/`|
|Low|Hardening|Keep WordPress and its themes up to date, remove unused themes and plugins, block user enumeration|
