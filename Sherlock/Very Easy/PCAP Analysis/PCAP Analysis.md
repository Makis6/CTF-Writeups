<img src="Images/PCAP%20Analysis%20-%20Logo.png" width="240">

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

---
# Introduction

## Scenario

> We have captured this traffic from P13's computer. Can you help him?

## Artefacts

We started the Sherlock with the `PCAP_Analysis.zip` file. It contained a file called `Pcap_Analysis.pcapng`.

# Tasks

## Task 1

**In network communication, what are the IP addresses of the sender and receiver?**

We imported the given file in Wireshark and filtered the traffic with `frame contains "P13"`, which revealed the following TCP stream.

The `contains` operator searches the raw bytes of every frame for the given string, regardless of the protocol. It is a quick way to locate a conversation when we only know a name or a keyword, as long as the data was not encrypted.

![PCAP Analysis - Task 1](Images/PCAP%20Analysis%20-%20Task%201.png)

It was a conversation between `P13` and `Cu713` about a script hidden somewhere. Since the messages were sent in cleartext, we could read them directly in the TCP stream. The exchanges were between `192.168.235.137` and `192.168.235.131`.

**ANSWER:** `192.168.235.137,192.168.235.131`

## Task 2

**P13 uploaded a file to the web server. What is the IP address of the server?**

File uploads over HTTP are almost always sent with the POST method, the file being carried in the body of the request. We therefore filtered the traffic to show only the POST requests.

```
http.request.method == "POST"
```

We found a POST request to `/panel.php` made from `192.168.235.137` (P13's IP) to `192.168.1.7`, which indicated that this IP belonged to the web server.

![PCAP Analysis - Task 2](Images/PCAP%20Analysis%20-%20Task%202.png)

**ANSWER:** `192.168.1.7`

## Task 3

**What is the name of the file that was sent through the network?**

When a file is uploaded through an HTML form, the browser encodes the request body as `multipart/form-data`. Each part of the body starts with a `Content-Disposition` header, which holds the name of the form field and the original name of the uploaded file. Wireshark decodes these parts under `MIME Multipart Media Encapsulation`.

We could see the name of the file by inspecting this section of the previous packet.

![PCAP Analysis - Task 3](Images/PCAP%20Analysis%20-%20Task%203.png)

The filename was `file`.

**ANSWER:** `file`

## Task 4

**What web server software is running on the target machine?**

By following the TCP stream of the upload to the web server, we identified `Apache/2.4.54` as the software running on it, thanks to the `Server:` field in the response headers.

![PCAP Analysis - Task 4](Images/PCAP%20Analysis%20-%20Task%204.png)

By default, Apache discloses its name and exact version in this header. For an attacker, this information makes it easy to look for known vulnerabilities affecting that specific version.

**ANSWER:** `Apache`

## Task 5

**What directory was the file uploaded to?**

We saw the directory the file was uploaded to in the same TCP stream. The file was uploaded to the `uploads` directory.

![PCAP Analysis - Task 6](Images/PCAP%20Analysis%20-%20Task%206.png)

Knowing the upload directory matters: if it is reachable from the web and the server executes the files it contains (for example PHP files), an uploaded script could be run simply by requesting its URL.

**ANSWER:** `uploads`

## Task 6

**How long did it take the sender to send the encrypted file?**

We could see the exact time it took the sender to send the encrypted file by going to `Statistics > Conversations` and opening the IPv4 tab. The answer appeared in the `Duration` column.

This window groups all the packets exchanged between each pair of hosts. The `Duration` column gives the time elapsed between the first and the last packet of a conversation, in seconds. The transfer therefore took about 7.3 milliseconds.

![PCAP Analysis - Task 6](Images/PCAP%20Analysis%20-%20Task%206%201.png)

**ANSWER:** `0.0073`

![PCAP Analysis - Solved](Images/PCAP%20Analysis%20-%20Solved.png)
