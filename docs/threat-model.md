# Threat Model

## Objective

The objective of the platform is to identify suspicious activity within simulated security events.

The first version focuses on four attack scenarios.

---

# 1. Brute-Force Login

## Description

An attacker repeatedly attempts to authenticate against an account or system.

## Example

```text
FAILED
FAILED
FAILED
FAILED
FAILED
...
FAILED
SUCCESS
Relevant Data
Source IP
Username
Login status
Timestamp
Initial Detection Concept

More than 10 failed login attempts from the same source IP within 2 minutes.

Initial Severity

HIGH

2. Port Scanning
Description

An attacker attempts to discover available network services by contacting multiple destination ports.

Example
192.168.1.50 → port 21
192.168.1.50 → port 22
192.168.1.50 → port 23
192.168.1.50 → port 25
192.168.1.50 → port 80
Relevant Data
Source IP
Destination IP
Destination port
Protocol
Timestamp
Initial Detection Concept

One source IP contacting many destination ports within a short time window.

Initial Severity

MEDIUM / HIGH

3. Suspicious Login
Description

An account experiences repeated authentication failures followed by a successful login.

Example
FAILED
FAILED
FAILED
SUCCESS
Relevant Data
Source IP
Username
Login status
Timestamp
Initial Detection Concept

Multiple failed login attempts followed by a successful authentication from the same source.

Initial Severity

HIGH

4. HTTP Traffic Anomaly
Description

A source generates an unusually high volume of HTTP requests within a short period.

Example
Normal:
10 requests/minute

Anomaly:
500 requests/minute
Relevant Data
Source IP
Destination IP
Request path
HTTP method
Timestamp
Request frequency
Initial Detection Concept

HTTP request volume significantly exceeds the defined normal baseline.

Initial Severity

MEDIUM

Future Threat Scenarios

Possible future extensions:

Credential stuffing
Account takeover
DNS tunneling
Suspicious outbound connections
Data exfiltration
Distributed attacks

These are outside the initial MVP.


**That's all for `threat-model.md`.**

---
