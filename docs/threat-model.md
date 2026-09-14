# Threat Model

## Objective

The objective of the platform is to identify suspicious activity within simulated security events in real-time.

The initial MVP version focuses on four primary threat scenarios:
1. **Brute-Force Login**
2. **Port Scanning**
3. **Suspicious Login**
4. **HTTP Traffic Anomaly**

---

## 1. Brute-Force Login

### Description
An attacker repeatedly attempts to authenticate against an account or system using automated scripts to guess passwords.

### Attack Pattern Example
```text
[LOGIN] status="FAILED"  username="admin"  source_ip="192.168.1.100"  t=00:01
[LOGIN] status="FAILED"  username="admin"  source_ip="192.168.1.100"  t=00:03
[LOGIN] status="FAILED"  username="admin"  source_ip="192.168.1.100"  t=00:05
... (10+ failures)
```

### Relevant Data Fields
* `event_type`: `LOGIN`
* `source_ip`: Source IP address of the requester
* `username`: Targeted account name
* `status`: `FAILED`
* `timestamp`: Event creation time

### Initial Detection Concept
* **Threshold**: More than 10 failed login attempts (`status = FAILED`) from the same `source_ip` within a **2-minute sliding window**.

### Initial Severity
* **HIGH**

---

## 2. Port Scanning

### Description
An attacker probes multiple destination ports on target systems to discover running network services and open vulnerabilities.

### Attack Pattern Example
```text
[FIREWALL] source_ip="192.168.1.50" dest_ip="10.0.0.5" dest_port=21  status="BLOCK" t=00:01
[FIREWALL] source_ip="192.168.1.50" dest_ip="10.0.0.5" dest_port=22  status="BLOCK" t=00:01
[FIREWALL] source_ip="192.168.1.50" dest_ip="10.0.0.5" dest_port=23  status="BLOCK" t=00:02
[FIREWALL] source_ip="192.168.1.50" dest_ip="10.0.0.5" dest_port=25  status="BLOCK" t=00:02
[FIREWALL] source_ip="192.168.1.50" dest_ip="10.0.0.5" dest_port=80  status="ALLOW" t=00:03
```

### Relevant Data Fields
* `event_type`: `FIREWALL`
* `source_ip`: Originating IP address
* `destination_ip`: Target host IP address
* `destination_port`: Target port number
* `protocol`: Protocol used (TCP/UDP)
* `timestamp`: Event creation time

### Initial Detection Concept
* **Threshold**: A single `source_ip` contacting **> 15 unique destination ports** within a **1-minute sliding window**.

### Initial Severity
* **MEDIUM / HIGH**

---

## 3. Suspicious Login

### Description
An account experiences multiple failed authentication attempts followed by a successful login, indicating potential credential compromise after guessing or brute-force activity.

### Attack Pattern Example
```text
[LOGIN] status="FAILED"  username="jdoe"  source_ip="198.51.100.44" t=01:10
[LOGIN] status="FAILED"  username="jdoe"  source_ip="198.51.100.44" t=01:12
[LOGIN] status="FAILED"  username="jdoe"  source_ip="198.51.100.44" t=01:15
[LOGIN] status="SUCCESS" username="jdoe"  source_ip="198.51.100.44" t=01:18
```

### Relevant Data Fields
* `event_type`: `LOGIN`
* `source_ip`: Source IP address
* `username`: Account name
* `status`: `FAILED` / `SUCCESS`
* `timestamp`: Event creation time

### Initial Detection Concept
* **Threshold**: 3 or more `FAILED` login attempts followed by a `SUCCESS` login from the same `source_ip` (or targeting the same `username`) within a **5-minute window**.

### Initial Severity
* **HIGH**

---

## 4. HTTP Traffic Anomaly

### Description
A source IP generates an abnormally high volume of HTTP requests within a short timeframe, characteristic of web scraping, automated vulnerability scanning, or Denial of Service (DoS) attempts.

### Attack Pattern Example
```text
Normal Baseline : ~10 requests / minute
Anomaly Spike   : > 200 requests / minute from a single source IP
```

### Relevant Data Fields
* `event_type`: `HTTP`
* `source_ip`: Originating IP address
* `destination_ip`: Web server IP address
* `request_path`: URI path requested (e.g., `/api/login`, `/index.html`)
* `http_method`: Request method (`GET`, `POST`)
* `status_code`: HTTP response code (`200`, `404`, `500`)
* `timestamp`: Event creation time

### Initial Detection Concept
* **Threshold**: HTTP request volume from a single `source_ip` exceeding **100 requests within a 1-minute window** (or exceeding 5x the normal baseline).

### Initial Severity
* **MEDIUM**

---

## Severity Model Overview

| Severity Level | Action Required | Examples |
| :--- | :--- | :--- |
| **LOW** | Informational logging, baseline tracking | Isolated single failed login, routine blocked port |
| **MEDIUM** | Requires analyst review or rate limiting | HTTP traffic anomaly, broad port scan |
| **HIGH** | Immediate notification, active threat | Brute-force login, Suspicious login (failed-then-success) |
| **CRITICAL** | Automated mitigation / emergency response | Confirmed multi-stage attack / data exfiltration (Future Scope) |

---

## Out-of-Scope / Future Extensions

The following advanced attack vectors are documented for future iterations:
* Credential stuffing across multiple accounts
* Account takeover & privilege escalation
* DNS tunneling / Data exfiltration over DNS
* Distributed Denial of Service (DDoS) from botnets
