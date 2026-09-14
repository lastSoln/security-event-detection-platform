# Attack Simulation Requirements

## Overview & Purpose

The **Security Event Simulator** is a Python-based component responsible for generating realistic stream of security events for testing and validating the end-to-end detection platform.

To adequately test the platform's detection rules and Spark Structured Streaming pipeline, the simulator must generate two distinct categories of events:
1. **Normal Baseline Activity**: Regular operational traffic mimicking everyday network, web, DNS, and authentication events.
2. **Malicious Attack Activity**: Targeted attack patterns designed to trigger security alerts.

---

## 1. Supported Event Types & Schema Adherence

All generated events **must** strictly conform to the platform event schema documented in [`docs/event-schema.md`](file:///c:/Users/ANIKET%20SAROJ/Desktop/security-event-detection-platform/docs/event-schema.md).

Every event must contain the following core envelope fields:
* `event_id` (UUIDv4 format string)
* `timestamp` (ISO 8601 UTC timestamp format)
* `event_type` (`LOGIN`, `HTTP`, `DNS`, `FIREWALL`)
* `device_id` (Identifier of originating generator/sensor)
* `agent_id` (Identifier of collector agent)
* `hostname` (Source host name)

---

## 2. Normal Baseline Activity Requirements

The simulator should continuously produce background noise representing benign traffic.

### A. Normal Authentication (`LOGIN`)
* **Status Distribution**: ~95% `SUCCESS`, ~5% `FAILED` (representing occasional typos).
* **Target Usernames**: Random selection from a realistic pool (`jdoe`, `asmith`, `alice`, `bob`, `sysadmin`).
* **Source IPs**: Selected from legitimate internal CIDRs (e.g., `10.0.1.0/24`, `192.168.1.0/24`) or known user IPs.
* **Frequency**: Random inter-arrival delay (1–10 seconds between events).

### B. Normal Web Traffic (`HTTP`)
* **Request Paths**: Common paths (`/`, `/index.html`, `/login`, `/dashboard`, `/api/v1/status`).
* **HTTP Methods**: 80% `GET`, 15% `POST`, 5% `PUT`/`DELETE`.
* **Status Codes**: 90% `200 OK`, 5% `304 Not Modified`, 4% `404 Not Found`, 1% `500 Internal Error`.
* **Frequency**: 5–15 requests/minute per active user IP.

### C. Normal Domain Resolution (`DNS`)
* **Queried Domains**: Popular domains (`google.com`, `github.com`, `microsoft.com`, `internal.corp`).
* **Query Types**: 85% `A`, 10% `AAAA`, 5% `CNAME`.
* **Response Codes**: 98% `NOERROR`, 2% `NXDOMAIN`.

### D. Normal Network Traffic (`FIREWALL`)
* **Status Distribution**: 90% `ALLOW`, 10% `BLOCK` (routine edge drop).
* **Common Ports**: `80` (HTTP), `443` (HTTPS), `53` (DNS), `22` (SSH).
* **Protocols**: `TCP`, `UDP`.

---

## 3. Attack Simulation Scenarios & Specifications

### Scenario 1: Brute-Force Login Attack
* **Objective**: Trigger Brute-Force Login Detection Rule (`#27`).
* **Pattern**: High-frequency authentication failures targeting a single username or from a single IP.
* **Simulator Specifications**:
  * **Event Type**: `LOGIN`
  * **Source IP**: Fixed attacker IP (e.g., `198.51.100.25`)
  * **Username**: `admin` or target user
  * **Status**: `FAILED`
  * **Rate / Volume**: **15 to 20 failed login events** generated within **30 to 60 seconds**.

### Scenario 2: Port Scanning Attack
* **Objective**: Trigger Port-Scan Detection Rule (`#28`).
* **Pattern**: Rapid connections to multiple distinct destination ports on a target host.
* **Simulator Specifications**:
  * **Event Type**: `FIREWALL`
  * **Source IP**: Fixed attacker IP (e.g., `203.0.113.88`)
  * **Destination IP**: Target server IP (e.g., `10.0.0.15`)
  * **Destination Ports**: Sequential or randomized sweep across **> 20 distinct ports** (e.g., `21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080`).
  * **Status**: Majority `BLOCK`
  * **Time Window**: All probes generated within **30 seconds**.

### Scenario 3: Suspicious Login (Failed-then-Success)
* **Objective**: Trigger Suspicious Login Detection Rule (`#29`).
* **Pattern**: Password guessing attempts followed immediately by a successful authentication.
* **Simulator Specifications**:
  * **Event Type**: `LOGIN`
  * **Source IP**: Fixed attacker IP (e.g., `198.51.100.99`)
  * **Username**: `jdoe`
  * **Sequence**:
    1. Generate **4 to 6 `FAILED` login events** spaced 2–5 seconds apart.
    2. Generate **1 `SUCCESS` login event** within 60 seconds of the last failure.
  * **Time Window**: Complete sequence occurs within **2 minutes**.

### Scenario 4: HTTP Traffic Anomaly
* **Objective**: Trigger HTTP Anomaly Detection Rule (`#30`).
* **Pattern**: Sudden burst of HTTP requests exceeding baseline thresholds.
* **Simulator Specifications**:
  * **Event Type**: `HTTP`
  * **Source IP**: Fixed attacker IP (e.g., `192.0.2.14`)
  * **Target Path**: Sensitive URI or endpoint (e.g., `/api/login` or `/search`)
  * **Rate / Volume**: **> 200 HTTP requests** generated within **60 seconds** (approx. 3–5 requests/second).

---

## 4. Simulator Configuration & Controls

The Python simulator command-line interface (CLI) should support configurable execution modes:

```bash
# Example simulator CLI usage
python -m simulator.main --rate 10 --duration 300 --scenario bruteforce
```

### Required Configuration Flags:
* `--rate`: Baseline events per second (default: `5`).
* `--duration`: Run duration in seconds (default: infinite/continuous).
* `--scenario`: Specific attack scenario to inject (`bruteforce`, `portscan`, `suspicious_login`, `http_anomaly`, `all`).
* `--output`: Output sink destination (`console`, `file`, `kafka`).

---

## 5. Acceptance Criteria

1. Generated JSON events pass schema validation against [`schemas/events.py`](file:///c:/Users/ANIKET%20SAROJ/Desktop/security-event-detection-platform/schemas/events.py).
2. Simulator can run in continuous baseline mode without errors.
3. Each attack scenario reliably reproduces the exact event sequences and time windows specified in this document.
