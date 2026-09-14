
# Detection Rules

## Purpose

This document defines how processed security events will be evaluated for suspicious behavior.

The initial detection engine will use rule-based detection.

Machine learning is not part of the initial MVP.

---

# Rule 1 — Brute-Force Login

## Logic

Trigger an alert when:

```text
More than 10 failed login attempts
FROM the same source IP
WITHIN 2 minutes
Alert
Type: BRUTE_FORCE
Severity: HIGH
Required Data
source_ip
username
status
timestamp
Rule 2 — Port Scanning
Logic

Trigger an alert when:

One source IP
contacts many destination ports
within a short time window

The exact threshold will be determined during implementation and testing.

Alert
Type: PORT_SCAN
Severity: MEDIUM / HIGH
Required Data
source_ip
destination_ip
destination_port
protocol
timestamp
Rule 3 — Suspicious Login
Logic

Trigger an alert when:

Multiple failed login attempts
        +
Successful login
        +
Same source IP
        +
Short time window
Alert
Type: SUSPICIOUS_LOGIN
Severity: HIGH
Required Data
source_ip
username
status
timestamp
Rule 4 — HTTP Traffic Anomaly
Logic

Trigger an alert when:

HTTP request volume
significantly exceeds
the expected baseline

The exact threshold will be determined after establishing normal traffic behavior.

Alert
Type: HTTP_ANOMALY
Severity: MEDIUM
Required Data
source_ip
destination_ip
request path
HTTP method
timestamp
request frequency
Alert Structure

Generated alerts should eventually contain:

alert_id
timestamp
alert_type
severity
source_ip
event_count
detection_rule
description

The final alert schema will be agreed upon before implementing the detection engine.

Detection Principles

Detection rules should:

Be deterministic
Be explainable
Have documented thresholds
Produce reproducible results
Minimize false positives
Preserve the evidence used to generate an alert

**That's all for `detection-rules.md`.**

---
