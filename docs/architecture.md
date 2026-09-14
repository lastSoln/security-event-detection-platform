# System Architecture

## High-Level Architecture

```text
                +----------------------+
                | Security Event       |
                | Simulator            |
                +----------+-----------+
                           |
                           v
                +----------------------+
                |        Kafka         |
                |   security-events    |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Spark Structured     |
                | Streaming            |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Processed Security   |
                | Events               |
                +----------+-----------+
                           |
                 +---------+---------+
                 |                   |
                 v                   v
          +-------------+    +----------------+
          |   Storage   |    | Detection      |
          | PostgreSQL  |    | Engine         |
          +-------------+    +-------+--------+
                                     |
                                     v
                              +-------------+
                              |   Alerts    |
                              +------+------+
                                     |
                                     v
                              +-------------+
                              |  Dashboard  |
                              +-------------+
Components
1. Security Event Simulator

Generates realistic security events.

It will generate:

LOGIN
HTTP
DNS
FIREWALL

Both normal and malicious activity will be simulated.

2. Kafka

Kafka provides the real-time streaming layer.

Initial topic:

security-events
3. Spark Structured Streaming

Spark processes events coming from Kafka.

Responsibilities:

Validate events
Clean events
Transform events
Aggregate events
Prepare data for detection
4. Storage

PostgreSQL will initially be used for storing processed security data and alerts.

5. Detection Engine

The detection engine analyzes processed events and identifies suspicious behavior.

Initial detections:

Brute-force login
Port scanning
Suspicious login
HTTP anomaly
6. Dashboard

The dashboard will eventually display:

Security events
Security alerts
Attack types
Severity levels
Suspicious IPs
Event trends
Design Principle

The detection engine should not depend directly on Kafka or Spark.

The Data Engineering and Cybersecurity components should communicate through well-defined data interfaces.

This allows both components to be developed independently.


