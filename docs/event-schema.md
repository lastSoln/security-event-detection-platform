# Security Event Schema

## Purpose

The Security Event Schema defines the common structure used by all security events in the platform.

The Security Event Simulator, ingestion API, Kafka pipeline, Spark processing layer, and detection engine will use this schema as the common data contract.

The schema is designed to support multiple monitored devices.

---

# Event Structure

Every event contains:

1. Event identity
2. Device identity
3. Event classification
4. Network information
5. Event-specific information

Example:

```json
{
  "event_id": "evt_001",
  "timestamp": "2026-09-14T12:30:15Z",

  "device_id": "device_001",
  "agent_id": "agent_001",
  "hostname": "laptop-01",

  "event_type": "LOGIN",

  "source_ip": "192.168.1.20",
  "destination_ip": "192.168.1.10",

  "username": "admin",
  "status": "FAILED",

  "method": null,
  "path": null,
  "status_code": null,

  "domain": null,

  "destination_port": null,
  "protocol": null
}
Fields
Field	Type	Required	Description
event_id	string	Yes	Unique identifier for the event
timestamp	ISO-8601 datetime	Yes	Time when the event occurred
device_id	string	Yes	Unique identifier of the monitored device
agent_id	string	Yes	Identifier of the security agent that generated the event
hostname	string	Yes	Hostname of the monitored device
event_type	enum	Yes	Type of security event
source_ip	IP address	No	Source IP address
destination_ip	IP address	No	Destination IP address
username	string	No	Username involved in the event
status	enum	No	Result/status of the event
method	string	No	HTTP method
path	string	No	HTTP request path
status_code	integer	No	HTTP response status code
domain	string	No	DNS domain queried
destination_port	integer	No	Destination network port
protocol	string	No	Network protocol
Event Types
LOGIN

Represents authentication activity.

Possible statuses:

SUCCESS
FAILED

Example:

{
  "event_id": "evt_login_001",
  "timestamp": "2026-09-14T12:30:15Z",
  "device_id": "device_001",
  "agent_id": "agent_001",
  "hostname": "laptop-01",
  "event_type": "LOGIN",
  "source_ip": "192.168.1.20",
  "destination_ip": "192.168.1.10",
  "username": "admin",
  "status": "FAILED"
}

Relevant detection information:

source_ip
username
status
timestamp
device_id
HTTP

Represents HTTP request activity.

Example:

{
  "event_id": "evt_http_001",
  "timestamp": "2026-09-14T12:31:15Z",
  "device_id": "device_001",
  "agent_id": "agent_001",
  "hostname": "laptop-01",
  "event_type": "HTTP",
  "source_ip": "192.168.1.20",
  "destination_ip": "192.168.1.10",
  "method": "GET",
  "path": "/login",
  "status_code": 200
}

Relevant detection information:

source_ip
destination_ip
method
path
status_code
timestamp
device_id
DNS

Represents DNS query activity.

Example:

{
  "event_id": "evt_dns_001",
  "timestamp": "2026-09-14T12:32:15Z",
  "device_id": "device_001",
  "agent_id": "agent_001",
  "hostname": "laptop-01",
  "event_type": "DNS",
  "source_ip": "192.168.1.20",
  "domain": "example.com"
}

Relevant detection information:

source_ip
domain
timestamp
device_id
FIREWALL

Represents firewall or network connection activity.

Example:

{
  "event_id": "evt_firewall_001",
  "timestamp": "2026-09-14T12:33:15Z",
  "device_id": "device_001",
  "agent_id": "agent_001",
  "hostname": "laptop-01",
  "event_type": "FIREWALL",
  "source_ip": "192.168.1.20",
  "destination_ip": "192.168.1.10",
  "status": "BLOCKED",
  "destination_port": 22,
  "protocol": "TCP"
}

Relevant detection information:

source_ip
destination_ip
destination_port
protocol
status
timestamp
device_id
Multi-Device Support

Multiple monitored devices can send events to the same central platform.

Example:

Device 001 ─┐
Device 002 ─┤
Device 003 ─┼──→ Central Ingestion Pipeline
Device 004 ─┘

Each event contains device_id, agent_id, and hostname so that events can be associated with their originating device.

Validation Rules

Every event must:

Have a unique event_id
Have a valid timestamp
Have a valid event_type
Have a device_id
Have an agent_id
Have a hostname
Use valid IP addresses when IP fields are provided
Use a valid destination port between 1 and 65535 when provided
Follow the documented field types

Event-specific fields should be populated according to the event type.

For example:

LOGIN events should provide authentication information.
HTTP events should provide HTTP information.
DNS events should provide DNS information.
FIREWALL events should provide network information.