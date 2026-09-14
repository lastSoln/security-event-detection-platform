# Security Event Schema

## Purpose

The Security Event Schema defines the common structure used throughout the platform.

The event simulator and data pipeline must follow this schema.

---

## Base Event

```json
{
  "event_id": "evt_001",
  "timestamp": "2026-09-12T12:31:04Z",
  "event_type": "LOGIN",
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "username": "admin",
  "status": "FAILED",
  "metadata": {}
}
Fields
Field	Type	Required	Description
event_id	string	Yes	Unique event identifier
timestamp	ISO-8601 datetime	Yes	Time of event
event_type	string	Yes	Type of security event
source_ip	IP address	No	Originating IP
destination_ip	IP address	No	Destination IP
username	string	No	Associated username
status	string	No	Event status
metadata	object	No	Event-specific information
Event Types
LOGIN

Authentication activity.

Possible statuses:

SUCCESS
FAILED

Example:

{
  "event_id": "evt_001",
  "timestamp": "2026-09-12T12:31:04Z",
  "event_type": "LOGIN",
  "source_ip": "192.168.1.10",
  "username": "admin",
  "status": "FAILED"
}
HTTP

HTTP request activity.

Example:

{
  "event_id": "evt_002",
  "timestamp": "2026-09-12T12:32:04Z",
  "event_type": "HTTP",
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "status": "SUCCESS",
  "metadata": {
    "method": "GET",
    "path": "/login",
    "status_code": 200
  }
}
DNS

DNS query activity.

Example:

{
  "event_id": "evt_003",
  "timestamp": "2026-09-12T12:33:04Z",
  "event_type": "DNS",
  "source_ip": "192.168.1.10",
  "metadata": {
    "domain": "example.com"
  }
}
FIREWALL

Network/firewall activity.

Example:

{
  "event_id": "evt_004",
  "timestamp": "2026-09-12T12:34:04Z",
  "event_type": "FIREWALL",
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "status": "BLOCKED",
  "metadata": {
    "destination_port": 22,
    "protocol": "TCP"
  }
}
Schema Rules

Every event must:

Have a unique event_id
Have a valid timestamp
Have a valid event_type
Follow the documented structure
Be valid JSON
Preserve information required for security detection

The schema may be revised during Milestone #1 after reviewing the threat model.

Any schema change should be discussed by both developers before implementation.



