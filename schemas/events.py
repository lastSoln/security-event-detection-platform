from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, IPvAnyAddress


class EventType(str, Enum):
    LOGIN = "LOGIN"
    HTTP = "HTTP"
    DNS = "DNS"
    FIREWALL = "FIREWALL"


class EventStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class SecurityEvent(BaseModel):
    # Event identity
    event_id: str = Field(min_length=1)
    timestamp: datetime

    # Device identity
    device_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    hostname: str = Field(min_length=1)

    # Event classification
    event_type: EventType

    # Network information
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None

    # Authentication information
    username: str | None = None
    status: EventStatus | None = None

    # HTTP information
    method: str | None = None
    path: str | None = None
    status_code: int | None = None

    # DNS information
    domain: str | None = None

    # Network/firewall information
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None