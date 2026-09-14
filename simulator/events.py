from datetime import datetime
import random

from schemas.events import EventStatus, EventType, SecurityEvent
from simulator.generator import BaseEventGenerator


class EventFactory:
    """Factory for creating populated SecurityEvent instances with realistic distributions."""

    USERNAMES = ["jdoe", "asmith", "alice", "bob", "sysadmin", "dev_user", "admin"]
    HTTP_PATHS = ["/", "/index.html", "/login", "/dashboard", "/api/v1/status", "/api/v1/users", "/search"]
    DNS_DOMAINS = ["google.com", "github.com", "microsoft.com", "internal.corp", "api.service.io"]
    FIREWALL_PORTS = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 5432]
    PROTOCOLS = ["TCP", "UDP"]

    @classmethod
    def create_login_event(
        cls,
        username: str | None = None,
        status: EventStatus | None = None,
        source_ip: str | None = None,
        timestamp: datetime | None = None,
    ) -> SecurityEvent:
        """Create a LOGIN security event (Issue #8)."""
        data = BaseEventGenerator.build_envelope(EventType.LOGIN, timestamp=timestamp)
        data.update({
            "source_ip": source_ip or BaseEventGenerator.generate_random_ip("external"),
            "username": username or random.choice(cls.USERNAMES),
            "status": status or (EventStatus.SUCCESS if random.random() < 0.95 else EventStatus.FAILED),
        })
        return SecurityEvent(**data)

    @classmethod
    def create_http_event(
        cls,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        path: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        timestamp: datetime | None = None,
    ) -> SecurityEvent:
        """Create an HTTP security event (Issue #9)."""
        data = BaseEventGenerator.build_envelope(EventType.HTTP, timestamp=timestamp)
        
        # Weighted HTTP methods
        default_method = random.choices(["GET", "POST", "PUT", "DELETE"], weights=[80, 15, 3, 2])[0]
        # Weighted HTTP status codes
        default_status_code = random.choices([200, 304, 404, 500], weights=[90, 5, 4, 1])[0]

        data.update({
            "source_ip": source_ip or BaseEventGenerator.generate_random_ip("external"),
            "destination_ip": destination_ip or BaseEventGenerator.generate_random_ip("internal"),
            "path": path or random.choice(cls.HTTP_PATHS),
            "method": method or default_method,
            "status_code": status_code or default_status_code,
        })
        return SecurityEvent(**data)

    @classmethod
    def create_dns_event(
        cls,
        source_ip: str | None = None,
        domain: str | None = None,
        timestamp: datetime | None = None,
    ) -> SecurityEvent:
        """Create a DNS security event (Issue #10)."""
        data = BaseEventGenerator.build_envelope(EventType.DNS, timestamp=timestamp)
        data.update({
            "source_ip": source_ip or BaseEventGenerator.generate_random_ip("internal"),
            "domain": domain or random.choice(cls.DNS_DOMAINS),
        })
        return SecurityEvent(**data)

    @classmethod
    def create_firewall_event(
        cls,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        status: EventStatus | None = None,
        timestamp: datetime | None = None,
    ) -> SecurityEvent:
        """Create a FIREWALL security event (Issue #11)."""
        data = BaseEventGenerator.build_envelope(EventType.FIREWALL, timestamp=timestamp)
        data.update({
            "source_ip": source_ip or BaseEventGenerator.generate_random_ip("external"),
            "destination_ip": destination_ip or BaseEventGenerator.generate_random_ip("internal"),
            "destination_port": destination_port or random.choice(cls.FIREWALL_PORTS),
            "protocol": protocol or random.choice(cls.PROTOCOLS),
            "status": status or (EventStatus.ALLOWED if random.random() < 0.9 else EventStatus.BLOCKED),
        })
        return SecurityEvent(**data)
