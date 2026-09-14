from datetime import datetime, timezone
import random
import uuid

from schemas.events import EventType, SecurityEvent


class BaseEventGenerator:
    """Base framework for generating security events conforming to the schema."""

    DEFAULT_HOSTNAMES = [
        "workstation-01.corp",
        "workstation-02.corp",
        "web-server-01.prod",
        "db-server-01.prod",
        "fw-gateway-01.edge",
    ]

    DEFAULT_DEVICE_IDS = ["DEV-1001", "DEV-1002", "DEV-1003", "DEV-2001"]
    DEFAULT_AGENT_IDS = ["AGENT-v1.2-A", "AGENT-v1.2-B", "AGENT-v2.0"]

    @staticmethod
    def generate_event_id() -> str:
        """Generate a unique UUIDv4 string."""
        return str(uuid.uuid4())

    @staticmethod
    def generate_timestamp() -> datetime:
        """Generate a UTC timestamp."""
        return datetime.now(timezone.utc)

    @staticmethod
    def generate_random_ip(subnet: str | None = None) -> str:
        """Generate a random IPv4 address within a specified subnet or global pool."""
        if subnet == "internal":
            return f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}"
        elif subnet == "external":
            first_octets = [198, 203, 192, 45, 185]
            return f"{random.choice(first_octets)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 254)}"
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    @classmethod
    def build_envelope(
        self,
        event_type: EventType,
        hostname: str | None = None,
        device_id: str | None = None,
        agent_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> dict:
        """Build the base security event envelope fields."""
        return {
            "event_id": self.generate_event_id(),
            "timestamp": timestamp or self.generate_timestamp(),
            "device_id": device_id or random.choice(self.DEFAULT_DEVICE_IDS),
            "agent_id": agent_id or random.choice(self.DEFAULT_AGENT_IDS),
            "hostname": hostname or random.choice(self.DEFAULT_HOSTNAMES),
            "event_type": event_type,
        }
