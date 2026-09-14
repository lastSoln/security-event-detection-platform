from datetime import datetime, timezone
import random

from schemas.events import EventStatus, SecurityEvent
from simulator.events import EventFactory
from simulator.generator import BaseEventGenerator


class ScenarioEngine:
    """Engine for generating normal background events and attack scenario bursts."""

    @classmethod
    def generate_random_normal_event(cls) -> SecurityEvent:
        """Generate a random benign background event."""
        choice = random.choice(["LOGIN", "HTTP", "DNS", "FIREWALL"])
        if choice == "LOGIN":
            return EventFactory.create_login_event()
        elif choice == "HTTP":
            return EventFactory.create_http_event()
        elif choice == "DNS":
            return EventFactory.create_dns_event()
        else:
            return EventFactory.create_firewall_event()

    @classmethod
    def generate_bruteforce_scenario(
        cls, attacker_ip: str = "198.51.100.25", target_user: str = "admin", count: int = 15
    ) -> list[SecurityEvent]:
        """Generate a Brute-Force Login attack scenario."""
        events = []
        now = datetime.now(timezone.utc)
        for _ in range(count):
            events.append(
                EventFactory.create_login_event(
                    username=target_user,
                    status=EventStatus.FAILED,
                    source_ip=attacker_ip,
                    timestamp=now,
                )
            )
        return events

    @classmethod
    def generate_portscan_scenario(
        cls, attacker_ip: str = "203.0.113.88", target_ip: str = "10.0.0.15", port_count: int = 20
    ) -> list[SecurityEvent]:
        """Generate a Port Scanning attack scenario."""
        events = []
        now = datetime.now(timezone.utc)
        ports = random.sample(range(20, 1000), port_count)
        for port in ports:
            events.append(
                EventFactory.create_firewall_event(
                    source_ip=attacker_ip,
                    destination_ip=target_ip,
                    destination_port=port,
                    status=EventStatus.BLOCKED,
                    timestamp=now,
                )
            )
        return events

    @classmethod
    def generate_suspicious_login_scenario(
        cls, attacker_ip: str = "198.51.100.99", target_user: str = "jdoe", failed_count: int = 5
    ) -> list[SecurityEvent]:
        """Generate a Suspicious Login (failures followed by success) attack scenario."""
        events = []
        now = datetime.now(timezone.utc)
        for _ in range(failed_count):
            events.append(
                EventFactory.create_login_event(
                    username=target_user,
                    status=EventStatus.FAILED,
                    source_ip=attacker_ip,
                    timestamp=now,
                )
            )
        # Followed by success
        events.append(
            EventFactory.create_login_event(
                username=target_user,
                status=EventStatus.SUCCESS,
                source_ip=attacker_ip,
                timestamp=now,
            )
        )
        return events

    @classmethod
    def generate_http_anomaly_scenario(
        cls, attacker_ip: str = "192.0.2.14", target_path: str = "/api/login", count: int = 150
    ) -> list[SecurityEvent]:
        """Generate an HTTP Traffic Anomaly attack scenario."""
        events = []
        now = datetime.now(timezone.utc)
        for _ in range(count):
            events.append(
                EventFactory.create_http_event(
                    source_ip=attacker_ip,
                    path=target_path,
                    timestamp=now,
                )
            )
        return events
