import pytest
from pydantic import ValidationError

from schemas.events import EventStatus, EventType, SecurityEvent


def test_valid_login_event():
    event = SecurityEvent(
        event_id="evt_001",
        timestamp="2026-09-14T12:30:15Z",
        device_id="device_001",
        agent_id="agent_001",
        hostname="laptop-01",
        event_type=EventType.LOGIN,
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        username="admin",
        status=EventStatus.FAILED,
    )

    assert event.event_id == "evt_001"
    assert event.device_id == "device_001"
    assert event.event_type == EventType.LOGIN
    assert event.status == EventStatus.FAILED


def test_valid_firewall_event():
    event = SecurityEvent(
        event_id="evt_002",
        timestamp="2026-09-14T12:31:15Z",
        device_id="device_002",
        agent_id="agent_002",
        hostname="desktop-01",
        event_type=EventType.FIREWALL,
        source_ip="192.168.1.30",
        destination_ip="192.168.1.10",
        status=EventStatus.BLOCKED,
        destination_port=22,
        protocol="TCP",
    )

    assert event.destination_port == 22
    assert event.protocol == "TCP"


def test_invalid_event_type():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="evt_003",
            timestamp="2026-09-14T12:30:15Z",
            device_id="device_001",
            agent_id="agent_001",
            hostname="laptop-01",
            event_type="INVALID",
        )


def test_invalid_ip_address():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="evt_004",
            timestamp="2026-09-14T12:30:15Z",
            device_id="device_001",
            agent_id="agent_001",
            hostname="laptop-01",
            event_type=EventType.LOGIN,
            source_ip="not-an-ip",
        )


def test_invalid_port():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="evt_005",
            timestamp="2026-09-14T12:30:15Z",
            device_id="device_001",
            agent_id="agent_001",
            hostname="laptop-01",
            event_type=EventType.FIREWALL,
            destination_port=70000,
        )


def test_missing_device_information():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="evt_006",
            timestamp="2026-09-14T12:30:15Z",
            event_type=EventType.LOGIN,
        )