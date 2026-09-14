from datetime import datetime, timezone
import json
from unittest.mock import patch

import pytest
from schemas.events import EventStatus, EventType, SecurityEvent
from simulator.events import EventFactory
from simulator.generator import BaseEventGenerator
from simulator.main import main as cli_main
from simulator.scenarios import ScenarioEngine


def test_base_event_generator_envelope():
    envelope = BaseEventGenerator.build_envelope(EventType.LOGIN)
    assert "event_id" in envelope
    assert "timestamp" in envelope
    assert "device_id" in envelope
    assert "agent_id" in envelope
    assert "hostname" in envelope
    assert envelope["event_type"] == EventType.LOGIN


def test_random_ip_subnets():
    internal_ip = BaseEventGenerator.generate_random_ip("internal")
    assert internal_ip.startswith("10.0.")

    external_ip = BaseEventGenerator.generate_random_ip("external")
    assert any(external_ip.startswith(prefix) for prefix in ["198.", "203.", "192.", "45.", "185."])

    default_ip = BaseEventGenerator.generate_random_ip()
    assert len(default_ip.split(".")) == 4


def test_issue_8_login_event_simulation():
    """Test Issue #8: Implement Login Event Simulation."""
    event = EventFactory.create_login_event(username="admin")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.LOGIN
    assert event.username == "admin"
    assert event.status in ["SUCCESS", "FAILED"]
    assert event.source_ip is not None


def test_issue_9_http_event_simulation():
    """Test Issue #9: Implement HTTP Event Simulation."""
    event = EventFactory.create_http_event(path="/login", method="POST")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.HTTP
    assert event.path == "/login"
    assert event.method == "POST"
    assert event.status_code in [200, 304, 404, 500]


def test_issue_10_dns_event_simulation():
    """Test Issue #10: Implement DNS Event Simulation."""
    event = EventFactory.create_dns_event(domain="google.com")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.DNS
    assert event.domain == "google.com"
    assert event.source_ip is not None


def test_issue_11_firewall_event_simulation():
    """Test Issue #11: Implement Firewall Event Simulation."""
    event = EventFactory.create_firewall_event(destination_port=80, protocol="TCP")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.FIREWALL
    assert event.destination_port == 80
    assert event.protocol == "TCP"
    assert event.status in ["ALLOWED", "BLOCKED"]


def test_event_custom_parameters():
    now = datetime.now(timezone.utc)
    event = EventFactory.create_login_event(
        username="custom_user",
        status=EventStatus.SUCCESS,
        source_ip="1.2.3.4",
        timestamp=now,
    )
    assert event.username == "custom_user"
    assert event.status == EventStatus.SUCCESS
    assert str(event.source_ip) == "1.2.3.4"
    assert event.timestamp == now


def test_issue_12_bruteforce_scenario():
    """Test Issue #12: Implement Brute-Force Scenario."""
    events = ScenarioEngine.generate_bruteforce_scenario(attacker_ip="198.51.100.25", count=15)
    assert len(events) == 15
    for e in events:
        assert isinstance(e, SecurityEvent)
        assert e.event_type == EventType.LOGIN
        assert e.status.value == "FAILED"
        assert str(e.source_ip) == "198.51.100.25"


def test_issue_13_portscan_scenario():
    """Test Issue #13: Implement Port-Scan Scenario."""
    events = ScenarioEngine.generate_portscan_scenario(attacker_ip="203.0.113.88", port_count=20)
    assert len(events) == 20
    distinct_ports = {e.destination_port for e in events}
    assert len(distinct_ports) == 20
    for e in events:
        assert e.event_type == EventType.FIREWALL
        assert e.status.value == "BLOCKED"


def test_issue_14_http_anomaly_scenario():
    """Test Issue #14: Implement HTTP Anomaly Scenario."""
    events = ScenarioEngine.generate_http_anomaly_scenario(attacker_ip="192.0.2.14", count=100)
    assert len(events) == 100
    for e in events:
        assert e.event_type == EventType.HTTP
        assert str(e.source_ip) == "192.0.2.14"


def test_scenario_suspicious_login():
    events = ScenarioEngine.generate_suspicious_login_scenario(failed_count=4)
    assert len(events) == 5
    assert events[-1].status.value == "SUCCESS"


def test_scenario_engine_random_normal_events():
    for _ in range(50):
        event = ScenarioEngine.generate_random_normal_event()
        assert isinstance(event, SecurityEvent)
        # Validate JSON serialization & deserialization
        dumped_json = event.model_dump_json()
        deserialized = json.loads(dumped_json)
        assert "event_id" in deserialized
        assert "event_type" in deserialized


def test_cli_file_output_sink(tmp_path):
    output_file = tmp_path / "events.json"
    test_args = [
        "simulator.main",
        "--duration",
        "1",
        "--rate",
        "10",
        "--scenario",
        "bruteforce",
        "--output",
        "file",
        "--out-file",
        str(output_file),
    ]
    with patch("sys.argv", test_args):
        cli_main()

    assert output_file.exists()
    lines = output_file.read_text().strip().split("\n")
    assert len(lines) >= 15  # 15 scenario events + baseline events
    for line in lines:
        raw_event = json.loads(line)
        event = SecurityEvent(**raw_event)
        assert event.event_id is not None
