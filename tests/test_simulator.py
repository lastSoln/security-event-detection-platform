from schemas.events import EventType, SecurityEvent
from simulator.events import EventFactory
from simulator.generator import BaseEventGenerator
from simulator.scenarios import ScenarioEngine


def test_base_event_generator_envelope():
    envelope = BaseEventGenerator.build_envelope(EventType.LOGIN)
    assert "event_id" in envelope
    assert "timestamp" in envelope
    assert "device_id" in envelope
    assert "agent_id" in envelope
    assert "hostname" in envelope
    assert envelope["event_type"] == EventType.LOGIN


def test_create_login_event():
    event = EventFactory.create_login_event(username="admin")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.LOGIN
    assert event.username == "admin"
    assert event.status is not None


def test_create_http_event():
    event = EventFactory.create_http_event(path="/login", method="POST")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.HTTP
    assert event.path == "/login"
    assert event.method == "POST"


def test_create_dns_event():
    event = EventFactory.create_dns_event(domain="google.com")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.DNS
    assert event.domain == "google.com"


def test_create_firewall_event():
    event = EventFactory.create_firewall_event(destination_port=80, protocol="TCP")
    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.FIREWALL
    assert event.destination_port == 80
    assert event.protocol == "TCP"


def test_scenario_bruteforce():
    events = ScenarioEngine.generate_bruteforce_scenario(count=10)
    assert len(events) == 10
    for e in events:
        assert isinstance(e, SecurityEvent)
        assert e.event_type == EventType.LOGIN
        assert e.status.value == "FAILED"


def test_scenario_portscan():
    events = ScenarioEngine.generate_portscan_scenario(port_count=15)
    assert len(events) == 15
    distinct_ports = {e.destination_port for e in events}
    assert len(distinct_ports) == 15


def test_scenario_suspicious_login():
    events = ScenarioEngine.generate_suspicious_login_scenario(failed_count=4)
    assert len(events) == 5
    assert events[-1].status.value == "SUCCESS"


def test_scenario_http_anomaly():
    events = ScenarioEngine.generate_http_anomaly_scenario(count=20)
    assert len(events) == 20
    for e in events:
        assert e.event_type == EventType.HTTP
