from qshield.monitor.alerts import AlertManager
from qshield.monitor.features import FeatureWindow
from qshield.monitor.rules import RuleEngine


def manager(tmp_path):
    return AlertManager(str(tmp_path / "alerts.jsonl"), cooldown_seconds=0)


def make_window(**overrides):
    values = dict(
        timestamp="2026-11-09T10:00:00+00:00", src_ip="127.0.0.1",
        window_seconds=10, packet_count=30, connection_attempts=20,
        syn_count=35, syn_ack_count=2, rst_count=0, half_open_syns=33,
        failed_handshakes=0, distinct_dst_ports=15, distinct_dst_ips=1,
        bytes_total=1800, message_rate=3.0
    )
    values.update(overrides)
    return FeatureWindow(**values)


def test_port_scan_rule(tmp_path):
    config = {"rules": {"port_scan": {"enabled": True, "min_distinct_ports": 10,
              "min_connection_attempts": 10, "severity": "HIGH", "score": 80}}}
    engine = RuleEngine(config, manager(tmp_path))
    alerts = engine.evaluate_window(make_window())
    assert any(a.rule_id == "PORT_SCAN" for a in alerts)


def test_syn_flood_rule(tmp_path):
    config = {"rules": {"syn_flood": {"enabled": True, "min_syn_count": 30,
              "min_half_open_syns": 20, "severity": "CRITICAL", "score": 95}}}
    engine = RuleEngine(config, manager(tmp_path))
    alerts = engine.evaluate_window(make_window())
    assert any(a.rule_id == "SYN_FLOOD" for a in alerts)


def test_normal_window_does_not_alert(tmp_path):
    config = {
        "rules": {
            "port_scan": {"enabled": True, "min_distinct_ports": 12,
                          "min_connection_attempts": 15, "severity": "HIGH", "score": 80},
            "syn_flood": {"enabled": True, "min_syn_count": 30,
                          "min_half_open_syns": 20, "severity": "CRITICAL", "score": 95},
        }
    }
    normal = make_window(packet_count=8, connection_attempts=2, syn_count=2,
                         half_open_syns=1, distinct_dst_ports=2)
    assert RuleEngine(config, manager(tmp_path)).evaluate_window(normal) == []


def test_replay_event_maps_to_high_priority_alert(tmp_path):
    config = {"rules": {"replay_or_tamper": {"enabled": True, "min_events": 1,
              "severity": "CRITICAL", "score": 100}}}
    engine = RuleEngine(config, manager(tmp_path))
    alerts = engine.evaluate_application_event({
        "event_type": "REPLAY", "source_ip": "127.0.0.1", "session_id": "s1"
    })
    assert alerts[0].rule_id == "REPLAY_OR_TAMPER"
    assert alerts[0].severity == "CRITICAL"


def test_auth_failure_requires_threshold(tmp_path):
    config = {"rules": {"failed_login": {"enabled": True, "min_failures": 3,
              "severity": "HIGH", "score": 85}}}
    engine = RuleEngine(config, manager(tmp_path))
    event = {"event_type": "HANDSHAKE_FAIL", "source_ip": "127.0.0.1"}
    assert engine.evaluate_application_event(event) == []
    assert engine.evaluate_application_event(event) == []
    assert any(a.rule_id == "AUTH_FAILURE"
               for a in engine.evaluate_application_event(event))


def test_member2_invalid_message_maps_to_malformed_alert(tmp_path):
    config = {
        "rules": {
            "malformed_input": {
                "enabled": True,
                "min_events": 1,
                "severity": "HIGH",
                "score": 85,
            }
        }
    }

    engine = RuleEngine(config, manager(tmp_path))

    event = {
        "event_type": "invalid_client_message",
        "source_ip": "127.0.0.1",
        "session_id": "test-session",
        "details": {"error": "Invalid message type"},
    }

    alerts = engine.evaluate_application_event(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "MALFORMED_INPUT"
    assert alerts[0].severity == "HIGH"
