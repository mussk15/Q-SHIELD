from qshield.monitor.rules import RuleEngine, load_config
from qshield.monitor.alerts import AlertManager

alert_manager = AlertManager(
    output_path="data/alerts.jsonl",
    cooldown_seconds=30,
)

rule_engine = RuleEngine(
    config=load_config(),
    alert_manager=alert_manager,
)


def process_event(event):
    """Send one application event to Member 3's IDS rules."""
    return rule_engine.evaluate_application_event(event)
