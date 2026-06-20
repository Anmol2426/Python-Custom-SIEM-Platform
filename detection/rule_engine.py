from detection.rules.base_rule import BaseRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.firewall_abuse import FirewallAbuseRule
from detection.rules.system_anomaly import SystemAnomalyRule


class RuleEngine:
    def __init__(self):
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """
        Register all detection rules here.
        (Later we can make this dynamic)
        """
        self.rules.append(BruteForceRule(threshold=2))
        self.rules.append(FirewallAbuseRule(threshold=2))
        self.rules.append(SystemAnomalyRule())

        pass

    def process_logs(self, logs):
        """
        Process a batch of logs through all rules
        """
        alerts = []

        for log in logs:
            for rule in self.rules:
                try:
                    result = rule.process(log)

                    if result:
                        alerts.append(result)

                except Exception as e:
                    print(f"[ERROR] Rule {rule.name} failed: {e}")

        return alerts