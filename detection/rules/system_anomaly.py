from detection.rules.base_rule import BaseRule


class SystemAnomalyRule(BaseRule):
    def __init__(self):
        super().__init__(
            name="System Anomaly Detection",
            description="System errors detected",
            severity="High"
        )

    def process(self, log):
        event_type = log.get("event_type")

        if not event_type:
            return None

        # Only detect actual system errors
        if event_type == "System Error":
            return self.create_alert(
                log,
                "System error detected"
            )

        return None