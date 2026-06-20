from detection.rules.base_rule import BaseRule


class FirewallAbuseRule(BaseRule):
    def __init__(self, threshold=2):
        super().__init__(
            name="Firewall Abuse Detection",
            description="Repeated firewall blocks from same IP",
            severity="Medium"
        )
        self.threshold = threshold
        self.block_counts = {}

    def process(self, log):
        src_ip = log.get("src_ip")
        event_type = log.get("event_type")

        if not src_ip or not event_type:
            return None

        if event_type == "Firewall Block":
            self.block_counts[src_ip] = self.block_counts.get(src_ip, 0) + 1

            if self.block_counts[src_ip] >= self.threshold:
                return self.create_alert(
                    log,
                    f"Repeated firewall blocks from {src_ip} ({self.block_counts[src_ip]} times)"
                )

        return None