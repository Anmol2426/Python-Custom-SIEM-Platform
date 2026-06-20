from datetime import datetime
class BaseRule:
    def __init__(self, name, description, severity):
        self.name = name
        self.description = description
        self.severity = severity

    def process(self, log):
        """
        Process a single log entry.
        Should return an alert dict if rule is triggered, else None.
        """
        raise NotImplementedError("Each rule must implement the process method")

    def create_alert(self, log, message):
        """
        Standard alert format
        """
        return {
            "log_id": log.get("id"),  # 🔥 THIS FIXES EVERYTHING
            "incident_id": None,
            "alert_type": self.name,
            "severity": self.severity,
            "src_ip": log.get("src_ip"),
            "description": message,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }