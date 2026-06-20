from datetime import datetime
from detection.rules.base_rule import BaseRule
from state.state_manager import StateManager


class BruteForceRule(BaseRule):
    def __init__(self, threshold=2, window_seconds=120, cooldown_seconds=300):
        super().__init__(
            name="Brute Force Detection",
            description="Multiple failed login attempts from same IP",
            severity="High"
        )

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        self.state_manager = StateManager()

        # Load persistent state
        saved_state = self.state_manager.get_rule_state("brute_force")

        self.failed_attempts = saved_state.get("failed_attempts", {})
        self.alerted_ips = saved_state.get("alerted_ips", {})

    def process(self, log):
        src_ip = log.get("src_ip")
        event_type = log.get("event_type")
        timestamp = log.get("timestamp")
        # ✅ NEW
        username = log.get("username")
        if not src_ip or not event_type or not timestamp:
            return None

        # Convert timestamp → epoch
        try:
            dt = datetime.strptime(timestamp, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now().year)  # ✅ FIX
            current_time = int(dt.timestamp())
        except Exception as e:
            print("TIMESTAMP ERROR:", timestamp, e)
            return None

        # Initialize if not present
        if src_ip not in self.failed_attempts:
            self.failed_attempts[src_ip] = []

        if event_type and "Failed" in event_type:

            # Add current timestamp
            self.failed_attempts[src_ip].append(current_time)

            # Remove timestamps outside window
            window_start = current_time - self.window_seconds
            self.failed_attempts[src_ip] = [
                t for t in self.failed_attempts[src_ip] if t >= window_start
            ]

            # Check threshold
            if len(self.failed_attempts[src_ip]) >= self.threshold:

                last_alert_time = self.alerted_ips.get(src_ip, 0)

                # Cooldown check
                if current_time - last_alert_time < self.cooldown_seconds:
                    return None

                # Update alert time
                self.alerted_ips[src_ip] = current_time

                user_part = f" on user {username}" if username else ""
                return self.create_alert(
                    log,
                    f"Brute force suspected{user_part} from {src_ip} "
                    f"({len(self.failed_attempts[src_ip])} failed attempts in {self.window_seconds}s)"
                )

        elif event_type == "Authentication Success":
            if src_ip in self.failed_attempts:
                # Only reset if below threshold
                if len(self.failed_attempts[src_ip]) < self.threshold:
                    self.failed_attempts[src_ip] = []

        return None

    def save_state(self):
        self.state_manager.set_rule_state(
            "brute_force",
            {
                "failed_attempts": self.failed_attempts,
                "alerted_ips": self.alerted_ips
            }
        )
        self.state_manager.save_state()

    
 