from detection.rule_engine import RuleEngine
from detection.alert_manager import AlertManager

class DetectionEngine:
    def __init__(self, db_connection):
        self.conn = db_connection
        self.rule_engine = RuleEngine()
        self.alert_manager = AlertManager(self.conn)
        self.last_processed_id = self.load_last_processed_id()

    def load_last_processed_id(self):
        """
        Load last processed log ID (initially 0)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT MAX(id) FROM logs")
            result = cursor.fetchone()

            # Start from beginning if no logs
            return 0 if result[0] is None else 0

        except Exception as e:
            print(f"[ERROR] Failed to load last processed ID: {e}")
            return 0

    def fetch_new_logs(self):
        """
        Fetch logs not yet processed
        """
        cursor = self.conn.cursor()

        query = """
        SELECT id, timestamp, src_ip, dst_ip, event_type, severity, raw_log
        FROM logs
        WHERE id > ?
        ORDER BY id ASC
        """

        cursor.execute(query, (self.last_processed_id,))
        rows = cursor.fetchall()

        logs = []
        for row in rows:
            log = {
                "id": row[0],
                "timestamp": row[1],
                "src_ip": row[2],
                "dst_ip": row[3],
                "event_type": row[4],
                "severity": row[5],
                "raw_log": row[6],
            }
            logs.append(log)

        return logs

    def run_detection(self):
        """
        Main detection pipeline
        """
        logs = self.fetch_new_logs()

        if not logs:
            return []

        alerts = self.rule_engine.process_logs(logs)
        self.alert_manager.handle_alerts(alerts)  # 👈 MUST be here

        # ✅ ADD THIS BLOCK HERE
        for rule in self.rule_engine.rules:
            if hasattr(rule, "save_state"):
                rule.save_state()

        # Update last processed ID
        self.last_processed_id = logs[-1]["id"]

        # Update last processed ID
        self.last_processed_id = logs[-1]["id"]

        return alerts