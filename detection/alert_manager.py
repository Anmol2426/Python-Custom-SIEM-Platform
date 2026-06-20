from detection.incident_manager import IncidentManager


class AlertManager:
    def __init__(self, db_connection):
        self.conn = db_connection
        self.incident_manager = IncidentManager(self.conn)  # ✅ NEW

    def store_alert(self, alert):
        cursor = self.conn.cursor()

        # 🔥 Dedup check
        cursor.execute("""
        SELECT 1 FROM alerts
        WHERE log_id = ?
        AND alert_type = ?
        """, (
            alert.get("log_id"),
            alert.get("alert_type")
        ))

        if cursor.fetchone():
            print("[DEBUG] Duplicate alert skipped")
            return

        # ✅ INCIDENT GROUPING (NEW)
        incident_id = self.incident_manager.get_or_create_incident(alert)
        alert["incident_id"] = incident_id

        # Insert if not duplicate
        cursor.execute("""
        INSERT INTO alerts (
            log_id,
            incident_id,
            alert_type,
            severity,
            src_ip,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("log_id"),
            alert.get("incident_id"),
            alert.get("alert_type"),
            alert.get("severity"),
            alert.get("src_ip"),
            alert.get("description"),
            alert.get("created_at"),
        ))

        self.conn.commit()
        print("[DEBUG] Insert successful")

    def handle_alerts(self, alerts):
        print(f"[DEBUG] Handling {len(alerts)} alerts")

        for alert in alerts:
            print("[DEBUG] Storing alert:", alert)
            self.store_alert(alert)