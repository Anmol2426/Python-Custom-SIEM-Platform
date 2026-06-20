from datetime import datetime


class IncidentManager:
    def __init__(self, conn):
        self.conn = conn

    def get_open_incident(self, src_ip):
        cursor = self.conn.cursor()

        query = """
        SELECT id FROM incidents
        WHERE src_ip = ? AND status = 'OPEN'
        LIMIT 1
        """

        cursor.execute(query, (src_ip,))
        result = cursor.fetchone()

        return result[0] if result else None

    def create_incident(self, alert):
        cursor = self.conn.cursor()

        query = """
        INSERT INTO incidents (incident_name, severity, status, src_ip, created_at)
        VALUES (?, ?, ?, ?, ?)
        """

        cursor.execute(query, (
            alert["alert_type"],
            alert["severity"],
            "OPEN",
            alert["src_ip"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        self.conn.commit()
        return cursor.lastrowid

    def get_or_create_incident(self, alert):
        src_ip = alert.get("src_ip")

        if not src_ip:
            return None

        incident_id = self.get_open_incident(src_ip)

        if incident_id:
            return incident_id

        return self.create_incident(alert)