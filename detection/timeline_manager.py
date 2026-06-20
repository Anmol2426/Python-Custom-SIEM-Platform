class TimelineManager:
    def __init__(self, conn):
        self.conn = conn

    def get_incident(self, incident_id):
        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT id, incident_name, src_ip, created_at
        FROM incidents
        WHERE id = ?
        """, (incident_id,))

        return cursor.fetchone()

    def get_logs_for_incident(self, src_ip):
        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT timestamp, event_type, raw_log
        FROM logs
        WHERE src_ip = ?
        ORDER BY id ASC
        """, (src_ip,))

        return cursor.fetchall()

    def build_timeline(self, incident_id):
        incident = self.get_incident(incident_id)

        if not incident:
            print("Incident not found")
            return

        _, name, src_ip, created_at = incident

        logs = self.get_logs_for_incident(src_ip)

        timeline = []

        for log in logs:
            entry = {
                "timestamp": log[0],
                "event_type": log[1],
                "raw_log": log[2]
            }
            timeline.append(entry)

        return {
            "incident_name": name,
            "src_ip": src_ip,
            "created_at": created_at,
            "timeline": timeline
        }
    
    def export_timeline(self, timeline_data, filename="timeline.txt"):
        if not timeline_data:
            print("[ERROR] No timeline data to export")
            return

        with open(filename, "w") as f:
            f.write("===== INCIDENT TIMELINE =====\n\n")
            f.write(f"Incident: {timeline_data['incident_name']}\n")
            f.write(f"Source IP: {timeline_data['src_ip']}\n")
            f.write(f"Created At: {timeline_data['created_at']}\n\n")

            for entry in timeline_data["timeline"]:
                f.write(f"[{entry['timestamp']}] {entry['event_type']}\n")

        print(f"[INFO] Timeline exported to {filename}")