from flask import Flask, render_template, request
import sqlite3
import os

app = Flask(__name__)

# ---------------- DB PATH ---------------- #

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "siem.db")


# ---------------- DB CONNECTION ---------------- #

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# 🔹 NEW: Search query parser (ONLY ADDITION)
def parse_search_query(query):
    filters = {}

    if not query:
        return filters

    tokens = query.split()

    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            key = key.lower().strip()
            value = value.strip()

            if key in ["ip", "severity", "username", "event", "event_type"]:
                if key == "event":
                    key = "event_type"
                filters[key] = value

    return filters


# ---------------- LOG QUERY (UNCHANGED) ---------------- #

def get_logs(filters=None):
    conn = get_db_connection()

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if filters:
        if filters.get("ip"):
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            params.extend([f"%{filters['ip']}%", f"%{filters['ip']}%"])

        if filters.get("severity"):
            query += " AND severity = ?"
            params.append(filters["severity"])

        if filters.get("username"):
            query += " AND username LIKE ?"
            params.append(f"%{filters['username']}%")

        if filters.get("event_type"):
            query += " AND event_type LIKE ?"
            params.append(f"%{filters['event_type']}%")

    query += " ORDER BY timestamp DESC"

    logs = conn.execute(query, params).fetchall()
    conn.close()

    print("LOG COUNT:", len(logs))

    return logs


# ---------------- DASHBOARD HOME ---------------- #

@app.route('/')
def index():

    # 🔸 MODIFIED: existing filters (kept intact)
    filters = {
        "ip": request.args.get("ip"),
        "severity": request.args.get("severity"),
        "username": request.args.get("username"),
        "event_type": request.args.get("event_type")
    }

    # 🔹 NEW: search query support
    search_query = request.args.get("search", "")
    parsed_filters = parse_search_query(search_query)

    # 🔹 NEW: merge search filters into existing filters
    filters.update({k: v for k, v in parsed_filters.items() if v})

    # existing cleanup (unchanged)
    filters = {k: v for k, v in filters.items() if v}

    conn = get_db_connection()

    # ---------------- DASHBOARD STATS (UNCHANGED) ---------------- #
    total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    high_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'").fetchone()[0]

    # ---------------- FILTERED LOGS ---------------- #
    logs = get_logs(filters)

    # =========================================================
    # 📊 CHART 1: SEVERITY DISTRIBUTION (UNCHANGED)
    # =========================================================
    severity_data = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM logs
        GROUP BY severity
    """).fetchall()

    severity_labels = [row["severity"] for row in severity_data]
    severity_values = [row["count"] for row in severity_data]

    # =========================================================
    # 📊 CHART 2: ATTACK TYPE DISTRIBUTION (UNCHANGED)
    # =========================================================
    attack_data = conn.execute("""
        SELECT event_type, COUNT(*) as count
        FROM logs
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 3
    """).fetchall()

    attack_labels = [row["event_type"] for row in attack_data]
    attack_values = [row["count"] for row in attack_data]

    # =========================================================
    # 📊 CHART 3: TIME SERIES (UNCHANGED)
    # =========================================================
    time_data = conn.execute("""
        SELECT substr(timestamp, 1, 14) as time_bucket,
               COUNT(*) as count
        FROM logs
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        LIMIT 10
    """).fetchall()

    time_labels = [row["time_bucket"] for row in time_data]
    time_values = [row["count"] for row in time_data]

    conn.close()

    return render_template(
        "index.html",
        total_logs=total_logs,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        high_alerts=high_alerts,
        logs=logs,
        filters=filters,

        # CHART DATA (UNCHANGED)
        severity_labels=severity_labels,
        severity_values=severity_values,

        attack_labels=attack_labels,
        attack_values=attack_values,

        time_labels=time_labels,
        time_values=time_values
    )


# ---------------- ALERTS ---------------- #

# 🔸 MODIFIED: JOIN logs to fetch username
@app.route('/alerts')
def alerts():
    conn = get_db_connection()

    alerts = conn.execute("""
        SELECT 
            a.*,
            l.username
        FROM alerts a
        LEFT JOIN logs l ON a.log_id = l.id
        ORDER BY a.created_at DESC
    """).fetchall()

    conn.close()
    return render_template("alerts.html", alerts=alerts)


# ---------------- INCIDENTS ---------------- #

@app.route('/incidents')
def incidents():
    conn = get_db_connection()
    incidents = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("incidents.html", incidents=incidents)


# ---------------- TIMELINE ---------------- #

@app.route('/timeline/<int:incident_id>')
def timeline(incident_id):

    conn = get_db_connection()

    # 🔹 Step 1: Get incident
    incident = conn.execute(
        "SELECT * FROM incidents WHERE id = ?",
        (incident_id,)
    ).fetchone()

    # 🔹 Step 2: Extract source IP
    src_ip = incident["src_ip"]

    # 🔹 Step 3: Fetch FULL timeline (ALL logs from that IP)
    timeline = conn.execute("""
        SELECT timestamp, event_type, username, src_ip
        FROM logs
        WHERE src_ip = ?
        ORDER BY timestamp ASC
    """, (src_ip,)).fetchall()

    conn.close()

    return render_template(
        "timeline.html",
        incident=incident,
        timeline=timeline
    )


# ---------------- RUN ---------------- #

if __name__ == '__main__':
    app.run(debug=True)