from database.db_manager import initialize_database, insert_log
from parsers.log_parser import parse_log
from collector.log_collector import collect_logs
# New additions for step 4 :
import sqlite3
from detection.engine import DetectionEngine
from detection.timeline_manager import TimelineManager
import argparse

# 🔹 NEW IMPORTS (ONLY ADDITION)
import threading
import webbrowser
from dashboard.app import app   # adjust if path differs


def process_log(raw_log):
    """
    Parse raw log and store it in database
    """

    parsed_log = parse_log(raw_log)

    if parsed_log:

        insert_log(
            timestamp=parsed_log["timestamp"],
            src_ip=parsed_log["src_ip"],
            dst_ip=parsed_log["dst_ip"],
            # ✅ NEW (IMPORTANT)
            username=parsed_log.get("username"),
            event_type=parsed_log["event_type"],
            severity=parsed_log["severity"],
            raw_log=parsed_log["raw_log"],
            # ✅ NEW (IMPORTANT)
            log_hash=parsed_log.get("log_hash")
        )

# 🔹 NEW: Run Flask in background
def run_dashboard():
    app.run(debug=True, use_reloader=False)

# 🔹 NEW: Auto open browser
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")


# New Addition for step 4 : Detection Engine
def main():
    conn = sqlite3.connect("siem.db")
    detector = DetectionEngine(conn)

    # Step 1: Collect logs
    logs = collect_logs()

    # Step 2: Parse + Store
    for raw_log in logs:
        if not raw_log.strip():
            continue
        process_log(raw_log)

    # Step 3: Run detection AFTER logs are inserted
    detector.run_detection()

    #Manual Timeline in CLI
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident", type=int, help="Show timeline for incident ID")

    args = parser.parse_args()
    
    # 👉 ADD THIS BLOCK BELOW
    if args.incident:
        tm = TimelineManager(conn)

        timeline = tm.build_timeline(args.incident)


        if timeline:
            print("\n===== INCIDENT TIMELINE =====")
            print(f"Incident: {timeline['incident_name']}")
            print(f"Source IP: {timeline['src_ip']}")
            print(f"Created At: {timeline['created_at']}")
            print("\n--- Events ---")

            for entry in timeline["timeline"]:
                print(f"[{entry['timestamp']}] → {entry['event_type']} (user: {entry.get('username')})")
            # Exporting Timleline 
            filename = f"incident_{args.incident}_timeline.txt"
            tm.export_timeline(timeline,filename)

    print("Logs collected, parsed, and stored successfully.")


if __name__ == "__main__":

    initialize_database()
    
     # 🔹 START DASHBOARD (BACKGROUND THREAD)
    threading.Thread(target=run_dashboard).start()

    # 🔹 OPEN BROWSER AFTER SHORT DELAY
    threading.Timer(2, open_browser).start()
    
    main()
