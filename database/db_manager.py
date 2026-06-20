import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "siem.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""

    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        username TEXT,
        event_type TEXT,
        severity TEXT,
        raw_log TEXT,
        log_hash TEXT
    );

    CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_name TEXT,
    severity TEXT,
    status TEXT,
    src_ip TEXT,
    created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        incident_id INTEGER,
        alert_type TEXT,
        severity TEXT,
        src_ip TEXT,
        description TEXT,
        created_at TEXT,
        FOREIGN KEY (log_id) REFERENCES logs(id),
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
    );

    CREATE TABLE IF NOT EXISTS timeline_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        event_time TEXT,
        event_type TEXT,
        src_ip TEXT,
        description TEXT,
        FOREIGN KEY (log_id) REFERENCES logs(id)
    );

    CREATE TABLE IF NOT EXISTS log_integrity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        sha256_hash TEXT,
        created_at TEXT,
        FOREIGN KEY (log_id) REFERENCES logs(id)
    );

    """)

    conn.commit()
    conn.close()


def insert_log(timestamp, src_ip, dst_ip, username, event_type, severity, raw_log, log_hash=None):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs
    (timestamp, src_ip, dst_ip, username, event_type, severity, raw_log, log_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, username, event_type, severity, raw_log, log_hash))

    log_id = cursor.lastrowid

    from datetime import datetime

    cursor.execute("""
    INSERT INTO log_integrity (log_id, sha256_hash, created_at)
    VALUES (?, ?, ?)
    """, (
        log_id,
        log_hash,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return log_id