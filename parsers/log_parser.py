import re
# ✅ NEW IMPORT (for hashing)
import hashlib

def extract_timestamp(log):
    """
    Extract timestamp from common syslog format
    Example: Jan 12 10:15:32
    """

    pattern = r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    match = re.search(pattern, log)

    if match:
        return match.group(1)

    return None


def extract_ip(log):
    """
    Extract source and destination IP addresses from different log formats
    """

    # Case 1: SSH logs (from IP)
    ssh_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
    if ssh_match:
        return ssh_match.group(1), None

    # Case 2: Firewall logs (SRC / DST)
    src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', log)
    dst_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', log)

    src_ip = src_match.group(1) if src_match else None
    dst_ip = dst_match.group(1) if dst_match else None

    return src_ip, dst_ip

# ✅ NEW FUNCTION (username extraction)
def extract_username(log):
    """
    Extract username from SSH logs
    Example: 'Failed password for root from ...'
    """
    match = re.search(r'for (\w+)', log)
    if match:
        return match.group(1)

    return None


def detect_event_type(log):
    """
    Identify event type and severity
    """

    log_lower = log.lower()

    if "failed password" in log_lower:
        return "Failed Login", "High"

    elif "accepted password" in log_lower:
        return "Authentication Success", "Low"

    elif "denied" in log_lower or "blocked" in log_lower:
        return "Firewall Block", "Medium"

    elif "error" in log_lower:
        return "System Error", "Medium"

    return "Unknown Event", "Low"


def parse_log(raw_log):
    """
    Generic log parser
    """
    if not raw_log.strip():
        return None

    timestamp = extract_timestamp(raw_log)

    src_ip, dst_ip = extract_ip(raw_log)

    event_type, severity = detect_event_type(raw_log)

    # ✅ NEW: Extract username
    username = extract_username(raw_log)

    # ✅ NEW: Generate log hash
    log_hash = hashlib.sha256(raw_log.strip().encode()).hexdigest()

    parsed_log = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,   # ✅ NEW FIELDS
        "event_type": event_type,
        "severity": severity,
        "raw_log": raw_log.strip(),
        "log_hash": log_hash    # ✅ NEW FIELDS
    }

    return parsed_log