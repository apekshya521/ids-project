import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from config import EVENT_DESCRIPTIONS as ALL_EVENTS

logger = logging.getLogger("ids.rules")

# ─────────────────────────────────────────────
# Thread Safety
# ─────────────────────────────────────────────
rules_lock = threading.Lock()

# ─────────────────────────────────────────────
# Risk Levels (Noise Optimized)
# ─────────────────────────────────────────────
CRITICAL_RISK = {
    1102,   # audit log cleared
    7045,   # service installed
    4719,   # audit policy changed
    5025,   # firewall stopped
    1116,   # malware detected
    1117    # malware action
}

HIGH_RISK = {
    4720,   # user created
    4726,   # user deleted
    4698,   # scheduled task created
    4728,   # added to admin group
    4732,   # added to local admin
}

MEDIUM_RISK = {
    4625,   # failed login
    4740,   # account lock
    4672,   # admin privileges
    4688,   # process created
    4702,   # scheduled task modified
    4648    # explicit credentials
}

LOW_RISK = {
    4634, 4647, 4768, 4769, 4771,
    4776, 4778, 4779, 4798, 4799,
    5140, 5142, 5144, 5145, 5156,
    5157, 7040, 6008, 7036
}

# ─────────────────────────────────────────────
# Ignore Windows Noise
# ─────────────────────────────────────────────
IGNORE_EVENTS = {
    16384, 16394,
    10010,
    6005, 6006
}

# ─────────────────────────────────────────────
# Account Filters
# ─────────────────────────────────────────────
SYSTEM_ACCOUNTS = {
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE"
}

ADMIN_ACCOUNTS = {
    "administrator",
    "admin",
    "domain_admin"
}

# ─────────────────────────────────────────────
# Tracking Variables
# ─────────────────────────────────────────────
failed_logins = defaultdict(lambda: {"count": 0, "ips": set(), "timestamp": None})
user_ips = defaultdict(lambda: {"ips": set(), "timestamp": None})
explicit_logons = defaultdict(lambda: {"count": 0, "timestamp": None})

recent_alerts = {}

# ─────────────────────────────────────────────
# Thresholds
# ─────────────────────────────────────────────
BRUTE_FORCE_LIMIT = 8
EXPLICIT_LOGON_LIMIT = 6
MULTI_IP_LIMIT = 4
TRACKING_WINDOW = 3600
ALERT_SUPPRESSION = 300

# ─────────────────────────────────────────────
# Cleanup Old Entries
# ─────────────────────────────────────────────
def cleanup_old_entries(now):

    cutoff = now - timedelta(seconds=TRACKING_WINDOW)

    for store in (failed_logins, user_ips, explicit_logons):
        remove = [
            u for u, d in store.items()
            if d["timestamp"] and d["timestamp"] < cutoff
        ]
        for u in remove:
            del store[u]

# ─────────────────────────────────────────────
# Off Hours Detection
# ─────────────────────────────────────────────
def check_off_hours(time_str):

    try:
        dt = datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
        return 0 <= dt.hour < 5
    except:
        return False

# ─────────────────────────────────────────────
# Multiple IP Detection
# ─────────────────────────────────────────────
def check_multiple_ips(username, ip):

    if ip and ip != "N/A":
        user_ips[username]["ips"].add(ip)

    return len(user_ips[username]["ips"]) > MULTI_IP_LIMIT

# ─────────────────────────────────────────────
# Alert Deduplication
# ─────────────────────────────────────────────
def suppress_duplicate(event_id, username, now):

    key = f"{event_id}-{username}"

    if key in recent_alerts:
        if (now - recent_alerts[key]).seconds < ALERT_SUPPRESSION:
            return True

    recent_alerts[key] = now
    return False

# ─────────────────────────────────────────────
# Rule Entry
# ─────────────────────────────────────────────
def apply_rules(log):

    with rules_lock:
        return _apply_rules_locked(log)

# ─────────────────────────────────────────────
# Rule Engine
# ─────────────────────────────────────────────
def _apply_rules_locked(log):

    event_id = log["event_id"]
    username = log.get("username", "N/A")
    ip = log.get("ip_address", "N/A")
    time = log.get("time", "unknown")
    channel = log.get("channel", "unknown")
    computer = log.get("computer", "unknown")
    logon_type = log.get("logon_type")

    description = ALL_EVENTS.get(str(event_id), "Unknown Event")

    now = datetime.now()

    cleanup_old_entries(now)

    result = {
        "event_id": event_id,
        "description": description,
        "channel": channel,
        "time": time,
        "computer": computer,
        "username": username,
        "ip_address": ip,
        "source": log.get("source", "Unknown"),
        "is_suspicious": False,
        "risk_level": "Normal",
        "reason": description
    }

    # ─────────────────────────
    # Ignore Noise Events
    # ─────────────────────────
    if event_id in IGNORE_EVENTS:
        return result

    # ─────────────────────────
    # Ignore System Accounts
    # ─────────────────────────
    if username in SYSTEM_ACCOUNTS:
        return result

    # ─────────────────────────
    # Brute Force Detection
    # ─────────────────────────
    if event_id == 4625:

        failed_logins[username]["count"] += 1
        failed_logins[username]["ips"].add(ip)
        failed_logins[username]["timestamp"] = now

        if (
            failed_logins[username]["count"] >= BRUTE_FORCE_LIMIT
            and len(failed_logins[username]["ips"]) == 1
        ):

            if suppress_duplicate(event_id, username, now):
                return result

            result.update({
                "is_suspicious": True,
                "risk_level": "High",
                "reason": f"Brute Force Suspected: {failed_logins[username]['count']} failures"
            })

            return result

    # ─────────────────────────
    # Reset Counter on Success
    # ─────────────────────────
    if event_id == 4624:
        failed_logins[username]["count"] = 0

    # ─────────────────────────
    # Off Hours Admin Login
    # ─────────────────────────
    if event_id == 4624 and username.lower() in ADMIN_ACCOUNTS:

        if check_off_hours(time):

            result.update({
                "is_suspicious": True,
                "risk_level": "High",
                "reason": f"Off-hours admin login detected"
            })

            return result

    # ─────────────────────────
    # Multiple IP Detection
    # ─────────────────────────
    if event_id == 4624 and check_multiple_ips(username, ip):

        result.update({
            "is_suspicious": True,
            "risk_level": "Medium",
            "reason": f"User logged in from multiple IPs"
        })

        return result

    # ─────────────────────────
    # Explicit Credentials Abuse
    # ─────────────────────────
    if event_id == 4648:

        explicit_logons[username]["count"] += 1
        explicit_logons[username]["timestamp"] = now

        if explicit_logons[username]["count"] >= EXPLICIT_LOGON_LIMIT:

            result.update({
                "is_suspicious": True,
                "risk_level": "Medium",
                "reason": "Repeated explicit credential usage"
            })

            return result

    # ─────────────────────────
    # Audit Log Cleared
    # ─────────────────────────
    if event_id == 1102:

        result.update({
            "is_suspicious": True,
            "risk_level": "Critical",
            "reason": "Security audit log cleared"
        })

        return result

    # ─────────────────────────
    # Malware Detected
    # ─────────────────────────
    if event_id in {1116, 1117}:

        result.update({
            "is_suspicious": True,
            "risk_level": "Critical",
            "reason": "Malware detected by Windows Defender"
        })

        return result

    # ─────────────────────────
    # Firewall Disabled
    # ─────────────────────────
    if event_id == 5025:

        result.update({
            "is_suspicious": True,
            "risk_level": "Critical",
            "reason": "Windows firewall stopped"
        })

        return result

    # ─────────────────────────
    # Suspicious Service Install
    # ─────────────────────────
    if event_id == 7045:

        path = log.get("service_path", "").lower()

        if "windows\\system32" not in path:

            result.update({
                "is_suspicious": True,
                "risk_level": "Critical",
                "reason": f"Suspicious service installed: {path}"
            })

            return result

    # ─────────────────────────
    # Risk Classification
    # ─────────────────────────
    if event_id in CRITICAL_RISK:

        result.update({
            "is_suspicious": True,
            "risk_level": "Critical"
        })

    elif event_id in HIGH_RISK:

        result.update({
            "is_suspicious": True,
            "risk_level": "High"
        })

    elif event_id in MEDIUM_RISK:

        result.update({
            "is_suspicious": True,
            "risk_level": "Medium"
        })

    elif event_id in LOW_RISK:

        result.update({
            "is_suspicious": True,
            "risk_level": "Low"
        })

    return result