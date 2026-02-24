import os
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from config import EVENT_DESCRIPTIONS as ALL_EVENTS

logger = logging.getLogger("ids.rules")

# ── Thread Safety ──────────────────────────
rules_lock = threading.Lock()

# ── Risk Levels ────────────────────────────
HIGH_RISK = {
    1102, 4625, 4720, 4726, 4728, 4732,
    4740, 4719, 7045, 4698, 4782, 4794,
    1116, 1117, 5025, 4946, 4947, 4948
}

MEDIUM_RISK = {
    4624, 4672, 4688, 4697, 4702, 4699,
    4723, 4724, 4738, 4756, 4757, 4781,
    5379, 4648, 4657, 4670,
    4904, 4905, 5001, 5004, 5007
}

LOW_RISK = {
    4634, 4647, 4768, 4769, 4770, 4771,
    4776, 4778, 4779, 4798, 4799, 5140,
    5142, 5144, 5145, 5156, 5157, 7040,
    6008, 7036, 1000, 1001, 1002
}

# ── Events to Ignore (Windows Noise) ──────
IGNORE_EVENTS = {16384, 16394, 10010, 6005, 6006}

# ── Tracking Variables with Timestamps ─────────────────────
# username → {"timestamp": datetime, "count": int}
failed_logins   = defaultdict(lambda: {"timestamp": None, "count": 0})
# username → {"timestamp": datetime, "ips": set}
user_ips        = defaultdict(lambda: {"timestamp": None, "ips": set()})
# username → {"timestamp": datetime, "count": int}
explicit_logons = defaultdict(lambda: {"timestamp": None, "count": 0})

BRUTE_FORCE_LIMIT    = 3
EXPLICIT_LOGON_LIMIT = 3
TRACKING_WINDOW      = 3600  # 1 hour in seconds


def cleanup_old_entries(now: datetime):
    """Remove tracking entries older than 1 hour"""
    cutoff = now - timedelta(seconds=TRACKING_WINDOW)
    
    # Clean failed_logins
    to_delete = [u for u, d in failed_logins.items() 
                 if d["timestamp"] and d["timestamp"] < cutoff]
    for u in to_delete:
        del failed_logins[u]
    
    # Clean user_ips
    to_delete = [u for u, d in user_ips.items() 
                 if d["timestamp"] and d["timestamp"] < cutoff]
    for u in to_delete:
        del user_ips[u]
    
    # Clean explicit_logons
    to_delete = [u for u, d in explicit_logons.items() 
                 if d["timestamp"] and d["timestamp"] < cutoff]
    for u in to_delete:
        del explicit_logons[u]


def check_off_hours(time_str):
    """Flag logins between 12am and 5am"""
    try:
        dt = datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
        return 0 <= dt.hour < 5
    except ValueError:
        return False


def check_multiple_ips(username, ip_address):
    """Flag if same user logs in from more than 2 different IPs"""
    if ip_address and ip_address != "local":
        user_ips[username]["ips"].add(ip_address)
    return len(user_ips[username]["ips"]) > 2


def apply_rules(log):
    with rules_lock:
        return _apply_rules_locked(log)


def _apply_rules_locked(log):
    event_id   = log["event_id"]
    username   = log.get("username",   "unknown")
    ip_address = log.get("ip_address", "local")
    channel    = log.get("channel",    "unknown")
    time       = log.get("time",       "unknown")
    computer   = log.get("computer",   "unknown")
    description = ALL_EVENTS.get(str(event_id), "Unknown Event")

    # ── Cleanup old entries (prevent memory leak) ──────────
    now = datetime.now()
    cleanup_old_entries(now)

    # ── Noise Filter: Ignore routine Windows events ────
    if event_id in IGNORE_EVENTS:
        return {
            "event_id":      event_id,
            "description":   description,
            "channel":       channel,
            "time":          time,
            "computer":      computer,
            "username":      username,
            "ip_address":    ip_address,
            "is_suspicious": False,
            "risk_level":    "Normal",
            "risk_score":    0,
            "severity":      "INFO",
            "reason":        "Routine system event",
            "mitigation":    "Normal Windows activity"
        }

    # Base result
    result = {
        "event_id":      event_id,
        "description":   description,
        "channel":       channel,
        "time":          time,
        "computer":      computer,
        "username":      username,
        "ip_address":    ip_address,
        "is_suspicious": False,
        "risk_level":    "Normal",
        "reason":        description
    }

    # ── Rule 1: Brute Force ────────────────
    if event_id == 4625:
        failed_logins[username]["count"] += 1
        failed_logins[username]["timestamp"] = now
        if failed_logins[username]["count"] >= BRUTE_FORCE_LIMIT:
            result.update({
                "is_suspicious": True,
                "risk_level":    "High",
                "reason":        f"Brute Force! {failed_logins[username]['count']} failed logins for: {username}"
            })
            return result

    # ── Rule 2: Reset on success ───────────
    if event_id == 4624:
        failed_logins[username]["count"] = 0
        failed_logins[username]["timestamp"] = now

    # ── Rule 3: Off Hours Login ────────────
    if event_id == 4624 and check_off_hours(time):
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        f"Off Hours Login Detected for: {username}"
        })
        return result

    # ── Rule 4: Multiple IPs Same User ────
    if event_id == 4624 and check_multiple_ips(username, ip_address):
        user_ips[username]["timestamp"] = now
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        f"Multiple IPs Detected for: {username} IPs: {user_ips[username]['ips']}"
        })
        return result

    # ── Rule 5: Explicit Credential Use ───
    if event_id == 4648:
        explicit_logons[username]["count"] += 1
        explicit_logons[username]["timestamp"] = now
        if explicit_logons[username]["count"] >= EXPLICIT_LOGON_LIMIT:
            result.update({
                "is_suspicious": True,
                "risk_level":    "High",
                "reason":        f"Repeated Explicit Credential Use by: {username}"
            })
            return result

    # ── Rule 6: Audit Log Cleared ──────────
    if event_id == 1102:
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        f"Audit Log Cleared by: {username}"
        })
        return result

    # ── Rule 7: Malware Detected ───────────
    if event_id in {1116, 1117}:
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        "Malware Detected by Windows Defender!"
        })
        return result

    # ── Rule 8: Firewall Stopped ───────────
    if event_id == 5025:
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        "Windows Firewall Stopped!"
        })
        return result

    # ── Rule 9: New Admin User ─────────────
    if event_id in {4728, 4732, 4756}:
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        f"User Added to Privileged Group by: {username}"
        })
        return result

    # ── Rule 10: Unexpected Shutdown ───────
    if event_id == 6008:
        result.update({
            "is_suspicious": True,
            "risk_level":    "Medium",
            "reason":        "Unexpected System Shutdown Detected"
        })
        return result

    # ── Rule 11: High Risk ─────────────────
    if event_id in HIGH_RISK:
        result.update({
            "is_suspicious": True,
            "risk_level":    "High",
            "reason":        description
        })

    # ── Rule 12: Medium Risk ───────────────
    elif event_id in MEDIUM_RISK:
        result.update({
            "is_suspicious": True,
            "risk_level":    "Medium",
            "reason":        description
        })

    # ── Rule 13: Low Risk ──────────────────
    elif event_id in LOW_RISK:
        result.update({
            "is_suspicious": True,
            "risk_level":    "Low",
            "reason":        description
        })

    return result