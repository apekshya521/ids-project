# scoring/scorer.py (Real-Time Version)
import threading
from collections import defaultdict
from datetime import datetime, timedelta

scorer_lock = threading.Lock()

# ── Time-Window Tracking ─────────────────
event_window   = defaultdict(list)   # username → [timestamps]
score_history  = defaultdict(int)    # username → accumulated score
WINDOW_SECONDS = 60                  # 1 minute rolling window

BASE_SCORES = {
    "High":   80,
    "Medium": 50,
    "Low":    25,
    "Normal":  0
}

BONUS_SCORES = {
    "Brute Force":       20,
    "Off Hours":         15,
    "Multiple IPs":      15,
    "Audit Log Cleared": 15,
    "Malware":           10,
    "Firewall Stopped":  10,
    "Privileged Group":  10,
    "Explicit Cred":      8,
    "Unexpected Shutdown": 5
}


def get_time_window_multiplier(username, event_id, now):
    """
    Count how many times same event happened
    for same user in last 60 seconds → escalate score
    """
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    
    # Clean old entries
    event_window[username] = [
        t for t in event_window[username] if t > cutoff
    ]
    
    # Add current event
    event_window[username].append(now)
    count = len(event_window[username])
    
    # Multiplier based on frequency
    if count >= 10:
        return 2.0   # Double score
    elif count >= 5:
        return 1.5   # 50% boost
    elif count >= 3:
        return 1.2   # 20% boost
    return 1.0       # No change


def calculate_score(detected_result):
    with scorer_lock:
        return _calculate_score_locked(detected_result)

def _calculate_score_locked(detected_result):
    event_id   = detected_result["event_id"]
    username   = detected_result["username"]
    risk_level = detected_result["risk_level"]
    reason     = detected_result["reason"]
    now        = datetime.now()

    # Base score
    score = BASE_SCORES.get(risk_level, 0)

    # Bonus for specific attack patterns
    for keyword, bonus in BONUS_SCORES.items():
        if keyword in reason:
            score += bonus

    # Time-window frequency multiplier
    multiplier = get_time_window_multiplier(username, event_id, now)
    score = int(score * multiplier)

    # Accumulate per-user score
    score_history[username] += score

    # Cap per-event at 100
    score = min(score, 100)

    # Severity
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        **detected_result,
        "risk_score":      score,
        "severity":        severity,
        "user_total_score": min(score_history[username], 999),
        "mitigation":      get_mitigation(severity)
    }


def get_mitigation(severity):
    return {
        "CRITICAL": "IMMEDIATE — Isolate host, block IP, reset password",
        "HIGH":     "URGENT — Investigate account, check admin groups",
        "MEDIUM":   "ELEVATED — Monitor for further activity",
        "LOW":      "ROUTINE — Log and correlate",
        "INFO":     "Normal activity"
    }.get(severity, "Review manually")


def score_log(clean_log):
    from rules.rule_engine import apply_rules
    detected = apply_rules(clean_log)
    return calculate_score(detected)
