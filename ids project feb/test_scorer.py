# test_scorer.py  (place in root of your project)
from scoring.scorer import calculate_score

def make_log(event_id, username, risk_level, reason, ip="192.168.1.1"):
    return {
        "event_id":      event_id,
        "username":      username,
        "ip_address":    ip,
        "channel":       "Security",
        "time":          "2026-02-20 02:30:00",
        "computer":      "WIN11-TEST",
        "is_suspicious": True,
        "risk_level":    risk_level,
        "reason":        reason,
        "description":   reason
    }

# ── Test Cases ───────────────────────────────
tests = [
    {
        "name": "Brute Force",
        "log": make_log(4625, "hacker", "High", "Brute Force! 5 failed logins for: hacker")
    },
    {
        "name": "Off Hours Login",
        "log": make_log(4624, "admin", "High", "Off Hours Login Detected for: admin")
    },
    {
        "name": "Audit Log Cleared",
        "log": make_log(1102, "badguy", "High", "Audit Log Cleared by: badguy")
    },
    {
        "name": "Malware Detected",
        "log": make_log(1116, "SYSTEM", "High", "Malware Detected by Windows Defender!")
    },
    {
        "name": "Firewall Stopped",
        "log": make_log(5025, "admin", "High", "Windows Firewall Stopped!")
    },
    {
        "name": "Multiple IPs",
        "log": make_log(4624, "user1", "High", "Multiple IPs Detected for: user1")
    },
    {
        "name": "Normal Logon",
        "log": make_log(4624, "john", "Normal", "An account was successfully logged on")
    },
    {
        "name": "Privilege Escalation",
        "log": make_log(4728, "hacker", "High", "User Added to Privileged Group by: hacker")
    },
]

# ── Run Tests ─────────────────────────────────
print("=" * 65)
print(f"{'TEST':<25} {'SCORE':>6}  {'SEVERITY':<10} {'TOTAL':>6}")
print("=" * 65)

for t in tests:
    result = calculate_score(t["log"])
    print(
        f"{t['name']:<25}"
        f" {result['risk_score']:>5}/100"
        f"  {result['severity']:<10}"
        f" {result['user_total_score']:>5} (total)"
    )
    print(f"  → {result['mitigation']}")
    print("-" * 65)
