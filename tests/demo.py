"""
demo.py — IDS Rule Simulation
Run: python demo.py

Injects synthetic log events directly into the detection pipeline.
No Windows, no WinRM, no real devices needed.
"""

import sys
import os
import json
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rules.rule_engine import apply_rules, _windows, _ip_windows, ALLOWLIST
from scoring.scorer    import calculate_score, _user_scores

# ── Colours ────────────────────────────────────────────────────────────────
SEV_COL = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.GREEN,
    "INFO":     Fore.WHITE,
}
PASS_COL = Fore.GREEN + Style.BRIGHT
FAIL_COL = Fore.RED   + Style.BRIGHT
HEAD_COL = Fore.MAGENTA + Style.BRIGHT
DIM      = Style.DIM
RST      = Style.RESET_ALL


# ── Helpers ────────────────────────────────────────────────────────────────

def reset():
    _windows.clear()
    _ip_windows.clear()
    _user_scores.clear()


def fake_log(event_id, username="attacker", ip="192.168.1.99",
             time_str=None, **kwargs):
    return {
        "event_id":    event_id,
        "username":    username,
        "ip_address":  ip,
        "channel":     "Security",
        "time":        time_str or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "computer":    "VICTIM-PC",
        "source":      "Microsoft-Windows-Security-Auditing",
        "description": "",
        "device_id":   "local",
        **kwargs,
    }


def run(log_dict, expect_alert=True, expect_rule=None, label=""):
    """Run one log through the full pipeline and print result."""
    detected = apply_rules(log_dict)
    scored   = calculate_score(detected)

    fired    = bool(scored.get("is_suspicious", False))
    score    = scored.get("risk_score", 0)
    severity = scored.get("severity") or "INFO"
    rule_id  = scored.get("rule_id") or "—"
    reason   = scored.get("reason") or "—"

    passed = (fired == expect_alert)
    if expect_rule and fired:
        passed = passed and (rule_id == expect_rule)

    status  = f"{PASS_COL}PASS{RST}" if passed else f"{FAIL_COL}FAIL{RST}"
    sev_str = f"{SEV_COL.get(severity, '')}{severity:<8}{RST}"

    print(f"  {status}  "
          f"{label:<45} "
          f"rule={rule_id:<6} "
          f"score={score:<4} "
          f"{sev_str} "
          f"{DIM}{str(reason)[:55]}{RST}")

    return passed


def header(title):
    print(f"\n{HEAD_COL}{'─'*72}")
    print(f"  {title}")
    print(f"{'─'*72}{RST}")


def send(log_dict):
    """Silently push a log through pipeline — no output."""
    apply_rules(log_dict)


# ── Individual Rule Tests ──────────────────────────────────────────────────

def test_r001_audit_log_cleared():
    header("R001 — Audit log cleared")
    reset()
    results = [
        run(fake_log(1102), True,  "R001", "Event 1102 fires immediately"),
        run(fake_log(104),  True,  "R001", "Event 104 also fires"),
    ]
    reset()
    results.append(
        run(fake_log(1102, username="SYSTEM"), False, None, "SYSTEM account suppressed")
    )
    return results


def test_r002_brute_force():
    header("R002 — Brute force login (threshold=8)")
    results = []

    # Test 1: single failure no alert
    reset()
    results.append(
        run(fake_log(4625, username="victim"), False, None, "Single failure — no alert")
    )

    # Test 2: 8th failure triggers
    reset()
    for _ in range(7):
        send(fake_log(4625, username="victim"))
    results.append(
        run(fake_log(4625, username="victim"), True, "R002", "8th failure triggers")
    )

    # Test 3: different users same IP — correctly fires SPRAY not brute force
    reset()
    for i in range(10):
        send(fake_log(4625, username=f"user{i}", ip="10.0.0.1"))
    results.append(
        run(fake_log(4625, username="user11", ip="10.0.0.1"),
            True, "R012", "Different users same IP — spray fires correctly")
    )

    # Test 4: SYSTEM always suppressed
    reset()
    for _ in range(10):
        send(fake_log(4625, username="SYSTEM"))
    results.append(
        run(fake_log(4625, username="SYSTEM"), False, None, "SYSTEM — always suppressed")
    )

    return results


def test_r003_malware():
    header("R003 — Malware detected")
    reset()
    results = [
        run(fake_log(1116), True, "R003", "Event 1116 fires immediately"),
        run(fake_log(1117), True, "R003", "Event 1117 fires immediately"),
    ]
    reset()
    results.append(
        run(fake_log(1116, username="SYSTEM"), False, None, "SYSTEM suppressed")
    )
    return results


def test_r004_firewall():
    header("R004 — Firewall disabled")
    reset()
    return [run(fake_log(5025), True, "R004", "Event 5025 fires immediately")]


def test_r005_defender():
    header("R005 — Defender disabled")
    reset()
    return [
        run(fake_log(5001), True, "R005", "Event 5001 fires immediately"),
        run(fake_log(5007), True, "R005", "Event 5007 fires (reduced conf)"),
    ]


def test_r006_new_user():
    header("R006 — New user created")
    reset()
    return [run(fake_log(4720, target_username="hacker"), True, "R006", "Event 4720 fires")]


def test_r007_priv_group():
    header("R007 — Added to privileged group")
    reset()
    return [
        run(fake_log(4728), True, "R007", "Event 4728 fires"),
        run(fake_log(4732), True, "R007", "Event 4732 fires"),
        run(fake_log(4756), True, "R007", "Event 4756 fires"),
    ]


def test_r008_audit_policy():
    header("R008 — Audit policy changed")
    reset()
    return [run(fake_log(4719), True, "R008", "Event 4719 fires")]


def test_r009_new_service():
    header("R009 — New service installed")
    reset()
    results = [
        run(fake_log(7045,
                     service_path="C:\\Users\\Public\\evil.exe",
                     service_name="EvilSvc"),
            True, "R009", "Suspicious path fires"),
    ]
    reset()
    detected = apply_rules(fake_log(
        7045,
        service_path="C:\\Windows\\System32\\legit.exe",
        service_name="LegitSvc"
    ))
    scored = calculate_score(detected)
    conf   = detected.get("confidence", 0)
    passed = conf <= 0.2
    status = f"{PASS_COL}PASS{RST}" if passed else f"{FAIL_COL}FAIL{RST}"
    print(f"  {status}  {'System32 path — low confidence':<45} conf={conf:.2f}  score={scored['risk_score']}")
    results.append(passed)
    return results


def test_r010_sched_task():
    header("R010 — Scheduled task created")
    reset()
    results = [
        run(fake_log(4698, task_name="EvilTask"), True, "R010", "Custom task fires"),
    ]
    reset()
    detected = apply_rules(fake_log(
        4698, task_name="WindowsUpdate",
        message="\\Microsoft\\Windows\\UpdateOrchestrator\\"
    ))
    scored = calculate_score(detected)
    passed = scored["risk_score"] < 20
    status = f"{PASS_COL}PASS{RST}" if passed else f"{FAIL_COL}FAIL{RST}"
    print(f"  {status}  {'Microsoft task — low score':<45} score={scored['risk_score']}")
    results.append(passed)
    return results


def test_r011_success_after_fail():
    header("R011 — Success after failures")
    reset()
    for _ in range(3):
        send(fake_log(4625, username="victim"))
    results = [
        run(fake_log(4624, username="victim"), True, "R011", "Success after 3 failures"),
    ]
    reset()
    results.append(
        run(fake_log(4624, username="cleanuser"), False, None, "Clean success — no alert")
    )
    return results


def test_r012_password_spray():
    header("R012 — Password spray")
    reset()
    for i in range(4):
        send(fake_log(4625, username=f"user{i}", ip="10.0.0.1"))
    return [
        run(fake_log(4625, username="user4", ip="10.0.0.1"),
            True, "R012", "5 users from same IP — spray fires"),
    ]


def test_r013_lockout():
    header("R013 — Account lockout")
    reset()
    return [run(fake_log(4740, target_username="victim"), True, "R013", "Event 4740 fires")]


def test_r014_offhours_admin():
    header("R014 — Off-hours admin login")
    reset()
    results = [
        run(fake_log(4624, username="administrator",
                     time_str="2025-03-17 02:00:00"),
            True, "R014", "Admin at 2 AM fires"),
    ]
    reset()
    results.append(
        run(fake_log(4624, username="regularuser",
                     time_str="2025-03-17 02:00:00"),
            False, None, "Regular user at 2 AM — no R014")
    )
    return results


def test_r015_explicit_creds():
    header("R015 — Explicit credentials abuse")
    reset()
    for _ in range(4):
        send(fake_log(4648, username="attacker"))
    results = [
        run(fake_log(4648, username="attacker"), True, "R015", "5th explicit cred fires"),
    ]
    reset()
    results.append(
        run(fake_log(4648, username="attacker"), False, None, "Single explicit cred — no alert")
    )
    return results


def test_r016_multi_ip():
    header("R016 — Multiple IP login")
    reset()
    for i in range(4):
        send(fake_log(4624, username="rover", ip=f"10.0.0.{i+1}"))
    return [
        run(fake_log(4624, username="rover", ip="10.0.0.5"),
            True, "R016", "5th distinct IP fires"),
    ]


def test_r017_powershell():
    header("R017 — Suspicious PowerShell")
    reset()
    results = [
        run(fake_log(4104, message="invoke-mimikatz -dumpcreds"),
            True, "R017", "Mimikatz keyword fires"),
        run(fake_log(4104, message="iex(new-object net.webclient)"),
            True, "R017", "IEX + webclient fires"),
    ]
    reset()
    results.append(
        run(fake_log(4104, message="Get-ChildItem C:\\Users"),
            False, None, "Normal PowerShell — no alert")
    )
    return results


def test_r018_network_share():
    header("R018 — Network share off-hours")
    reset()
    results = [
        run(fake_log(5140, time_str="2025-03-17 03:00:00"),
            True, "R018", "Share access at 3 AM fires"),
    ]
    reset()
    results.append(
        run(fake_log(5140, time_str="2025-03-17 14:00:00"),
            False, None, "Share access at 2 PM — no alert")
    )
    return results


def test_r019_task_modified():
    header("R019 — Scheduled task modified rapidly")
    reset()
    for _ in range(2):
        send(fake_log(4702, username="attacker"))
    results = [
        run(fake_log(4702, username="attacker"), True, "R019", "3 rapid modifications fires"),
    ]
    reset()
    results.append(
        run(fake_log(4702, username="attacker"), False, None, "Single modification — no alert")
    )
    return results


def test_scoring_sanity():
    header("Scoring sanity checks")
    checks = [
        ("Score never exceeds 100",
         lambda: calculate_score(apply_rules(fake_log(1116)))["risk_score"] <= 100),
        ("Single 4625 scores zero",
         lambda: calculate_score(apply_rules(fake_log(4625)))["risk_score"] == 0),
        ("MITRE tag preserved",
         lambda: bool(calculate_score(apply_rules(fake_log(1102))).get("mitre"))),
        ("SYSTEM always scores zero",
         lambda: calculate_score(apply_rules(fake_log(1102, username="SYSTEM")))["risk_score"] == 0),
        ("Mitigation always present",
         lambda: bool(calculate_score(apply_rules(fake_log(1116))).get("mitigation"))),
    ]
    results = []
    for label, fn in checks:
        reset()
        try:
            passed = fn()
        except Exception as e:
            passed = False
            label  = f"{label} [ERR: {e}]"
        status = f"{PASS_COL}PASS{RST}" if passed else f"{FAIL_COL}FAIL{RST}"
        print(f"  {status}  {label}")
        results.append(passed)
    return results


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    loaded_users = ALLOWLIST.get("usernames", [])
    if not loaded_users:
        print(f"{FAIL_COL}WARNING: allowlist.yaml not loaded — "
              f"check rules/allowlist.yaml exists{RST}\n")
    else:
        print(f"{DIM}Allowlist: {len(loaded_users)} suppressed accounts loaded{RST}")

    print(f"\n{HEAD_COL}{'='*72}")
    print(f"  IDS RULE SIMULATION — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*72}{RST}")

    all_results = []
    all_results += test_r001_audit_log_cleared()
    all_results += test_r002_brute_force()
    all_results += test_r003_malware()
    all_results += test_r004_firewall()
    all_results += test_r005_defender()
    all_results += test_r006_new_user()
    all_results += test_r007_priv_group()
    all_results += test_r008_audit_policy()
    all_results += test_r009_new_service()
    all_results += test_r010_sched_task()
    all_results += test_r011_success_after_fail()
    all_results += test_r012_password_spray()
    all_results += test_r013_lockout()
    all_results += test_r014_offhours_admin()
    all_results += test_r015_explicit_creds()
    all_results += test_r016_multi_ip()
    all_results += test_r017_powershell()
    all_results += test_r018_network_share()
    all_results += test_r019_task_modified()
    all_results += test_scoring_sanity()

    total  = len(all_results)
    passed = sum(1 for r in all_results if r)
    failed = total - passed

    print(f"\n{HEAD_COL}{'='*72}{RST}")
    if failed == 0:
        print(f"  {PASS_COL}ALL {total} CHECKS PASSED — pipeline working correctly{RST}")
    else:
        print(f"  {PASS_COL}{passed} passed{RST}  {FAIL_COL}{failed} failed{RST}  ({total} total)")
    print(f"{HEAD_COL}{'='*72}{RST}\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())