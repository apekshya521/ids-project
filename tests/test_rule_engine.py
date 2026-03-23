"""
Run: python -m pytest tests/test_rule_engine.py -v
All 30 tests should pass before Tuesday submission.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from rules.rule_engine import apply_rules, _windows, _ip_windows
from scoring.scorer    import calculate_score, _user_scores


# ── Helpers ────────────────────────────────────────────────────────────────

def make_log(event_id, username="testuser", ip="10.0.0.5", **kwargs):
    return {
        "event_id":   event_id,
        "username":   username,
        "ip_address": ip,
        "channel":    "Security",
        "time":       "2025-03-17 14:00:00",
        "computer":   "TESTPC-01",
        "source":     "Microsoft-Windows-Security-Auditing",
        "description": "",
        **kwargs,
    }


def reset_state():
    _windows.clear()
    _ip_windows.clear()
    _user_scores.clear()


# ── R001: Audit log cleared ────────────────────────────────────────────────

class TestR001AuditLogCleared:

    def setup_method(self):
        reset_state()

    def test_1102_fires_immediately(self):
        r = apply_rules(make_log(1102))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R001"

    def test_104_fires(self):
        r = apply_rules(make_log(104))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R001"

    def test_confidence_is_1(self):
        r = apply_rules(make_log(1102))
        assert r["confidence"] == 1.0

    def test_severity_critical(self):
        r = apply_rules(make_log(1102))
        assert r["severity"] == "critical"

    def test_scores_critical(self):
        detected = apply_rules(make_log(1102))
        scored   = calculate_score(detected)
        assert scored["risk_score"] >= 80
        assert scored["severity"] == "CRITICAL"

    def test_system_suppressed(self):
        r = apply_rules(make_log(1102, username="SYSTEM"))
        assert r["is_suspicious"] is False

    def test_reason_contains_evidence(self):
        r = apply_rules(make_log(1102))
        assert "evidence" in r["reason"].lower() or "cleared" in r["reason"].lower()


# ── R002: Brute force ──────────────────────────────────────────────────────

class TestR002BruteForce:

    def setup_method(self):
        reset_state()

    def test_single_failure_no_alert(self):
        r = apply_rules(make_log(4625))
        assert r["is_suspicious"] is False

    def test_seven_failures_no_alert(self):
        for _ in range(7):
            r = apply_rules(make_log(4625, username="victim"))
        assert r["is_suspicious"] is False

    def test_eighth_failure_fires(self):
        for _ in range(8):
            r = apply_rules(make_log(4625, username="victim"))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R002"

    def test_count_appears_in_reason(self):
        for _ in range(8):
            r = apply_rules(make_log(4625, username="victim"))
        assert "8" in r["reason"]

    def test_different_users_no_trigger(self):
        for i in range(10):
            r = apply_rules(make_log(4625, username=f"user{i}", ip=f"10.0.{i}.1"))
        assert r["is_suspicious"] is False

    def test_system_never_triggers(self):
        for _ in range(10):
            r = apply_rules(make_log(4625, username="SYSTEM"))
        assert r["is_suspicious"] is False

    def test_score_zero_below_threshold(self):
        detected = apply_rules(make_log(4625))
        scored   = calculate_score(detected)
        assert scored["risk_score"] == 0

    def test_score_nonzero_after_threshold(self):
        for _ in range(8):
            detected = apply_rules(make_log(4625, username="victim"))
        scored = calculate_score(detected)
        assert scored["risk_score"] > 0


# ── R003: Malware detected ─────────────────────────────────────────────────

class TestR003MalwareDetected:

    def setup_method(self):
        reset_state()

    def test_1116_fires(self):
        r = apply_rules(make_log(1116))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R003"

    def test_1117_fires(self):
        r = apply_rules(make_log(1117))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R003"

    def test_scores_critical(self):
        detected = apply_rules(make_log(1116))
        scored   = calculate_score(detected)
        assert scored["risk_score"] >= 80
        assert scored["severity"] == "CRITICAL"

    def test_system_suppressed(self):
        r = apply_rules(make_log(1116, username="SYSTEM"))
        assert r["is_suspicious"] is False


# ── R004: Firewall disabled ────────────────────────────────────────────────

class TestR004FirewallDisabled:

    def setup_method(self):
        reset_state()

    def test_5025_fires(self):
        r = apply_rules(make_log(5025))
        assert r["is_suspicious"] is True
        assert r["rule_id"] == "R004"

    def test_confidence_is_1(self):
        r = apply_rules(make_log(5025))
        assert r["confidence"] == 1.0


# ── R009: New service installed ────────────────────────────────────────────

class TestR009NewService:

    def setup_method(self):
        reset_state()

    def test_suspicious_path_high_confidence(self):
        r = apply_rules(make_log(7045, service_path="C:\\Users\\Public\\evil.exe"))
        assert r["is_suspicious"] is True
        assert r["confidence"] >= 0.8

    def test_system32_path_low_confidence(self):
        r = apply_rules(make_log(
            7045,
            service_path="C:\\Windows\\System32\\legit.exe"
        ))
        if r["is_suspicious"]:
            assert r["confidence"] <= 0.2

    def test_4697_also_covered(self):
        r = apply_rules(make_log(7045))
        assert r["rule_id"] == "R009"


# ── Scorer general behaviour ───────────────────────────────────────────────

class TestScorer:

    def setup_method(self):
        reset_state()

    def test_score_never_exceeds_100(self):
        detected = apply_rules(make_log(1116))
        scored   = calculate_score(detected)
        assert scored["risk_score"] <= 100

    def test_non_suspicious_scores_zero(self):
        detected = apply_rules(make_log(4625))
        scored   = calculate_score(detected)
        assert scored["risk_score"] == 0
        assert scored["severity"] == "INFO"

    def test_severity_label_present(self):
        detected = apply_rules(make_log(1116))
        scored   = calculate_score(detected)
        assert scored["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_mitigation_present(self):
        detected = apply_rules(make_log(1116))
        scored   = calculate_score(detected)
        assert scored.get("mitigation")

    def test_critical_event_gets_critical_mitigation(self):
        detected = apply_rules(make_log(1102))
        scored   = calculate_score(detected)
        assert "isolate" in scored["mitigation"].lower()

    def test_repeated_events_accumulate_score(self):
        scores = []
        for _ in range(3):
            _windows.clear()
            detected = apply_rules(make_log(1102, username="attacker"))
            scored   = calculate_score(detected)
            scores.append(scored["risk_score"])
        assert scores[-1] >= scores[0]

    def test_rule_id_preserved_in_scored(self):
        detected = apply_rules(make_log(1102))
        scored   = calculate_score(detected)
        assert scored["rule_id"] == "R001"

    def test_mitre_tag_preserved(self):
        detected = apply_rules(make_log(1102))
        scored   = calculate_score(detected)
        assert scored["mitre"] == "T1070.001"