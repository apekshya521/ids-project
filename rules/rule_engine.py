import yaml
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("ids.rules")
_lock  = threading.Lock()
_BASE  = Path(__file__).parent


# ── Load YAML files ────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error(f"Missing file: {path}")
        return {}


RULES     = _load_yaml(_BASE / "rules.yaml").get("rules", [])
ALLOWLIST = _load_yaml(_BASE / "allowlist.yaml")

# O(1) lookup: event_id → list of rules
_RULES_BY_EVENT: dict[int, list] = defaultdict(list)
for _r in RULES:
    for _eid in _r.get("event_ids", []):
        _RULES_BY_EVENT[_eid].append(_r)

logger.info(f"Rule engine ready — {len(RULES)} rules, "
            f"{len(_RULES_BY_EVENT)} event IDs covered")


# ── In-memory state ────────────────────────────────────────────────────────

# Per-username window: tracks events, unique IPs seen
_windows: dict[str, dict] = defaultdict(lambda: {
    "events":     [],        # [(timestamp, rule_id, ip)]
    "unique_ips": set(),
})

# Per-IP window: tracks unique usernames (for password spray R012)
_ip_windows: dict[str, dict] = defaultdict(lambda: {
    "events":       [],
    "unique_users": set(),
})


def _cleanup(state: dict, now: datetime, window_seconds: int):
    cutoff = now - timedelta(seconds=window_seconds)
    kept = [e for e in state["events"] if e[0] > cutoff]
    state["events"] = kept
    # Rebuild unique_ips from surviving events to prevent stale entries
    state["unique_ips"] = {e[2] for e in kept if e[2] not in ("N/A", "Non-Network Event", "Host-Based Event", "")}


def _cleanup_ip(state: dict, now: datetime, window_seconds: int):
    cutoff = now - timedelta(seconds=window_seconds)
    kept = [e for e in state["events"] if e[0] > cutoff]
    state["events"] = kept
    state["unique_users"] = {e[2] for e in kept}


# ── Allowlist ──────────────────────────────────────────────────────────────

def _allowlist_multiplier(log: dict, rule_id: str | None = None) -> float:
    username  = log.get("username", "")
    ip        = log.get("ip_address", "")
    device_id = log.get("device_id", "local")

    # Hard suppress system accounts
    if username in ALLOWLIST.get("usernames", []):
        return 0.0

    # Per-device rule suppression
    device_cfg = ALLOWLIST.get("devices", {}).get(device_id, {})
    suppressed = device_cfg.get("suppress_rules", [])
    if rule_id and rule_id in suppressed:
        return 0.0

    # Trusted IPs reduce confidence
    trusted_cfg = ALLOWLIST.get("trusted_ips", {})
    if ip in trusted_cfg.get("addresses", []):
        return 1.0 - trusted_cfg.get("confidence_reduction", 0.4)

    return 1.0


# ── Context ────────────────────────────────────────────────────────────────

def _is_off_hours(now: datetime, log: dict = None) -> bool:
    """
    Check whether an event occurred outside business hours.
    Uses the log's own time field when available — essential for
    replayed logs and demo/test scenarios where system time differs
    from the event time being tested.
    """
    if log:
        time_str = log.get("time", "")
        if time_str:
            try:
                now = datetime.strptime(str(time_str)[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                pass  # fall back to system time

    bh    = ALLOWLIST.get("business_hours", {})
    start = bh.get("start", 8)
    end   = bh.get("end", 19)
    days  = bh.get("days", [0, 1, 2, 3, 4])
    return (now.weekday() not in days) or not (start <= now.hour < end)


def _context_multiplier(now: datetime, log: dict = None) -> float:
    return 1.25 if _is_off_hours(now, log) else 1.0


# ── Context condition checker ──────────────────────────────────────────────

def _context_conditions_met(conditions: list, log: dict, now: datetime) -> bool:
    username = log.get("username", "").lower()

    for cond in conditions:
        if "off_hours" in cond:
            # Pass log so time field is used, not system clock
            if cond["off_hours"] != _is_off_hours(now, log):
                return False

        if "username_in" in cond:
            allowed = [u.lower() for u in cond["username_in"]]
            if username not in allowed:
                return False

        if "username_not_in" in cond:
            blocked = [u.lower() for u in cond["username_not_in"]]
            if username in blocked:
                return False

    return True


# ── Confidence reducer ─────────────────────────────────────────────────────

def _apply_reducers(rule: dict, log: dict, confidence: float) -> float:
    for reducer in rule.get("confidence_reducers", []):
        condition = reducer.get("condition", "")

        if condition == "path_contains":
            val  = reducer.get("value", "").lower()
            path = (
                log.get("service_path", "") or
                log.get("task_path", "") or
                log.get("message", "")
            ).lower()
            if val in path:
                confidence = reducer.get("reduce_to", confidence)

        elif condition == "event_id_is":
            if log.get("event_id") == reducer.get("value"):
                confidence = reducer.get("reduce_to", confidence)

    return confidence


# ── Result builder ─────────────────────────────────────────────────────────

def _build_result(rule: dict, log: dict, confidence: float, **fmt) -> dict:
    try:
        reason = rule["reason"].format(
            count            = fmt.get("count", 1),
            prior_count      = fmt.get("prior_count", 0),
            window           = (rule.get("threshold") or {}).get("window_seconds", 0),
            ip               = log.get("ip_address", "unknown"),
            ip_count         = fmt.get("ip_count", 0),
            unique_usernames = fmt.get("unique_usernames", 0),
            service_name     = log.get("service_name", "unknown"),
            service_path     = log.get("service_path", "unknown"),
            task_name        = log.get("task_name", "unknown"),
            target_username  = log.get("target_username",
                                       log.get("username", "unknown")),
            matched_keyword  = fmt.get("matched_keyword", ""),
        )
    except (KeyError, ValueError):
        reason = rule.get("reason", rule["name"])

    return {
        "rule_id":       rule["id"],
        "rule_name":     rule["name"],
        "mitre":         rule.get("mitre", ""),
        "category":      rule.get("category", "unknown"),
        "severity":      rule["severity"],
        "base_score":    rule["base_score"],
        "confidence":    round(confidence, 4),
        "reason":        reason,
        "is_suspicious": True,
    }


# ── Rule evaluators ────────────────────────────────────────────────────────

def _eval_single_fire(rule: dict, log: dict, now: datetime) -> dict | None:
    """Rules with threshold: null — fire on first matching event."""
    confidence = rule.get("confidence_on_threshold", 1.0)

    # Context-gated rules (e.g. off_hours_admin R014, network share R018)
    require_ctx = rule.get("require_context", [])
    if require_ctx:
        if not _context_conditions_met(require_ctx, log, now):
            return None
        confidence = rule.get("confidence_when_context_met", confidence)

    # Content keyword match (e.g. PowerShell R017)
    content_cfg = rule.get("require_content_match")
    if content_cfg:
        message  = log.get(content_cfg.get("field", "message"), "").lower()
        keywords = content_cfg.get("keywords", [])
        matched  = [kw for kw in keywords if kw.lower() in message]
        if len(matched) < content_cfg.get("min_matches", 1):
            return None
        confidence = rule.get("confidence_when_content_matched",
                               content_cfg.get("confidence", 0.7))
        return _build_result(rule, log, confidence,
                             matched_keyword=matched[0])

    # Apply confidence reducers (e.g. system32 path for services)
    confidence = _apply_reducers(rule, log, confidence)

    if confidence <= 0.0:
        return None

    return _build_result(rule, log, confidence)


def _eval_threshold(rule: dict, log: dict,
                    state: dict, now: datetime) -> dict | None:
    """Rules with a count or unique_ips threshold."""
    threshold_cfg = rule["threshold"]
    window_secs   = threshold_cfg.get("window_seconds", 3600)
    group_by      = threshold_cfg.get("group_by", "username")
    ip            = log.get("ip_address", "N/A")
    username      = log.get("username", "N/A")

    # ── Password spray: group by IP (R012) ────────────────────────
    if group_by == "ip_address":
        ip_state = _ip_windows[ip]
        _cleanup_ip(ip_state, now, window_secs)
        ip_state["events"].append((now, rule["id"], username))
        ip_state["unique_users"].add(username)

        required = threshold_cfg.get("unique_usernames", 999)
        if len(ip_state["unique_users"]) >= required:
            confidence = rule.get("confidence_on_threshold", 0.8)
            return _build_result(rule, log, confidence,
                                 unique_usernames=len(ip_state["unique_users"]))
        return None

    # ── Unique IPs threshold (R016) ────────────────────────────────
    if "unique_ips" in threshold_cfg:
        state["unique_ips"].add(ip)
        if len(state["unique_ips"]) >= threshold_cfg["unique_ips"]:
            confidence = rule.get("confidence_on_threshold", 0.65)
            return _build_result(rule, log, confidence,
                                 ip_count=len(state["unique_ips"]))
        return None

    # ── Standard count threshold ───────────────────────────────────
    rule_events = [e for e in state["events"] if e[1] == rule["id"]]
    count       = len(rule_events)
    required    = threshold_cfg.get("count", 999)

    if count < required:
        return None

    # ── Success-after-failure check (R011) ─────────────────────────
    if rule.get("require_prior_failures"):
        prior_eid      = rule.get("prior_failure_event_id", 4625)
        prior_min      = rule.get("prior_failure_min", 3)
        prior_win      = rule.get("prior_failure_window", 600)
        cutoff         = now - timedelta(seconds=prior_win)
        prior_rules    = [r for r in RULES if prior_eid in r.get("event_ids", [])]
        prior_rule_ids = {r["id"] for r in prior_rules}
        prior_count    = sum(
            1 for t, rid, i in state["events"]
            if t > cutoff and rid in prior_rule_ids
        )
        if prior_count < prior_min:
            return None
        confidence = rule.get("confidence_on_threshold", 0.85)
        return _build_result(rule, log, confidence, prior_count=prior_count)

    confidence = rule.get("confidence_on_threshold", 0.75)
    confidence = _apply_reducers(rule, log, confidence)
    return _build_result(rule, log, confidence, count=count,
                         window=threshold_cfg.get("window_seconds", 0))


def _evaluate_rule(rule: dict, log: dict,
                   state: dict, now: datetime) -> dict | None:
    window_secs = (rule.get("threshold") or {}).get("window_seconds", 3600)
    ip          = log.get("ip_address", "N/A")

    # Cleanup uses the rule's own window, then we add the new event
    _cleanup(state, now, window_secs)
    state["events"].append((now, rule["id"], ip))
    # unique_ips is now rebuilt by _cleanup, so just add the new one
    if ip not in ("N/A", "Non-Network Event", "Host-Based Event", ""):
        state["unique_ips"].add(ip)

    if rule.get("threshold") is None:
        return _eval_single_fire(rule, log, now)
    else:
        return _eval_threshold(rule, log, state, now)


# ── Public entry point ─────────────────────────────────────────────────────

def apply_rules(log: dict) -> dict:
    with _lock:
        return _apply_rules_locked(log)


def _apply_rules_locked(log: dict) -> dict:
    event_id = log.get("event_id", 0)
    username = log.get("username", "N/A")
    now      = datetime.now()

    base = {
        **log,
        "is_suspicious":        False,
        "rule_id":              None,
        "rule_name":            None,
        "mitre":                None,
        "category":             None,
        "severity":             "normal",
        "base_score":           0,
        "confidence":           0.0,
        "reason":               log.get("description", ""),
        "context_multiplier":   1.0,
        "allowlist_multiplier": 1.0,
    }

    matching_rules = _RULES_BY_EVENT.get(event_id, [])
    if not matching_rules:
        return base

    state = _windows[username]

    # Evaluate all matching rules, keep best (highest confidence)
    best: dict | None = None
    for rule in matching_rules:
        al_mult = _allowlist_multiplier(log, rule["id"])
        if al_mult == 0.0:
            continue

        result = _evaluate_rule(rule, log, state, now)
        if result is None:
            continue

        if best is None or result["confidence"] > best["confidence"]:
            best = result
            best["_al_mult"] = al_mult

    if best is None:
        return base

    al_mult  = best.pop("_al_mult", 1.0)

    # Pass log so off-hours uses event time, not system clock
    ctx_mult = _context_multiplier(now, log)

    return {
        **base,
        **best,
        "context_multiplier":   ctx_mult,
        "allowlist_multiplier": al_mult,
    }