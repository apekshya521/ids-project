import threading
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("ids.scorer")
_lock  = threading.Lock()

# Per-user accumulated score with time decay
# Score halves every 30 minutes so old activity fades
_user_scores: dict[str, dict] = defaultdict(lambda: {
    "score":     0.0,
    "last_seen": datetime.min,
})

DECAY_HALF_LIFE  = 1800   # seconds — 30 minutes
MAX_HISTORY_BONUS = 20    # max points added from user history per event

# Score → severity label (checked top to bottom)
SEVERITY_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (10, "LOW"),
    (0,  "INFO"),
]

MITIGATION = {
    "CRITICAL": "IMMEDIATE — isolate host, block IP, reset credentials",
    "HIGH":     "URGENT — investigate account and review recent activity",
    "MEDIUM":   "ELEVATED — monitor closely for further signals",
    "LOW":      "ROUTINE — log and correlate with other events",
    "INFO":     "Normal activity — no action required",
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _decayed_score(stored: dict, now: datetime) -> float:
    """Apply exponential decay to a stored user score."""
    elapsed = max((now - stored["last_seen"]).total_seconds(), 0)
    return stored["score"] * (0.5 ** (elapsed / DECAY_HALF_LIFE))


def _severity_label(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


# ── Public API ─────────────────────────────────────────────────────────────

def calculate_score(detected: dict) -> dict:
    with _lock:
        return _calculate_locked(detected)


def _calculate_locked(d: dict) -> dict:
    # Non-suspicious → zero score, no further work
    if not d.get("is_suspicious"):
        return {
            **d,
            "risk_score": 0,
            "severity":   "INFO",
            "mitigation": MITIGATION["INFO"],
        }

    username = d.get("username", "N/A")
    base     = float(d.get("base_score", 0))
    conf     = float(d.get("confidence", 0.5))
    ctx      = float(d.get("context_multiplier", 1.0))
    al       = float(d.get("allowlist_multiplier", 1.0))
    now      = datetime.now()

    # ── Core formula ──────────────────────────────────────────────
    # raw = base_severity × confidence × context × allowlist_factor
    raw = base * conf * ctx * al

    # ── History bonus ──────────────────────────────────────────────
    # Rewards sustained attacker activity — repeat offenders score higher
    stored      = _user_scores[username]
    history     = min(_decayed_score(stored, now), MAX_HISTORY_BONUS)
    raw        += history

    # Update stored score for this user
    _user_scores[username] = {
        "score":     _decayed_score(stored, now) + raw,
        "last_seen": now,
    }

    # ── Cap and label ──────────────────────────────────────────────
    final    = min(int(raw), 100)
    severity = _severity_label(final)

    logger.debug(
        f"[SCORE] {username} | base={base:.0f} conf={conf:.2f} "
        f"ctx={ctx:.2f} al={al:.2f} hist={history:.1f} "
        f"→ {final} ({severity})"
    )

    return {
        **d,
        "risk_score": final,
        "severity":   severity,
        "mitigation": MITIGATION[severity],
    }


def reset_user_score(username: str):
    """Call this if you want to manually clear a user's history (e.g. after investigation)."""
    with _lock:
        if username in _user_scores:
            del _user_scores[username]