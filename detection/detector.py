from collections import defaultdict
import datetime
import logging
from rules.rule_engine import apply_rules

logger = logging.getLogger("ids.detector")

# Simple user session tracking
user_sessions = defaultdict(list)

def detect(log):
    username = log.get("username", "unknown")
    if username != "unknown":
        now = datetime.datetime.now()
        user_sessions[username].append(now)
        
        # Keep only last 10 minutes
        cutoff = now - datetime.timedelta(minutes=10)
        user_sessions[username] = [t for t in user_sessions[username] if t > cutoff]
        
        if len(user_sessions[username]) > 100:
            logger.warning(f"High activity volume detected for user: {username}")
            
    # Delegate to rules engine
    return apply_rules(log)