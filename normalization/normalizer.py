import os
from config import EVENT_DESCRIPTIONS


def normalize(log):
    # Get event_id with default 0 if missing
    event_id = log.get("event_id", 0)

    # Look up description from JSON
    description = EVENT_DESCRIPTIONS.get(str(event_id))
    
    # Fallback reasoning: Use description from JSON, or 'message' from raw log, 
    # or a generic label.
    if not description:
        description = log.get("message", "System Event")

    # Preserve ALL original fields (record_id, message, raw_data, etc.)
    # and override/set normalized fields on top
    return {
        **log,
        "event_id":    event_id,
        "description": description[:200] if description else "System Activity",
        "channel":     log.get("channel", "Unknown"),
        "time":        log.get("time", ""),
        "computer":    log.get("computer", "Unknown"),
        "source":      log.get("source", "Unknown"),
        "username":    log.get("username", "N/A"),
        "ip_address":  log.get("ip_address", "N/A"),
        "device_id":   log.get("device_id", "local"),
    }