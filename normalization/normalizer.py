import os
from config import EVENT_DESCRIPTIONS


def normalize(log):
    event_id = log["event_id"]

    # Look up description from JSON
    description = EVENT_DESCRIPTIONS.get(str(event_id), "Normal System Event")

    return {
        "event_id":    event_id,
        "description": description,
        "channel":     log["channel"],
        "time":        log["time"],
        "computer":    log["computer"],
        "username":    log.get("username", "unknown"),
        "ip_address":  log.get("ip_address", "local"),
    }