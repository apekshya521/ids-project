import win32evtlog
import win32evtlogutil
import logging
import ipaddress
import json
from datetime import datetime

logger = logging.getLogger("ids.reader")

# ── All 3 Channels ─────────────────────────
CHANNELS = ["Security", "Application", "System"]

# ── Events That Never Have IP ──────────────
NO_IP_EVENTS = {
    4720, 4726, 4728, 4732, 4740,
    1102, 4719, 7045, 4698, 4699,
    4672, 4634, 4647, 1116, 1117,
    5025, 5001, 4946, 4947, 4948
}

# ── Known Username Positions Per EventID ───
USERNAME_POSITIONS = {
    4624: 5,   # successful logon
    4625: 5,   # failed logon
    4672: 1,   # special privileges
    4720: 0,   # account created
    4726: 0,   # account deleted
    4740: 0,   # account locked
    4728: 0,   # added to global group
    4732: 0,   # added to local group
    1102: 1,   # log cleared
    4698: 0,   # scheduled task created
    4699: 0,   # scheduled task deleted
    7045: 0,   # new service installed
}

# ── Known IP Positions Per EventID ─────────
IP_POSITIONS = {
    4624: 18,  # logon
    4625: 19,  # failed logon
    5140: 6,   # network share access
    4648: 12,  # explicit credentials
}

# ── Skip These Usernames ───────────────────
SKIP_USERNAMES = {
    "-", "", "N/A", "RulesEngine",
    "SYSTEM", "LOCAL SERVICE",
    "NETWORK SERVICE", "Window Manager",
    "Font Driver Host", "UMFD-0",
    "UMFD-1", "UMFD-2", "DWM-1",
    "DWM-2", "DWM-3"
}


# ══════════════════════════════════════════
# MAIN FUNCTIONS
# ══════════════════════════════════════════

def read_all_logs(after_records=None):
    """
    Reads all 3 channels at once.

    Args:
        after_records: dict of last record per channel
        e.g. {"Security": 500, "Application": 300, "System": 200}

    Returns:
        List of all logs from all 3 channels
    """
    if after_records is None:
        after_records = {}

    all_logs = []

    for channel in CHANNELS:
        last = after_records.get(channel, 0)
        logs = read_logs(channel, after_record=last)
        all_logs.extend(logs)
        logger.info(f"[{channel}] Read {len(logs)} new events")

    logger.info(f"Total logs read: {len(all_logs)}")
    return all_logs


def read_logs(channel, after_record=0):
    """
    Reads events from ONE channel.

    Args:
        channel:      "Security" / "Application" / "System"
        after_record: only read events newer than this record number

    Returns:
        List of log dictionaries
    """
    logs = []

    try:
        # Open connection to Windows Event Log
        log   = win32evtlog.OpenEventLog("localhost", channel)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        events = win32evtlog.ReadEventLog(log, flags, 0)

        for event in events:
            record_id = event.RecordNumber
            event_id  = event.EventID & 0xFFFF
            inserts   = list(event.StringInserts) if event.StringInserts else []

            # Stop when we hit already processed events
            if record_id <= after_record:
                break

            # Extract all fields
            username   = extract_username(event_id, inserts)
            ip_address = extract_ip(event_id, inserts)
            computer   = extract_computer(event)
            timestamp  = extract_timestamp(event)
            raw_data   = extract_raw_message(event, channel, inserts)

            logs.append({
                "event_id":   event_id,
                "channel":    channel,
                "time":       timestamp,
                "computer":   computer,
                "username":   username,
                "ip_address": ip_address,
                "source":     event.SourceName if event.SourceName else "Unknown"
                
            })

        win32evtlog.CloseEventLog(log)

    except Exception as e:
        logger.error(f"[READER ERROR] {channel}: {e}", exc_info=True)

    return logs


# ══════════════════════════════════════════
# EXTRACTION FUNCTIONS
# ══════════════════════════════════════════

def extract_computer(event):
    """
    Gets source computer name.
    Falls back to UNKNOWN if missing.
    """
    try:
        computer = event.ComputerName
        if computer and computer.strip():
            return computer.strip()
    except:
        pass

    logger.warning("Computer name missing — using UNKNOWN")
    return "UNKNOWN"


def extract_timestamp(event):
    """
    Gets event timestamp.
    Falls back to current time if missing.
    """
    try:
        ts = str(event.TimeGenerated)
        if ts and ts.strip():
            return ts.strip()
    except:
        pass

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.warning(f"Timestamp missing — using current time: {now}")
    return now


def extract_username(event_id, inserts):
    """
    Gets username from correct StringInserts position.
    Returns N/A if not found or invalid.
    """
    try:
        # Check if EventID has known username position
        if event_id not in USERNAME_POSITIONS:
            return "N/A"

        index    = USERNAME_POSITIONS[event_id]
        username = inserts[index].strip() if index < len(inserts) else ""

        # Filter out system accounts and placeholders
        if (username
                and username not in SKIP_USERNAMES
                and not username.endswith("$")
                and not username.startswith("\\")
                and "T" not in username[:10]):  # skip timestamp-like values
            return username

    except:
        pass

    return "N/A"


def extract_ip(event_id, inserts):
    """
    Gets IP address from event.

    Priority:
    1. Known position for this EventID
    2. Scan all values for valid IP
    3. Host-Based Event (if local event)
    4. Non-Network Event (if no IP found)
    """
    try:
        # Events that never have IP
        if event_id in NO_IP_EVENTS:
            return "Host-Based Event"

        if not inserts:
            return "Non-Network Event"

        # Try known exact position first
        if event_id in IP_POSITIONS:
            idx = IP_POSITIONS[event_id]
            if idx < len(inserts):
                ip_val = inserts[idx].strip()
                if ip_val and ip_val not in ("-", "::1", "127.0.0.1", ""):
                    return ip_val
            return "Host-Based Event"

        # Fallback — scan all values for valid IP
        for part in inserts:
            part = part.strip()
            if part and part[0].isdigit() and part.count(".") == 3:
                try:
                    ip = ipaddress.ip_address(part)
                    if str(ip) not in ("127.0.0.1", "0.0.0.0"):
                        return str(ip)
                except ValueError:
                    pass

    except Exception as e:
        logger.debug(f"Error extracting IP: {e}")

    return "Non-Network Event"


def extract_raw_message(event, channel, inserts):
    """
    Gets full formatted message from Event Viewer.
    Falls back to raw inserts if formatting fails.
    """
    try:
        raw_text = win32evtlogutil.SafeFormatMessage(event, channel)
        if raw_text and raw_text.strip():
            return raw_text.strip()
    except:
        pass

    # Fallback to raw inserts
    try:
        return json.dumps(inserts) if inserts else "N/A"
    except:
        pass

    return "N/A"