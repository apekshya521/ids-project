import win32evtlog
import win32evtlogutil
import logging
import ipaddress
import json
import re
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


def read_logs(channel, after_record=0, lookback_minutes=45):
    """
    Reads events from ONE channel.
    
    Args:
        channel:          "Security" / "Application" / "System"
        after_record:      only read events newer than this record number (higher priority)
        lookback_minutes:  if after_record is 0, read events from the last X minutes
    """
    logs = []
    now = datetime.now()
    log_handle = None

    try:
        log_handle = win32evtlog.OpenEventLog("localhost", channel)
        
        # Flags for reading: Start from the newest and go backwards
        # We stop when we hit after_record OR exceed lookback_minutes
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        is_first_event = True
        
        while True:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not events:
                break

            for event in events:
                record_id = event.RecordNumber
                
                # Detect log clear: if the newest event ID in the log is smaller than our bookmark, 
                # the log was cleared and IDs reset to 1. Reset our bookmark to capture new events.
                if is_first_event:
                    is_first_event = False
                    if after_record > 0 and record_id < after_record:
                        logger.warning(f"[{channel}] Log clear detected! Newest ID ({record_id}) < Bookmark ({after_record}). Resetting bookmark.")
                        after_record = 0
                
                # ── Stop Condition 1: Bookmark reached ──
                if after_record > 0 and record_id <= after_record:
                    return logs

                # ── Stop Condition 2: Time window exceeded ──
                # event.TimeGenerated is a pywintypes.datetime object
                event_time = datetime.fromtimestamp(event.TimeGenerated.timestamp())
                delta = now - event_time
                
                if after_record == 0 and (delta.total_seconds() / 60) > lookback_minutes:
                    return logs

                # ── Process Event ──
                event_id = event.EventID & 0xFFFF
                inserts = list(event.StringInserts) if event.StringInserts else []
                
                # Extract fields
                username = extract_username(event_id, inserts)
                ip_address = extract_ip(event_id, inserts)
                computer = event.ComputerName
                timestamp = event_time.strftime("%Y-%m-%d %H:%M:%S")
                raw_data = extract_raw_message(event, channel, inserts)

                logs.append({
                    "record_id":  record_id,
                    "event_id":   event_id,
                    "channel":    channel,
                    "time":       timestamp,
                    "computer":   computer,
                    "username":   username,
                    "ip_address": ip_address,
                    "source":     event.SourceName if event.SourceName else "Unknown",
                    "message":    raw_data
                })

    except Exception as e:
        logger.error(f"[READER ERROR] {channel}: {e}")
    finally:
        # Always close event log handle to prevent OS handle leak
        if log_handle:
            try:
                win32evtlog.CloseEventLog(log_handle)
            except Exception:
                pass

    # Since we read backwards, we reverse to return them in chronological order
    return logs[::-1]


# ══════════════════════════════════════════
# EXTRACTION FUNCTIONS
# ══════════════════════════════════════════

def extract_computer(event):
    """
    Gets source computer name.
    Uses the actual MachineName from the event.
    """
    try:
        # Try to get MachineName from the event
        computer = event.ComputerName
        if computer and computer.strip():
            return computer.strip()
    except (IndexError, TypeError, ValueError, AttributeError, UnicodeError):
        pass
    
    # Fallback to local hostname if event doesn't have ComputerName
    try:
        import socket
        return socket.gethostname()
    except:
        pass
    
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
    except (IndexError, TypeError, ValueError, AttributeError, UnicodeError):
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
                and not re.match(r'\d{4}-\d{2}-\d{2}T', username)):  # skip ISO timestamp values
            return username

    except (IndexError, TypeError, ValueError, AttributeError, UnicodeError):
        pass

    return "N/A"


def extract_ip(event_id, inserts):
    """
    Gets IP address from event.
    Hardened with regex scanner fallback.
    """
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    try:
        # Events that never have IP
        if event_id in NO_IP_EVENTS:
            return "Host-Based Event"

        if not inserts:
            return "Non-Network Event"

        # 1. Try known exact position first
        if event_id in IP_POSITIONS:
            idx = IP_POSITIONS[event_id]
            if idx < len(inserts):
                ip_val = inserts[idx].strip()
                if ip_val and ip_val not in ("-", "::1", "127.0.0.1", "0.0.0.0", ""):
                    return ip_val

        # 2. Fallback: Scan ALL inserts for a valid IP pattern
        for part in inserts:
            part = str(part).strip()
            match = re.search(ip_pattern, part)
            if match:
                ip_candidate = match.group(0)
                if ip_candidate not in ("127.0.0.1", "0.0.0.0"):
                    return ip_candidate

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
    except (IndexError, TypeError, ValueError, AttributeError, UnicodeError):
        pass

    # Fallback to raw inserts
    try:
        return json.dumps(inserts) if inserts else "N/A"
    except (IndexError, TypeError, ValueError, AttributeError, UnicodeError):
        pass

    return "N/A"
