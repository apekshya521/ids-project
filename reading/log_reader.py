# reading/log_reader.py
import win32evtlog
import logging
import ipaddress

logger = logging.getLogger("ids.reader")


def read_logs(channel="Security", after_record=0):
    """
    Reads events from one channel.
    after_record=0 → reads latest batch
    after_record=N → only reads events newer than N
    """
    logs = []

    try:
        log    = win32evtlog.OpenEventLog("localhost", channel)
        flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                  win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        events = win32evtlog.ReadEventLog(log, flags, 0)

        for event in events:
            record_id = event.RecordNumber
            event_id  = event.EventID & 0xFFFF
            inserts   = list(event.StringInserts) if event.StringInserts else []

            # Stop when we hit already-processed events
            if record_id <= after_record:
                break

            username   = extract_username(event_id, inserts)
            ip_address = extract_ip(inserts)

            logs.append({
                "event_id":   event_id,
                "channel":    channel,
                "time":       str(event.TimeGenerated),
                "computer":   event.ComputerName,
                "username":   username,
                "ip_address": ip_address,
                "record_id":  record_id,     # ← needed for tracking
            })

        win32evtlog.CloseEventLog(log)

    except Exception as e:
        logger.error(f"[READER ERROR] {channel}: {e}", exc_info=True)

    return logs


def extract_username(event_id, inserts):
    try:
        # Known positions per EventID
        positions = {
            4624: 5,   # successful logon
            4625: 5,   # failed logon
            4672: 1,   # special privileges
            4720: 0,   # account created
            4726: 0,   # account deleted
            4740: 0,   # account locked
            4728: 0,   # added to group
            4732: 0,   # added to local group
            1102: 1,   # log cleared
        }

        # ── Only extract username for KNOWN EventIDs ──
        if event_id not in positions:
            return "unknown"     # ← FIX: don't guess for unknown events

        index = positions[event_id]
        if index < len(inserts):
            username = inserts[index].strip()

            # ── Filter out non-username values ────────
            SKIP_VALUES = {
                "-", "", "RulesEngine", "SYSTEM",
                "LOCAL SERVICE", "NETWORK SERVICE",
                "Window Manager", "Font Driver Host"
            }
            if username and username not in SKIP_VALUES:
                return username

    except:
        pass
    return "unknown"


def extract_ip(inserts):
    try:
        if not inserts:
            return "local"
        for part in inserts:
            part = part.strip()
            # Basic pre-filter to avoid throwing exceptions on every string
            if part and part[0].isdigit() and part.count(".") == 3:
                try:
                    ip = ipaddress.ip_address(part)
                    # We can exclude loopback/multicast if desired, but let's just return valid IPs
                    return str(ip)
                except ValueError:
                    pass
    except Exception as e:
        logger.debug(f"Error extracting IP: {e}")
    return "local"
