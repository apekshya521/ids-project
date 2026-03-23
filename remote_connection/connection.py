import winrm
import json
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Remote connection settings from environment
REMOTE_IP = os.getenv("REMOTE_DEVICE_01_IP", "")
USERNAME = os.getenv("REMOTE_DEVICE_01_USERNAME", "")
PASSWORD = os.getenv("REMOTE_DEVICE_01_PASSWORD", "")

# ── Timezone Settings ──────────────────────────────────
TIMEZONE_STR = os.getenv("REMOTE_DEVICE_01_TIMEZONE", "UTC")
if TIMEZONE_STR == "UTC+5:45":
    NEPAL_TZ = timezone(timedelta(hours=5, minutes=45))  # UTC+5:45
else:
    NEPAL_TZ = timezone.utc
INDIA_TZ = timezone(timedelta(hours=5, minutes=30))  # UTC+5:30

def convert_timestamp(raw_time):
    """Convert /Date(ms)/ to readable timestamp using device's local time"""
    try:
        if raw_time and "/Date(" in str(raw_time):
            ms = int(str(raw_time).replace("/Date(", "").replace(")/", ""))
            # Convert to datetime without timezone conversion (device local time)
            dt = datetime.fromtimestamp(ms / 1000)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return str(raw_time)
    except:
        return str(raw_time)

def connect_remote(ip, username, password):
    try:
        session = winrm.Session(
            target=f"http://{ip}:5985/wsman",
            auth=(username, password),
            transport="basic",
            read_timeout_sec=30,
            operation_timeout_sec=25
        )
        return session
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return None

def get_event_logs(session, log_name="System", max_events=20):
    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    $raw_logs = Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -Oldest
    $ps_logs = if ($raw_logs) {{ $raw_logs }} else {{ @() }}
    if ($ps_logs.Count -gt 0) {{
        $logs = $ps_logs | ForEach-Object {{
            [PSCustomObject]@{{
                TimeCreated      = $_.TimeCreated
                Id               = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                Channel          = $_.LogName
                UserId           = if ($_.UserId) {{ $_.UserId.Value }} else {{ "N/A" }}
                ProviderName     = $_.ProviderName
                Message          = $_.Message
                RecordNumber     = $_.RecordId
                ComputerName     = $_.MachineName
                StringInserts    = if ($_.Properties) {{ $_.Properties.Value }} else {{ @() }}
            }}
        }} | ConvertTo-Json -Depth 3
    }} else {{
        $logs = '[]'
    }}
    if ($logs) {{ $logs }} else {{ '[]' }}
    """
    try:
        result = session.run_ps(ps_script)
        if result.status_code == 0:
            output = result.std_out.decode("utf-8").strip()
            if not output or output == "[]":
                return []
            data = json.loads(output)
            return data if isinstance(data, list) else [data]
        else:
            print("PS Error:", result.std_err.decode("utf-8"))
            return []
    except Exception as e:
        print(f"❌ Fetch Error: {e}")
        return []

def display_logs(logs):
    if not logs:
        print("  ⚠️  No logs found.")
        return

    print(f"\n{'='*110}")
    print(f"{'TIMESTAMP':<22} {'ID':<8} {'LEVEL':<15} {'CHANNEL':<15} {'USER':<20} {'SOURCE':<25}")
    print(f"{'='*110}")

    for log in logs:
        timestamp = convert_timestamp(log.get("TimeCreated", "N/A"))
        # Emulate the extraction logic for display testing
        ev_id     = str(log.get("Id",               "N/A"))
        level     = str(log.get("LevelDisplayName", "N/A"))
        channel   = str(log.get("Channel",          "N/A"))
        source    = str(log.get("ProviderName",     "N/A"))
        
        # User/IP extraction logic display
        inserts = log.get("StringInserts", [])
        user = str(log.get("UserId", "N/A")) if log.get("UserId") else "N/A"
        if len(inserts) > 0:
            user = f"{user} (Has {len(inserts)} Inserts)"

        message   = (log.get("Message") or "No message")[:80]

        print(f"{timestamp:<22} {ev_id:<8} {level:<15} {channel:<15} {user:<20} {source:<25}")
        print(f"  └─ {message}")
        print()

if __name__ == "__main__":
    print(f" Connecting to {REMOTE_IP} as '{USERNAME}'...")
    session = connect_remote(REMOTE_IP, USERNAME, PASSWORD)

    if session:
        print("✅ Session created! Fetching logs...\n")
        for log_type in ["System", "Application", "Security"]:
            print(f"\n📋 Fetching {log_type} Logs...")
            logs = get_event_logs(session, log_name=log_type, max_events=20)
            display_logs(logs)