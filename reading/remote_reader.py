import winrm
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from config import REMOTE_DEVICES, CONNECTION_SETTINGS

logger = logging.getLogger("ids.remote_reader")

# Timezone mapping
TIMEZONE_MAP = {
    "UTC+5:45": timezone(timedelta(hours=5, minutes=45)),
    "UTC+5:30": timezone(timedelta(hours=5, minutes=30)),
    "UTC": timezone.utc
}

def convert_timestamp(raw_time):
    """Convert /Date(ms)/ to readable timestamp using device's local time"""
    try:
        if raw_time and "/Date(" in str(raw_time):
            ms = int(str(raw_time).replace("/Date(", "").replace(")/", ""))
            # Convert to datetime without timezone conversion (device local time)
            dt = datetime.fromtimestamp(ms / 1000)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return str(raw_time)
    except (ValueError, TypeError, AttributeError):
        return str(raw_time)

class RemoteLogReader:
    def __init__(self, device_config: Dict):
        self.device_id = device_config["device_id"]
        self.name = device_config["name"]
        self.ip = device_config["ip"]
        self.username = device_config["username"]
        self.password = device_config["password"]
        self.channels = device_config.get("channels", ["Security", "Application", "System"])
        self.max_events = device_config.get("max_events_per_poll", 20)
        self.timezone_str = device_config.get("timezone", "UTC")
        self.timezone = TIMEZONE_MAP.get(self.timezone_str, timezone.utc)
        self.session = None
        
    def connect(self) -> bool:
        """Establish WinRM connection to remote device"""
        try:
            self.session = winrm.Session(
                target=f"http://{self.ip}:5985/wsman",
                auth=(self.username, self.password),
                transport="basic",
                read_timeout_sec=CONNECTION_SETTINGS.get("timeout", 30),
                operation_timeout_sec=CONNECTION_SETTINGS.get("operation_timeout", 25)
            )
            logger.info(f"Connected to {self.name} ({self.ip})")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.name} ({self.ip}): {e}")
            return False
    
    def disconnect(self):
        """Close the connection"""
        self.session = None
        logger.info(f"Disconnected from {self.name} ({self.ip})")
    
    def get_event_logs(self, channel: str, max_events: Optional[int] = None, after_record: int = 0) -> List[Dict]:
        """Fetch event logs from remote device, filtered by record number"""
        if not self.session:
            if not self.connect():
                return []
        
        max_events = max_events or self.max_events
        
        # Filter by record number if specified
        # Filter by record number if specified
        if after_record > 0:
            xpath = f"*[System[EventRecordID > {after_record}]]"
            ps_script = f"""
            $ErrorActionPreference = 'SilentlyContinue'
            Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' -MaxEvents {max_events} -Oldest | ForEach-Object {{
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
                    Properties       = if ($_.Properties) {{ $_.Properties.Value }} else {{ @() }}
                }}
            }} | ConvertTo-Json -Depth 3 -Compress
            """
        else:
            ps_script = f"""
            $ErrorActionPreference = 'SilentlyContinue'
            Get-WinEvent -LogName '{channel}' -MaxEvents {max_events} | ForEach-Object {{
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
                    Properties       = if ($_.Properties) {{ $_.Properties.Value }} else {{ @() }}
                }}
            }} | ConvertTo-Json -Depth 3 -Compress
            """
        
        try:
            # logger.info(f"🌐 [{self.name}] Polling {channel} (after {after_record})")
            result = self.session.run_ps(ps_script)
            if result.status_code == 0:
                output = result.std_out.decode("utf-8").strip()
                if not output or output == "[]":
                    return []
                
                data = json.loads(output)
                logs = data if isinstance(data, list) else [data]
                
                from reading.log_reader import extract_username, extract_ip
                
                normalized_logs = []
                for log in logs:
                    event_id = int(log.get("Id") or 0)
                    inserts = log.get("Properties", [])
                    if not isinstance(inserts, list): inserts = [inserts]
                    inserts = [str(i) if i is not None else "" for i in inserts]

                    username = extract_username(event_id, inserts)
                    if username == "N/A" and log.get("UserId") and log.get("UserId") != "N/A":
                        username = log.get("UserId")
                    
                    ip_address = extract_ip(event_id, inserts)
                    if ip_address in ("Host-Based Event", "Non-Network Event"):
                        ip_address = self.ip

                    normalized_log = {
                        "record_id":   log.get("RecordNumber") or 0,
                        "event_id":    event_id,
                        "channel":     log.get("Channel") or channel,
                        "time":        convert_timestamp(log.get("TimeCreated")),
                        "computer":    log.get("ComputerName") or self.ip,
                        "username":    username,
                        "ip_address":  ip_address, 
                        "source":      log.get("ProviderName", "Unknown"),
                        "message":     log.get("Message", ""),
                        "device_id":   self.device_id,
                        "device_name": self.name,
                        "device_ip":   self.ip,
                        "timezone":    self.timezone_str
                    }
                    normalized_logs.append(normalized_log)
                
                return normalized_logs
            else:
                err = result.std_err.decode('utf-8')
                if "No events were found" not in err:
                    logger.error(f"❌ PowerShell error from {self.name}: {err[:200]}...")
                    if "Transport Error" in err or "connection" in err.lower():
                        self.session = None
                return []
        except Exception as e:
            logger.error(f"⚠️ Error fetching logs from {self.name}: {e}")
            self.session = None
            return []

class RemoteLogManager:
    def __init__(self):
        self.readers = {}
        self._initialize_readers()
    
    def _initialize_readers(self):
        """Initialize readers for all enabled remote devices"""
        for device in REMOTE_DEVICES:
            if device.get("enabled", True):
                reader = RemoteLogReader(device)
                self.readers[device["device_id"]] = reader
                logger.info(f"Initialized reader for {device['name']}")
    
    def get_reader(self, device_id: str) -> Optional[RemoteLogReader]:
        """Get reader for specific device"""
        return self.readers.get(device_id)
    
    def get_all_readers(self) -> Dict[str, RemoteLogReader]:
        """Get all active readers"""
        return self.readers
    
    def read_logs(self, device_id: str, channel: str, after_record: int = 0, max_events: Optional[int] = None) -> List[Dict]:
        """Read logs from specific device, optionally after a specific record number"""
        reader = self.get_reader(device_id)
        if not reader:
            logger.error(f"No reader found for device {device_id}")
            return []
        
        return reader.get_event_logs(channel, max_events, after_record)
    
    def read_all_logs(self, channel: str, max_events: Optional[int] = None) -> List[Dict]:
        """Read logs from all enabled devices"""
        all_logs = []
        for device_id, reader in self.readers.items():
            try:
                logs = reader.get_event_logs(channel, max_events)
                all_logs.extend(logs)
            except Exception as e:
                logger.error(f"Error reading from {device_id}: {e}")
        
        return all_logs
    
    def test_connection(self, device_id: str) -> bool:
        """Test connection to specific device"""
        reader = self.get_reader(device_id)
        if not reader:
            return False
        
        return reader.connect()
    
    def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all devices"""
        results = {}
        for device_id, reader in self.readers.items():
            results[device_id] = reader.connect()
        return results

# Global instance
remote_manager = RemoteLogManager()
