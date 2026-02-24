# IDS Project - User Manual

## Table of Contents
1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Web Dashboard](#web-dashboard)
6. [API Reference](#api-reference)
7. [Detection Rules](#detection-rules)
8. [Configuration](#configuration)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The **IDS (Intrusion Detection System)** project is a real-time Windows Event Log monitoring system that detects suspicious security events and generates alerts. It monitors three Windows Event channels:
- **Security** - User login, privilege changes, audit events
- **Application** - Application-level errors and events
- **System** - System-level events, firewall, defender alerts

### Key Features
✅ Real-time event monitoring  
✅ 13 security rules for threat detection  
✅ Web-based dashboard with live alerts  
✅ RESTful API for programmatic access  
✅ WebSocket support for real-time notifications  
✅ SQLite database for alert storage  
✅ Thread-safe rule engine  

---

## System Requirements

### Hardware
- **CPU**: 2+ cores recommended
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 500MB for application, varies for database

### Software
- **OS**: Windows 10/11 (requires Event Viewer access)
- **Python**: 3.8 or higher
- **Admin Rights**: Required for reading Windows Event Logs

---

## Installation

### Step 1: Clone/Extract Project
```powershell
cd "c:\Users\jarvis\Desktop\ids project feb"
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Initialize Database
```powershell
python test_db.py
```

This creates `ids.db` in the project root directory.

### Step 4: Verify Setup
```powershell
python test_reader.py
```

You should see a list of recent Windows events.

---

## Quick Start

### Start the IDS Server
```powershell
uvicorn main:app --reload --port 8000
```

**Output:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete
```

### Access the Dashboard
Open your browser and go to:
```
http://127.0.0.1:8000/
```

You should see:
- List of detected alerts
- Real-time statistics
- Event details and risk levels
- Clear alerts button

---

## Web Dashboard

### Dashboard Features

#### 1. **Alerts Section**
- **Time**: When the event was detected
- **Event ID**: Windows Event identifier
- **User**: Username associated with the event
- **IP Address**: Source IP address
- **Risk Level**: High / Medium / Low
- **Reason**: Detection reason

#### 2. **Statistics**
- **Total Alerts**: Count of all detected suspicious events
- **High Risk**: Number of high-severity alerts
- **Today**: Events detected in current day
- **Last Alert**: Timestamp of most recent alert

#### 3. **Controls**
- **Real-time Updates**: Live alerts appear via WebSocket
- **Clear Alerts**: Removes all alerts from database
- **Refresh**: Manual page refresh

---

## API Reference

### Base URL
```
http://127.0.0.1:8000
```

### Endpoints

#### 1. **GET /ping**
Health check endpoint

**Request:**
```bash
curl http://127.0.0.1:8000/ping
```

**Response:**
```json
{
  "status": "IDS is running ✅",
  "alerts_stored": 42
}
```

---

#### 2. **GET /api/alerts**
Get all detected alerts

**Request:**
```bash
curl "http://127.0.0.1:8000/api/alerts?limit=50"
```

**Parameters:**
- `limit` (optional): Number of alerts to return (1-500, default: 100)

**Response:**
```json
[
  {
    "event_id": 4625,
    "description": "An account failed to log on",
    "username": "hacker",
    "ip_address": "192.168.1.105",
    "computer": "DESKTOP-ABC123",
    "channel": "Security",
    "time": "2026-02-24 02:30:00",
    "risk_level": "High",
    "reason": "Brute Force! 3 failed logins for: hacker",
    "severity": "CRITICAL"
  }
]
```

---

#### 3. **GET /api/stats**
Get statistics

**Request:**
```bash
curl http://127.0.0.1:8000/api/stats
```

**Response:**
```json
{
  "total": 42,
  "high_risk": 12,
  "medium_risk": 20,
  "low_risk": 10
}
```

---

#### 4. **DELETE /api/alerts**
Clear all alerts from database

**Request:**
```bash
curl -X DELETE http://127.0.0.1:8000/api/alerts
```

**Response:**
```json
{
  "status": "cleared"
}
```

---

#### 5. **WebSocket /ws**
Real-time alert stream

**JavaScript Example:**
```javascript
const ws = new WebSocket("ws://127.0.0.1:8000/ws");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === "NEW_ALERT") {
    console.log("New Alert:", data.alert);
  }
};

ws.onerror = (error) => {
  console.error("WebSocket error:", error);
};
```

---

## Detection Rules

### Rule 1: Brute Force Attack (Event 4625)
- **Trigger**: 3+ failed login attempts within 1 hour
- **Risk Level**: HIGH
- **Action**: Alert stored immediately
- **Reason**: Possible password guessing attack

**Example Alert:**
```
Brute Force! 3 failed logins for: attacker
```

---

### Rule 2: Off-Hours Login (Event 4624)
- **Trigger**: Successful login between 12:00 AM - 5:00 AM
- **Risk Level**: HIGH
- **Detection**: Time-based check
- **Reason**: Suspicious login outside business hours

**Example Alert:**
```
Off Hours Login Detected for: admin
Time: 2026-02-24 02:30:00
```

---

### Rule 3: Multiple IPs (Event 4624)
- **Trigger**: Same user logs in from 3+ different IPs within 1 hour
- **Risk Level**: HIGH
- **Reason**: Account may be compromised or shared illegally

**Example Alert:**
```
Multiple IPs Detected for: john.doe
IPs: {'192.168.1.10', '192.168.1.20', '192.168.1.30'}
```

---

### Rule 4: Explicit Credential Use (Event 4648)
- **Trigger**: 3+ explicit credential use attempts within 1 hour
- **Risk Level**: HIGH
- **Reason**: Possible lateral movement or privilege escalation

**Example Alert:**
```
Repeated Explicit Credential Use by: svcaccount
```

---

### Rule 5: Audit Log Cleared (Event 1102)
- **Trigger**: Security audit log cleared
- **Risk Level**: HIGH (CRITICAL)
- **Reason**: Attacker covering tracks

**Example Alert:**
```
Audit Log Cleared by: attacker
```

---

### Rule 6: Malware Detected (Events 1116, 1117)
- **Trigger**: Windows Defender malware detection
- **Risk Level**: HIGH
- **Reason**: Malware detected on system

**Example Alert:**
```
Malware Detected by Windows Defender!
```

---

### Rule 7: Firewall Stopped (Event 5025)
- **Trigger**: Windows Firewall service stopped
- **Risk Level**: HIGH
- **Reason**: Security control compromised

**Example Alert:**
```
Windows Firewall Stopped!
```

---

### Rule 8: User Added to Admin Group (Events 4728, 4732, 4756)
- **Trigger**: User added to privileged group
- **Risk Level**: HIGH
- **Reason**: Unauthorized privilege escalation

**Example Alert:**
```
User Added to Privileged Group by: badactor
```

---

### Rule 9: Unexpected Shutdown (Event 6008)
- **Trigger**: System shutdown without notification
- **Risk Level**: MEDIUM
- **Reason**: Possible DoS or system compromise

**Example Alert:**
```
Unexpected System Shutdown Detected
```

---

### Rule 10-13: Risk-Based Classification
- **Events 1102, 4625, 4720, etc.**: HIGH risk
- **Events 4624, 4672, 4688, etc.**: MEDIUM risk
- **Events 4634, 4647, 4768, etc.**: LOW risk

---

## Configuration

### Environment Variables

Edit configuration or set environment variables:

```powershell
# Database path (default: ids.db in project root)
$env:IDS_DB_PATH = "C:\custom\path\ids.db"

# Poll interval in seconds (default: 10)
$env:IDS_POLL_INTERVAL = "15"

# Logging level (default: INFO)
$env:IDS_LOG_LEVEL = "DEBUG"
```

### Modify in config.py

Edit `c:\Users\jarvis\Desktop\ids project feb\config.py`:

```python
# Poll every 10 seconds
POLL_INTERVAL = 10

# Monitor these channels
CHANNELS = ["Security", "Application", "System"]

# Database location
DB_PATH = "ids.db"

# Log level
LOG_LEVEL = "INFO"
```

### Modify Rule Thresholds

Edit `c:\Users\jarvis\Desktop\ids project feb\rules\rule_engine.py`:

```python
# Brute force triggers after 3 failed logins
BRUTE_FORCE_LIMIT = 3

# Explicit cred use triggers after 3 attempts
EXPLICIT_LOGON_LIMIT = 3

# Tracking window (1 hour = 3600 seconds)
TRACKING_WINDOW = 3600
```

---

## Testing

### Test Database
```powershell
python test_db.py
```
Initializes and tests database connection.

---

### Test Log Reading
```powershell
python test_reader.py
```
Reads recent Windows events and shows pipeline processing.

---

### Test Scoring
```powershell
python test_scorer.py
```
Tests risk scoring for various event types.

---

### Full Integration Test
```powershell
# Terminal 1: Start server
uvicorn main:app --reload --port 8000

# Terminal 2: Generate test events
# Run PowerShell script to create security events, or wait for real events
```

---

## Troubleshooting

### Issue: "Connection Refused" on Port 8000

**Solution 1: Port Already in Use**
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Use different port
uvicorn main:app --reload --port 8080
```

**Solution 2: Firewall Blocking**
```powershell
# Add firewall rule
netsh advfirewall firewall add rule name="IDS" dir=in action=allow protocol=tcp localport=8000
```

---

### Issue: "No Alerts Showing"

**Check 1: Server Running**
```powershell
curl http://127.0.0.1:8000/ping
```

**Check 2: Event Log Access**
- Run PowerShell as Administrator
- Restart server after

**Check 3: Database**
```powershell
# Check if database exists
Test-Path "ids.db"

# Reinitialize
python test_db.py
```

---

### Issue: High CPU Usage

**Solution:**
Increase `POLL_INTERVAL` in config.py:
```python
POLL_INTERVAL = 30  # Increased from 10
```

---

### Issue: Database Error

**Solution 1: Reset Database**
```powershell
# Stop server
Remove-Item ids.db
python test_db.py
# Restart server
```

**Solution 2: Check Permissions**
```powershell
# Ensure write permissions to project folder
cmd /c "icacls . /grant %username%:F"
```

---

### Issue: Rule Not Triggering

**Debug Steps:**

1. Check logs:
```powershell
$env:IDS_LOG_LEVEL = "DEBUG"
# Restart server
```

2. Verify event exists:
```powershell
python test_reader.py
```

3. Test rule directly:
```python
from rules.rule_engine import apply_rules

test_event = {
    "event_id": 4625,
    "username": "test",
    "channel": "Security",
    "time": "2026-02-24 10:00:00",
    "computer": "TEST-PC",
    "ip_address": "192.168.1.1"
}

result = apply_rules(test_event)
print(result)
```

---

### Issue: WebSocket Not Connecting

**Solution:**
```javascript
// Use correct protocol
const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
const ws = new WebSocket(protocol + "//" + window.location.host + "/ws");
```

---

## Performance Tips

### 1. **Optimize Poll Interval**
- Faster detection: POLL_INTERVAL = 5
- Lower resource use: POLL_INTERVAL = 30

### 2. **Database Maintenance**
- Regularly clear old alerts:
```bash
curl -X DELETE http://127.0.0.1:8000/api/alerts
```

### 3. **Enable Event Log Rotation**
- Windows Event Viewer → Properties → Set max log size

### 4. **Use Production Server**
- Development: `uvicorn main:app --reload`
- Production: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app`

---

## Support & Additional Resources

### Log Files
- Check Python logs: `config.py` controls log output
- Windows Event Viewer: Check source events

### Documentation Files
- `rules/rule_engine.py` - Rule definitions
- `db/database.py` - Database schema
- `normalization/event_description.json` - Event mappings

### Common Commands

**Restart Server (Clean)**
```powershell
Stop-Process -Name uvicorn -Force
python test_db.py
uvicorn main:app --reload --port 8000
```

**View Current Alerts**
```powershell
curl http://127.0.0.1:8000/api/alerts | ConvertFrom-Json | Format-Table
```

**Monitor in Real-Time**
```javascript
// In browser console
const ws = new WebSocket("ws://" + window.location.host + "/ws");
ws.onmessage = e => console.log(JSON.parse(e.data));
```

---

## Safety & Security Notes

⚠️ **Important Security Considerations:**

1. **Admin Rights Required**: Server must run with admin privileges to read Event Logs
2. **Default Port**: 8000 is localhost only by default (secure)
3. **CORS Enabled**: Default config allows all origins for testing - disable in production
4. **No Authentication**: Add authentication before exposing to network
5. **Database**: Store `ids.db` in secure location, backup regularly

---

## Version Information
- **Project**: Intrusion Detection System (IDS)
- **Date**: February 2026
- **Python**: 3.8+
- **Framework**: FastAPI + Uvicorn

---

**For questions or issues, check the troubleshooting section above.**

---

**End of User Manual**
