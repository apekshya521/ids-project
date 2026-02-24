# Windows-Log-IDS

A real-time **Intrusion Detection System (IDS)** for Windows that monitors Event Logs and detects suspicious security events using intelligent rule-based detection.

## 🎯 Features

- ✅ **Real-time Monitoring** - Continuously monitors Windows Security, Application, and System event logs
- ✅ **13 Security Rules** - Detects brute force, privilege escalation, malware, and more
- ✅ **Web Dashboard** - Beautiful UI for viewing detected alerts
- ✅ **REST API** - Programmatic access to alerts and statistics
- ✅ **WebSocket Support** - Live real-time alert notifications
- ✅ **SQLite Database** - Persistent alert storage
- ✅ **Thread-Safe** - Designed for concurrent event processing
- ✅ **Configurable** - Easy to customize rules and thresholds

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- Python 3.8+
- Administrator Rights (for reading Event Logs)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/apekshya521/Windows-Log-IDS.git
cd Windows-Log-IDS
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Initialize database**
```bash
python test_db.py
```

4. **Start the IDS server**
```bash
uvicorn main:app --reload --port 8000
```

5. **Open dashboard**
```
http://127.0.0.1:8000/
```

## 📊 Detection Rules

The IDS implements 13 security rules:

| Rule | Event | Trigger | Risk |
|------|-------|---------|------|
| Brute Force | 4625 | 3+ failed logins in 1 hour | HIGH |
| Off-Hours Login | 4624 | Login between 12am-5am | HIGH |
| Multiple IPs | 4624 | 3+ different IPs per user | HIGH |
| Explicit Credential Use | 4648 | 3+ uses in 1 hour | HIGH |
| Audit Log Cleared | 1102 | Security log cleared | HIGH |
| Malware Detected | 1116/1117 | Windows Defender detection | HIGH |
| Firewall Stopped | 5025 | Firewall service stopped | HIGH |
| Admin Escalation | 4728/4732 | User added to admin group | HIGH |
| System Shutdown | 6008 | Unexpected shutdown | MEDIUM |
| High-Risk Events | Various | Classified as high-risk | HIGH |
| Medium-Risk Events | Various | Classified as medium-risk | MEDIUM |
| Low-Risk Events | Various | Classified as low-risk | LOW |
| Normal Events | Other | No rule match | NORMAL |

## 🔌 API Endpoints

### Health Check
```bash
GET /ping
```

### Get Alerts
```bash
GET /api/alerts?limit=50
```

### Get Statistics
```bash
GET /api/stats
```

### Clear Alerts
```bash
DELETE /api/alerts
```

### Live Alerts (WebSocket)
```
WS /ws
```

## 📁 Project Structure

```
Windows-Log-IDS/
├── main.py                 # FastAPI application & polling loop
├── config.py               # Configuration settings
├── requirements.txt        # Dependencies
├── USER_MANUAL.md         # Comprehensive user guide
├── README.md              # This file
│
├── alerts/
│   ├── __init__.py
│   └── alert_manager.py   # Real-time alert notifications
│
├── db/
│   ├── __init__.py
│   └── database.py        # SQLite database operations
│
├── detection/
│   ├── __init__.py
│   └── detector.py        # Event detection logic
│
├── reading/
│   ├── __init__.py
│   └── log_reader.py      # Windows Event Log reader
│
├── normalization/
│   ├── __init__.py
│   ├── normalizer.py      # Event normalization
│   └── event_description.json  # Event ID mappings
│
├── rules/
│   ├── __init__.py
│   └── rule_engine.py     # Security rule definitions
│
├── scoring/
│   ├── __init__.py
│   └── scorer.py          # Risk scoring logic
│
├── templates/
│   └── index.html         # Dashboard HTML
│
├── static/
│   ├── css/
│   │   └── style.css      # Dashboard styles
│   └── js/
│       └── main.js        # Dashboard scripts
│
└── tests/
    ├── test_db.py         # Database tests
    ├── test_reader.py     # Log reader tests
    └── test_scorer.py     # Scoring tests
```

## ⚙️ Configuration

### Environment Variables

```bash
# Database path
IDS_DB_PATH=ids.db

# Poll interval (seconds)
IDS_POLL_INTERVAL=10

# Log level
IDS_LOG_LEVEL=INFO
```

### Modify Rules

Edit `rules/rule_engine.py` to adjust thresholds:

```python
BRUTE_FORCE_LIMIT = 3           # Failed logins threshold
EXPLICIT_LOGON_LIMIT = 3        # Explicit credential use threshold
TRACKING_WINDOW = 3600          # 1 hour tracking window
```

## 🧪 Testing

### Test Database
```bash
python test_db.py
```

### Test Log Reading
```bash
python test_reader.py
```

### Test Scoring
```bash
python test_scorer.py
```

## 📚 Documentation

For detailed information, see [USER_MANUAL.md](USER_MANUAL.md) which includes:
- Complete installation guide
- Web dashboard walkthrough
- API reference with examples
- Detailed rule explanations
- Configuration options
- Troubleshooting guide

## 🔒 Security Notes

⚠️ **Important:**
- Requires administrator privileges to read Windows Event Logs
- Store `ids.db` in a secure location
- Back up database regularly
- Enable authentication before exposing to network
- Customize CORS settings for production

## 📊 Pipeline Architecture

```
Windows Event Logs
       ↓
Read Logs (log_reader.py)
       ↓
Normalize (normalizer.py)
       ↓
Detect (detector.py + rule_engine.py)
       ↓
Score (scorer.py)
       ↓
Store Alert (database.py)
       ↓
Display (dashboard + WebSocket)
```

## 🛠️ Development

### Run in Development Mode
```bash
uvicorn main:app --reload --port 8000
```

### Debug Logging
```bash
IDS_LOG_LEVEL=DEBUG uvicorn main:app --reload
```

### Database Reset
```bash
rm ids.db
python test_db.py
```

## 📝 Requirements

```
pywin32==306
pandas==2.2.0
numpy==1.26.4
psutil==5.9.8
watchdog==4.0.0
xmltodict==0.13.0
fastapi==0.109.0
uvicorn==0.27.0.post1
python-multipart==0.0.9
websockets==12.0
jinja2==3.1.3
pytest==8.0.0
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new rules
- Improve documentation
- Optimize performance

## 📄 License

This project is available under the MIT License.

## 👤 Author

**Jarvis** - Windows Log IDS Project

## 📞 Support

For issues or questions:
1. Check the [USER_MANUAL.md](USER_MANUAL.md) troubleshooting section
2. Review rule definitions in `rules/rule_engine.py`
3. Check logs with `IDS_LOG_LEVEL=DEBUG`

## 🔗 Related Resources

- [Windows Event Log IDs](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Windows Security Monitoring](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging)

---

**Last Updated:** February 2026  
**Status:** Active Development ✅

