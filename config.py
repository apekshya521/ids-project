import os
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("IDS_DB_PATH", str(BASE_DIR / "ids.db"))

# Application Configuration
POLL_INTERVAL = 10
CHANNELS = ["Security", "Application", "System"]

# Email Configuration for Critical Alerts (from .env file)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECIPIENTS = [email.strip() for email in os.getenv("EMAIL_RECIPIENTS", "").split(",") if email.strip()]
COOLDOWN_MINUTES = int(os.getenv("COOLDOWN_MINUTES", "5"))

def is_email_configured():
    """Check if email is properly configured"""
    return bool(EMAIL_SENDER and EMAIL_PASSWORD and EMAIL_RECIPIENTS)

# Logging Configuration
LOG_LEVEL = "INFO"

def setup_logging():
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

# Load Event Descriptions Once
EVENT_DESC_PATH = BASE_DIR / "normalization" / "event_description.json"
try:
    with open(EVENT_DESC_PATH, "r") as f:
        EVENT_DESCRIPTIONS = json.load(f)
except FileNotFoundError:
    EVENT_DESCRIPTIONS = {}
    print(f"WARNING: Could not find event descriptions at {EVENT_DESC_PATH}")

setup_logging()
logger = logging.getLogger("ids.config")
logger.info(f"Loaded config: POLL_INTERVAL={POLL_INTERVAL}s, DB_PATH={DB_PATH}")
