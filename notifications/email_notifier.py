import smtplib
import threading
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("ids.email")

# Import configuration from central config.py
try:
    from config import SMTP_SERVER, SMTP_PORT, EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENTS, COOLDOWN_MINUTES
except ImportError:
    logger.warning("Main config not found, using defaults")
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_SENDER = ""
    EMAIL_PASSWORD = ""
    EMAIL_RECIPIENTS = []
    COOLDOWN_MINUTES = 5

# Notification Controls
email_lock = threading.Lock()
last_notifications = defaultdict(datetime)

def send_critical_alert(alert_data):
    """
    Send email notification for critical alerts only
    """
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECIPIENTS:
        logger.warning("Email not configured - skipping notification")
        return False

    # Check cooldown to prevent spam
    event_key = f"{alert_data.get('event_id', 'unknown')}-{alert_data.get('username', 'unknown')}"
    now = datetime.now()
    
    with email_lock:
        if event_key in last_notifications:
            time_diff = now - last_notifications[event_key]
            if time_diff < timedelta(minutes=COOLDOWN_MINUTES):
                logger.info(f"Email cooldown active for {event_key}")
                return False
        
        last_notifications[event_key] = now

    # Send email in background thread
    threading.Thread(
        target=_send_email_thread,
        args=(alert_data,),
        daemon=True
    ).start()
    
    return True

def _send_email_thread(alert_data):
    """
    Background thread to send email
    """
    try:
        msg = MIMEMultipart()
        msg['From'] = formataddr(("Windows IDS System", EMAIL_SENDER))
        msg['To'] = ', '.join(EMAIL_RECIPIENTS)
        msg['Subject'] = f"🚨 CRITICAL ALERT: Event {alert_data.get('event_id', 'Unknown')} - {alert_data.get('computer', 'Unknown')}"

        # Email body
        body = _create_email_body(alert_data)
        msg.attach(MIMEText(body, 'html'))

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Critical alert email sent for event {alert_data.get('event_id')}")

    except Exception as e:
        logger.error(f"Failed to send email notification: {e}")

def _create_email_body(alert_data):
    """
    Create HTML email body
    """
    event_id = alert_data.get('event_id', 'Unknown')
    description = alert_data.get('description', 'Unknown Event')
    computer = alert_data.get('computer', 'Unknown')
    username = alert_data.get('username', 'Unknown')
    ip_address = alert_data.get('ip_address', 'Unknown')
    channel = alert_data.get('channel', 'Unknown')
    time = alert_data.get('time', 'Unknown')
    reason = alert_data.get('reason', 'Critical security event detected')
    risk_score = alert_data.get('risk_score', 0)

    return f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ background-color: #dc3545; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .alert-info {{ background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; padding: 15px; margin: 15px 0; }}
            .details {{ margin: 15px 0; }}
            .details table {{ width: 100%; border-collapse: collapse; }}
            .details th {{ background-color: #f8f9fa; padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }}
            .details td {{ padding: 10px; border-bottom: 1px solid #dee2e6; }}
            .footer {{ background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }}
            .risk-score {{ font-size: 24px; font-weight: bold; color: #dc3545; text-align: center; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 CRITICAL SECURITY ALERT</h1>
                <p>Immediate attention required</p>
            </div>
            
            <div class="content">
                <div class="alert-info">
                    <h3>Event {event_id}: {description}</h3>
                    <p><strong>Reason:</strong> {reason}</p>
                </div>
                
                <div class="risk-score">
                    Risk Score: {risk_score}/100
                </div>
                
                <div class="details">
                    <h4>Event Details:</h4>
                    <table>
                        <tr>
                            <th>Computer</th>
                            <td>{computer}</td>
                        </tr>
                        <tr>
                            <th>Username</th>
                            <td>{username}</td>
                        </tr>
                        <tr>
                            <th>IP Address</th>
                            <td>{ip_address}</td>
                        </tr>
                        <tr>
                            <th>Channel</th>
                            <td>{channel}</td>
                        </tr>
                        <tr>
                            <th>Time</th>
                            <td>{time}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 15px 0;">
                    <h4>⚠️ Recommended Actions:</h4>
                    <ul>
                        <li>Immediately investigate the source computer</li>
                        <li>Check user account for suspicious activity</li>
                        <li>Review recent logon attempts</li>
                        <li>Consider isolating the affected system</li>
                        <li>Reset user password if compromise suspected</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>This alert was generated by Windows Log IDS at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>If this is a false positive, please update your IDS rules accordingly.</p>
            </div>
        </div>
    </body>
    </html>
    """

def test_email_configuration():
    """
    Test email configuration by sending a test email
    """
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECIPIENTS:
        return False, "Email not configured"
    
    test_alert = {
        'event_id': 9999,
        'description': 'Test Alert',
        'computer': 'TEST-COMPUTER',
        'username': 'test-user',
        'ip_address': '127.0.0.1',
        'channel': 'Test',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'reason': 'This is a test email notification',
        'risk_score': 95
    }
    
    try:
        _send_email_thread(test_alert)
        return True, "Test email sent successfully"
    except Exception as e:
        return False, f"Failed to send test email: {e}"
