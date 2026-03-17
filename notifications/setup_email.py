#!/usr/bin/env python3
"""
Email Configuration Setup Script (Refactored)
Run this script to configure email notifications within the central config.py
"""

import os
import sys
import re
from pathlib import Path

# Fix path to allow importing from parent directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

try:
    from config import is_email_configured, EMAIL_SENDER, EMAIL_RECIPIENTS, BASE_DIR
except ImportError:
    print("Error: Could not import configuration. Please run from the project structure.")
    sys.exit(1)

CONFIG_FILE = BASE_DIR / "config.py"

def setup_email():
    """Interactive email configuration setup"""
    print("=== Windows Log IDS - Email Notification Setup ===\n")
    
    # Check if already configured
    if is_email_configured():
        print("Email is already configured!")
        print(f"Current Sender: {EMAIL_SENDER}")
        choice = input("Do you want to reconfigure? (y/n): ").lower()
        if choice != 'y':
            return
    
    print("Please provide your email configuration:\n")
    
    # Get sender email
    while True:
        sender = input("Gmail address for sending alerts: ").strip()
        if '@' in sender and '.' in sender:
            break
        print("Please enter a valid email address")
    
    # Get app password
    print("\nNote: Use an App Password, not your regular Gmail password")
    print("Generate one at: https://myaccount.google.com/apppasswords\n")
    password = input("Gmail App Password: ").strip()
    
    # Get recipients
    print("\nEnter recipient email addresses (comma-separated):")
    recipients_input = input("Recipients: ").strip()
    recipients = [email.strip() for email in recipients_input.split(',') if email.strip()]
    
    if not recipients:
        print("Error: At least one recipient is required")
        return
    
    # Surgically update config.py
    try:
        with open(CONFIG_FILE, 'r') as f:
            content = f.read()
            
        # Update EMAIL_SENDER
        content = re.sub(r'EMAIL_SENDER\s*=\s*".*?"', f'EMAIL_SENDER = "{sender}"', content)
        # Update EMAIL_PASSWORD
        content = re.sub(r'EMAIL_PASSWORD\s*=\s*".*?"', f'EMAIL_PASSWORD = "{password}"', content)
        # Update EMAIL_RECIPIENTS
        recipients_list_str = "[" + ", ".join([f'"{r}"' for r in recipients]) + "]"
        content = re.sub(r'EMAIL_RECIPIENTS\s*=\s*\[.*?\]', f'EMAIL_RECIPIENTS = {recipients_list_str}', content, flags=re.DOTALL)
        
        with open(CONFIG_FILE, 'w') as f:
            f.write(content)
        
        print(f"\n✅ Email configuration updated in config.py!")
        print(f"Sender: {sender}")
        print(f"Recipients: {', '.join(recipients)}")
        
        # Test email
        choice = input("\nWould you like to send a test email? (y/n): ").lower()
        if choice == 'y':
            test_email()
            
    except Exception as e:
        print(f"❌ Error updating configuration: {e}")

def test_email():
    """Send a test email"""
    try:
        from notifications.email_notifier import test_email_configuration
        success, message = test_email_configuration()
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

def show_status():
    """Show current email configuration status"""
    print("=== Email Configuration Status ===\n")
    
    if is_email_configured():
        # Reload settings
        import importlib
        import config
        importlib.reload(config)
        
        print("✅ Email is configured")
        print(f"Sender: {config.EMAIL_SENDER}")
        print(f"Recipients: {', '.join(config.EMAIL_RECIPIENTS)}")
    else:
        print("❌ Email is not configured")
        print("Run 'python notifications/setup_email.py' to configure")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "status":
            show_status()
        elif sys.argv[1] == "test":
            test_email()
        else:
            print("Usage: python setup_email.py [status|test]")
    else:
        setup_email()
