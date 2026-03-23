#!/usr/bin/env python3
"""
Inject test alerts into the running IDS system
Run this while main.py is running to see alerts appear in dashboard
"""

import sys
import os
import asyncio
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import process_log

def make_test_log(event_id, username="attacker", ip="192.168.1.100", **kwargs):
    """Create a test log entry"""
    return {
        "event_id": event_id,
        "username": username,
        "ip_address": ip,
        "channel": "Security",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "computer": "TEST-PC",
        "source": "Microsoft-Windows-Security-Auditing",
        "message": "Test event for demonstration",
        "record_id": 99999,
        **kwargs
    }

async def inject_test_alerts():
    """Inject test events that will trigger your rules"""
    
    print("🚨 Injecting test alerts into running IDS...")
    
    # Test R001: Audit log cleared
    result = await process_log(make_test_log(1102), "local")
    print(f"✅ Injected: Audit log cleared - Score: {result.get('risk_score', 0) if result else 'N/A'}")
    
    # Test R002: Brute force (need 8 failures)
    print("🔄 Injecting 8 failed logins for brute force test...")
    for i in range(8):
        await process_log(make_test_log(4625, username="victim"), "local")
    print("✅ Injected: Brute force attack (R002)")
    
    # Test R003: Malware detected
    result = await process_log(make_test_log(1116), "local")
    print(f"✅ Injected: Malware detected - Score: {result.get('risk_score', 0) if result else 'N/A'}")
    
    # Test R004: Firewall disabled
    result = await process_log(make_test_log(5025), "local")
    print(f"✅ Injected: Firewall disabled - Score: {result.get('risk_score', 0) if result else 'N/A'}")
    
    # Test R006: New user created
    result = await process_log(make_test_log(4720, target_username="hacker"), "local")
    print(f"✅ Injected: New user created - Score: {result.get('risk_score', 0) if result else 'N/A'}")
    
    # Test R007: Added to admin group
    result = await process_log(make_test_log(4728), "local")
    print(f"✅ Injected: Added to privileged group - Score: {result.get('risk_score', 0) if result else 'N/A'}")
    
    print("\n🎯 Check your dashboard at http://localhost:8000")
    print("   You should now see multiple alerts!")

if __name__ == "__main__":
    asyncio.run(inject_test_alerts())
