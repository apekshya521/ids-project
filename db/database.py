import sqlite3
import logging
import json
from datetime import datetime, timedelta
import os

from config import DB_PATH

logger = logging.getLogger("ids.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                description TEXT,
                username TEXT,
                ip_address TEXT,
                computer TEXT,
                channel TEXT,
                source TEXT,
                time TEXT,
                risk_level TEXT,
                severity TEXT,
                risk_score REAL,
                reason TEXT,
                mitigation TEXT,
                raw_data TEXT,
                source_type TEXT,
                device_id TEXT,
                device_name TEXT,
                device_ip TEXT,
                UNIQUE(event_id, time, computer, device_id)
            )
        ''')
        
        # Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER,
                event_id INTEGER,
                channel TEXT,
                time TEXT,
                computer TEXT,
                username TEXT,
                ip_address TEXT,
                source TEXT,
                message TEXT,
                device_id TEXT,
                device_name TEXT,
                source_type TEXT,
                device_ip TEXT,
                severity TEXT,
                risk_score REAL,
                UNIQUE(record_id, channel, device_id)
            )
        ''')
        
        # Patch existing DB
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN severity TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN risk_score REAL')
        except sqlite3.OperationalError:
            pass
        
        conn.commit()
    logger.info("Database ready!")

def save_alert(alert_data):
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO alerts (
                    event_id, description, username, ip_address, computer, 
                    channel, source, time, risk_level, severity, risk_score, 
                    reason, mitigation, raw_data, source_type, device_id, 
                    device_name, device_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('event_id'),
                alert_data.get('description'),
                alert_data.get('username'),
                alert_data.get('ip_address'),
                alert_data.get('computer'),
                alert_data.get('channel'),
                alert_data.get('source'),
                alert_data.get('time'),
                alert_data.get('risk_level'),
                alert_data.get('severity'),
                alert_data.get('risk_score'),
                alert_data.get('reason'),
                alert_data.get('mitigation'),
                alert_data.get('raw_data'),
                alert_data.get('source_type'),
                alert_data.get('device_id'),
                alert_data.get('device_name'),
                alert_data.get('device_ip')
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Duplicate
            return False
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
            return False

def get_alerts(limit=5000, window_minutes=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        query = 'SELECT * FROM alerts'
        params = []
        
        if window_minutes:
            cutoff_time = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
            query += ' WHERE time >= ?'
            params.append(cutoff_time)
            
        query += ' ORDER BY time DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def save_log(log_data):
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO logs (
                    record_id, event_id, channel, time, computer, username, 
                    ip_address, source, message, device_id, device_name, 
                    source_type, device_ip, severity, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_data.get('record_id'),
                log_data.get('event_id'),
                log_data.get('channel'),
                log_data.get('time'),
                log_data.get('computer'),
                log_data.get('username'),
                log_data.get('ip_address'),
                log_data.get('source'),
                log_data.get('message'),
                log_data.get('device_id'),
                log_data.get('device_name'),
                log_data.get('source_type'),
                log_data.get('device_ip'),
                log_data.get('severity', 'INFO'),
                log_data.get('risk_score', 0)
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        except Exception as e:
            logger.error(f"Error saving log: {e}")

def get_logs(limit=100, device_id=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        query = 'SELECT * FROM logs'
        params = []
        
        if device_id and device_id != 'all':
            query += ' WHERE device_id = ?'
            params.append(device_id)
            
        query += ' ORDER BY time DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_logs_with_window(limit=100, device_id=None, window_minutes=60):
    with get_connection() as conn:
        cursor = conn.cursor()
        query = 'SELECT * FROM logs WHERE 1=1'
        params = []
        
        if device_id and device_id != 'all':
            query += ' AND device_id = ?'
            params.append(device_id)
            
        if window_minutes:
            cutoff_time = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
            query += ' AND time >= ?'
            params.append(cutoff_time)
            
        query += ' ORDER BY time DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_stats():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
        severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM logs')
        total_logs = cursor.fetchone()[0]
        
        import socket
        return {
            "total": total,
            "total_logs": total_logs,
            "host": socket.gethostname(),
            "by_severity": severity_counts,
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "info": severity_counts.get("INFO", 0)
        }

def clear_alerts():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()

def cleanup_old_data(minutes=60):
    with get_connection() as conn:
        cursor = conn.cursor()
        cutoff_time = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('DELETE FROM logs WHERE time < ?', (cutoff_time,))
        cursor.execute('DELETE FROM alerts WHERE time < ?', (cutoff_time,))
        conn.commit()

def get_last_record_ids():
    """
    Returns bookmarks for all devices.
    Format:
    {
        "local": {"Security": 123, ...},
        "remote_win_01": {"Security": 456, ...}
    }
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT device_id, channel, MAX(record_id) as rid FROM logs GROUP BY device_id, channel')
        
        bookmarks = {}
        for row in cursor.fetchall():
            d_id = row['device_id'] or "local"
            channel = row['channel']
            rid = row['rid']
            
            if d_id not in bookmarks:
                bookmarks[d_id] = {}
            bookmarks[d_id][channel] = rid
            
        return bookmarks
