import sqlite3
import threading
import logging
from contextlib import contextmanager
from config import DB_PATH

logger = logging.getLogger("ids.db")

# ── Connection Pool ────────────────────────
_connection_pool_lock = threading.Lock()
_connection_pool = []
MAX_POOL_SIZE = 3


@contextmanager
def get_connection():
    """
    Context manager for database connections.
    Returns a connection from pool or creates new one.
    Automatically closes/returns to pool on exit.
    """
    conn = None
    
    with _connection_pool_lock:
        if _connection_pool:
            conn = _connection_pool.pop()
    
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    
    try:
        yield conn
    finally:
        # Return connection to pool if pool not full
        with _connection_pool_lock:
            if len(_connection_pool) < MAX_POOL_SIZE:
                _connection_pool.append(conn)
            else:
                conn.close()


def _column_exists(cursor, table, column):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns


def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()

        # ── Raw logs table ─────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id   INTEGER,
                channel    TEXT,
                time       TEXT,
                computer   TEXT,
                username   TEXT,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Alerts table ───────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    INTEGER,
                description TEXT,
                channel     TEXT,
                time        TEXT,
                computer    TEXT,
                username    TEXT,
                ip_address  TEXT,
                reason      TEXT,
                risk_level  TEXT,
                risk_score  INTEGER,
                severity    TEXT,
                mitigation  TEXT,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Schema migrations ──────────────────
        # Add missing columns if they don't exist
        if not _column_exists(cursor, "alerts", "description"):
            cursor.execute("ALTER TABLE alerts ADD COLUMN description TEXT")
            logger.info("Added 'description' column to alerts")
        
        if not _column_exists(cursor, "alerts", "risk_level"):
            cursor.execute("ALTER TABLE alerts ADD COLUMN risk_level TEXT")
            logger.info("Added 'risk_level' column to alerts")
        
        if not _column_exists(cursor, "alerts", "risk_score"):
            cursor.execute("ALTER TABLE alerts ADD COLUMN risk_score INTEGER")
            logger.info("Added 'risk_score' column to alerts")
        
        if not _column_exists(cursor, "alerts", "mitigation"):
            cursor.execute("ALTER TABLE alerts ADD COLUMN mitigation TEXT")
            logger.info("Added 'mitigation' column to alerts")
        
        if not _column_exists(cursor, "alerts", "created_at"):
            cursor.execute("ALTER TABLE alerts ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
            logger.info("Added 'created_at' column to alerts")

        conn.commit()
    logger.info("Database ready!")


def save_alert(alert):
    with get_connection() as conn:
        # ── Deduplication Check ──────────────────
        duplicate = conn.execute("""
            SELECT id FROM alerts 
            WHERE event_id = ? AND username = ? AND channel = ? 
            AND created_at >= datetime('now', '-60 seconds')
            LIMIT 1
        """, (alert.get("event_id"), alert.get("username"), alert.get("channel"))).fetchone()
        
        if duplicate:
            logger.debug(f"Skipping duplicate alert: {alert.get('event_id')} for {alert.get('username')}")
            return False

        conn.execute("""
            INSERT INTO alerts
            (event_id, description, channel, time, computer,
             username, ip_address, reason, risk_level, risk_score,
             severity, mitigation)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.get("event_id"),
            alert.get("description"),
            alert.get("channel"),
            alert.get("time"),
            alert.get("computer"),
            alert.get("username"),
            alert.get("ip_address"),
            alert.get("reason"),
            alert.get("risk_level"),
            alert.get("risk_score"),
            alert.get("severity"),
            alert.get("mitigation")
        ))
        conn.commit()
        return True


def get_alerts(limit=500):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def get_stats():
    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                COUNT(*)                        AS total,
                SUM(severity = 'CRITICAL')      AS critical,
                SUM(severity = 'HIGH')          AS high,
                SUM(severity = 'MEDIUM')        AS medium,
                SUM(severity = 'LOW')           AS low
            FROM alerts
        """).fetchone()
    return {
        "total":    row["total"]    or 0,
        "critical": row["critical"] or 0,
        "high":     row["high"]     or 0,
        "medium":   row["medium"]   or 0,
        "low":      row["low"]      or 0
    }


def clear_alerts():
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()