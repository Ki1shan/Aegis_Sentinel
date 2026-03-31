import sqlite3
from datetime import datetime
from contextlib import contextmanager
from typing import Optional
import os
import hashlib
import secrets

DB_PATH = os.path.join(os.path.dirname(__file__), "aegis_sentinel.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'operator',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                window_start TEXT,
                blocked INTEGER DEFAULT 0,
                blocked_at TEXT,
                total_requests INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT,
                threat_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'low',
                UNIQUE(ip_address)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                count INTEGER,
                user_agent TEXT,
                threat_score REAL,
                headers_count INTEGER,
                response_time_ms REAL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                threat_score REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_by TEXT,
                acknowledged_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                pattern_value TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                active INTEGER DEFAULT 1
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_model_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                features TEXT NOT NULL,
                prediction REAL,
                confidence REAL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_request_log_ip ON request_log(ip_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_request_log_timestamp ON request_log(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)
        """)
        
        if not get_user_by_username("admin"):
            create_user("admin", "aegis2024!", "admin")
        
        default_settings = {
            "max_requests": "10",
            "window_seconds": "15",
            "block_duration": "300",
            "ml_threshold": "0.7",
            "enable_ml": "true",
            "alert_email": "",
            "auto_block": "true"
        }
        
        for key, value in default_settings.items():
            cursor.execute("""
                INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
            """, (key, value))


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hash_obj.hex(), salt


def create_user(username: str, password: str, role: str = "operator") -> bool:
    password_hash, salt = hash_password(password)
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, salt, role))
            return True
    except sqlite3.IntegrityError:
        return False


def authenticate_user(username: str, password: str) -> Optional[dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            password_hash, _ = hash_password(password, user["salt"])
            if password_hash == user["password_hash"]:
                cursor.execute("""
                    UPDATE users SET last_login = ? WHERE username = ?
                """, (datetime.now().isoformat(), username))
                return dict(user)
        return None


def get_user_by_username(username: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()


def get_or_create_ip(ip_address: str) -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO ip_tracking (ip_address, count, window_start, total_requests, first_seen, last_seen)
            VALUES (?, 1, ?, 1, ?, ?)
        """, (ip_address, now, now, now))
        
        cursor.execute("SELECT * FROM ip_tracking WHERE ip_address = ?", (ip_address,))
        return dict(cursor.fetchone())


def update_ip_tracking(ip_address: str, blocked: bool = False, threat_score: float = 0.0, risk_level: str = "low"):
    with get_db() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            UPDATE ip_tracking 
            SET total_requests = total_requests + 1,
                last_seen = ?,
                threat_score = ?,
                risk_level = ?,
                blocked = ?,
                blocked_at = CASE WHEN ? = 1 THEN ? ELSE blocked_at END
            WHERE ip_address = ?
        """, (now, threat_score, risk_level, blocked, blocked, now if blocked else None, ip_address))


def increment_ip_count(ip_address: str, window_seconds: int) -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        now = datetime.now()
        
        cursor.execute("SELECT * FROM ip_tracking WHERE ip_address = ?", (ip_address,))
        ip_entry = cursor.fetchone()
        
        if not ip_entry:
            return get_or_create_ip(ip_address)
        
        window_start = datetime.fromisoformat(ip_entry["window_start"])
        elapsed = (now - window_start).total_seconds()
        
        if elapsed > window_seconds:
            cursor.execute("""
                UPDATE ip_tracking 
                SET count = 1, window_start = ?, blocked = 0, blocked_at = NULL
                WHERE ip_address = ?
            """, (now.isoformat(), ip_address))
        else:
            cursor.execute("""
                UPDATE ip_tracking SET count = count + 1 WHERE ip_address = ?
            """, (ip_address,))
        
        cursor.execute("SELECT * FROM ip_tracking WHERE ip_address = ?", (ip_address,))
        return dict(cursor.fetchone())


def block_ip(ip_address: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            UPDATE ip_tracking 
            SET blocked = 1, blocked_at = ?, risk_level = 'critical'
            WHERE ip_address = ?
        """, (now, ip_address))
        return cursor.rowcount > 0


def unblock_ip(ip_address: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE ip_tracking 
            SET blocked = 0, blocked_at = NULL, count = 0, risk_level = 'low', threat_score = 0
            WHERE ip_address = ?
        """, (ip_address,))
        return cursor.rowcount > 0


def get_all_tracked_ips() -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ip_tracking ORDER BY total_requests DESC")
        return [dict(row) for row in cursor.fetchall()]


def log_request(ip_address: str, status: str, count: int, user_agent: str, threat_score: float = 0.0, headers_count: int = 0, response_time_ms: float = 0.0):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO request_log (ip_address, status, timestamp, count, user_agent, threat_score, headers_count, response_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, status, datetime.now().isoformat(), count, user_agent, threat_score, headers_count, response_time_ms))


def get_recent_requests(limit: int = 100) -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM request_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_requests_in_window(ip_address: str, window_seconds: int) -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cutoff = datetime.now()
        cursor.execute("""
            SELECT * FROM request_log 
            WHERE ip_address = ? AND timestamp > ?
            ORDER BY timestamp DESC
        """, (ip_address, cutoff.isoformat()))
        return [dict(row) for row in cursor.fetchall()]


def create_alert(ip_address: str, severity: str, message: str, threat_score: float = 0.0):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (ip_address, severity, message, threat_score)
            VALUES (?, ?, ?, ?)
        """, (ip_address, severity, message, threat_score))
        return cursor.lastrowid


def get_active_alerts(acknowledged: bool = False) -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM alerts 
            WHERE acknowledged = ? 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                END,
                created_at DESC
        """, (1 if acknowledged else 0,))
        return [dict(row) for row in cursor.fetchall()]


def acknowledge_alert(alert_id: int, username: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE alerts 
            SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
            WHERE id = ?
        """, (username, datetime.now().isoformat(), alert_id))
        return cursor.rowcount > 0


def get_threat_signatures() -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_signatures WHERE active = 1")
        return [dict(row) for row in cursor.fetchall()]


def add_threat_signature(pattern_type: str, pattern_value: str, severity: str, description: str = "") -> Optional[int]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_signatures (pattern_type, pattern_value, severity, description)
            VALUES (?, ?, ?, ?)
        """, (pattern_type, pattern_value, severity, description))
        return cursor.lastrowid


def get_settings() -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        return {row["key"]: row["value"] for row in cursor.fetchall()}


def update_setting(key: str, value: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, datetime.now().isoformat()))


def get_ip_request_patterns(ip_address: str, window_seconds: int = 300) -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        cutoff = datetime.now()
        
        cursor.execute("""
            SELECT * FROM request_log 
            WHERE ip_address = ? AND timestamp > ?
            ORDER BY timestamp DESC
        """, (ip_address, cutoff.isoformat()))
        
        requests = [dict(row) for row in cursor.fetchall()]
        
        if not requests:
            return {"pattern": "none", "requests_per_minute": 0, "unique_agents": 0, "unique_paths": 0}
        
        unique_agents = len(set(r["user_agent"] for r in requests))
        unique_paths = len(set(r["status"] for r in requests))
        
        if len(requests) >= 2:
            first_ts = datetime.fromisoformat(requests[-1]["timestamp"])
            last_ts = datetime.fromisoformat(requests[0]["timestamp"])
            duration_minutes = max((last_ts - first_ts).total_seconds() / 60, 1)
            requests_per_minute = len(requests) / duration_minutes
        else:
            requests_per_minute = 0
        
        rapid_fire = sum(1 for i in range(1, len(requests)) 
                         if (datetime.fromisoformat(requests[i-1]["timestamp"]) - 
                             datetime.fromisoformat(requests[i]["timestamp"])).total_seconds() < 1)
        
        return {
            "total_requests": len(requests),
            "requests_per_minute": round(requests_per_minute, 2),
            "unique_agents": unique_agents,
            "unique_paths": unique_paths,
            "rapid_fire_count": rapid_fire,
            "avg_threat_score": sum(r["threat_score"] for r in requests) / len(requests) if requests else 0
        }


def get_high_risk_ips(threshold: float = 0.6) -> list:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM ip_tracking 
            WHERE threat_score >= ? OR risk_level IN ('high', 'critical')
            ORDER BY threat_score DESC
        """, (threshold,))
        return [dict(row) for row in cursor.fetchall()]


def get_statistics() -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        
        now = datetime.now()
        recent_cutoff = now
        
        cursor.execute("SELECT COUNT(*) as total FROM request_log")
        total_requests = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM ip_tracking")
        total_ips = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM ip_tracking WHERE blocked = 1")
        blocked_ips = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE acknowledged = 0")
        active_alerts = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE severity = 'critical' AND acknowledged = 0")
        critical_alerts = cursor.fetchone()["total"]
        
        cursor.execute("""
            SELECT COUNT(*) as total FROM request_log 
            WHERE timestamp > ?
        """, (now.isoformat(),))
        recent_requests = cursor.fetchone()["total"]
        
        cursor.execute("SELECT AVG(threat_score) as avg FROM ip_tracking WHERE threat_score > 0")
        avg_threat = cursor.fetchone()["avg"] or 0
        
        return {
            "total_requests": total_requests,
            "total_ips": total_ips,
            "blocked_ips": blocked_ips,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
            "recent_requests": recent_requests,
            "avg_threat_score": round(avg_threat, 3)
        }
