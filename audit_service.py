import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)

def log_action(user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address, created_at)
            VALUES (:u, :a, :et, :ei, :d, :ip, CURRENT_TIMESTAMP)
        """), {"u": user_id, "a": action, "et": entity_type, "ei": entity_id, "d": details, "ip": ip_address})

def get_audit_logs(limit=50):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT a.id, u.username, a.action, a.entity_type, a.entity_id,
                   a.details, a.ip_address, a.created_at
            FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
            ORDER BY a.created_at DESC LIMIT :limit
        """), {"limit": limit}).fetchall()
    return [dict(r._mapping) for r in rows]
