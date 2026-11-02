import os
from sqlalchemy import create_engine, text
from audit_service import log_action

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
MAX_REQUESTS = 2

def create_concern(student_id, message, corrected_name=None, corrected_email=None,
                   corrected_phone=None, corrected_aapar_id=None, ip_address=None):
    with engine.begin() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM concerns WHERE student_id=:s"), {"s": student_id}).scalar_one()
        if count >= MAX_REQUESTS:
            return {"ok": False, "error": "Maximum 2 requests allowed"}
        pending = conn.execute(text("SELECT COUNT(*) FROM concerns WHERE student_id=:s AND status='pending'"), {"s": student_id}).scalar_one()
        if pending:
            return {"ok": False, "error": "A request is already pending"}
        new_id = conn.execute(text("""
            INSERT INTO concerns (student_id, message, corrected_name, corrected_email,
                corrected_phone, corrected_aapar_id, status, created_at)
            VALUES (:s,:m,:n,:e,:p,:a,'pending',CURRENT_TIMESTAMP) RETURNING id
        """), {"s": student_id, "m": message, "n": corrected_name, "e": corrected_email,
               "p": corrected_phone, "a": corrected_aapar_id}).scalar_one()
    log_action(None, "CONCERN_CREATED", "concern", new_id, f"Student {student_id} requested review", ip_address)
    return {"ok": True, "concern_id": new_id}

def list_concerns(status=None):
    query = """SELECT c.id,c.student_id,s.name,c.message,c.corrected_name,c.corrected_email,
        c.corrected_phone,c.corrected_aapar_id,c.status,c.admin_note,c.created_at
        FROM concerns c JOIN students s ON s.id=c.student_id"""
    params = {}
    if status:
        query += " WHERE c.status=:st"
        params["st"] = status
    query += " ORDER BY c.created_at DESC"
    with engine.connect() as conn:
        rows = conn.execute(text(query), params).fetchall()
    return [dict(r._mapping) for r in rows]

def review_concern(concern_id, admin_id, approve, admin_note=None, ip_address=None):
    new_status = "approved" if approve else "rejected"
    with engine.begin() as conn:
        concern = conn.execute(text("SELECT * FROM concerns WHERE id=:i AND status='pending'"), {"i": concern_id}).fetchone()
        if not concern:
            return {"ok": False, "error": "Concern not found or already reviewed"}
        conn.execute(text("""UPDATE concerns SET status=:st,admin_note=:n,reviewed_by=:a,
            reviewed_at=CURRENT_TIMESTAMP WHERE id=:i"""),
            {"st": new_status, "n": admin_note, "a": admin_id, "i": concern_id})
        if approve:
            conn.execute(text("""UPDATE students SET name=COALESCE(:n,name),
                email=COALESCE(:e,email),phone=COALESCE(:p,phone),
                aapar_id=COALESCE(:a,aapar_id) WHERE id=:s"""),
                {"n": concern.corrected_name, "e": concern.corrected_email,
                 "p": concern.corrected_phone, "a": concern.corrected_aapar_id,
                 "s": concern.student_id})
    log_action(admin_id, f"CONCERN_{new_status.upper()}", "concern", concern_id, admin_note, ip_address)
    return {"ok": True, "status": new_status, "student_id": concern.student_id}
