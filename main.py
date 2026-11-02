import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
import networkx as nx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from ml_service import predict
from audit_service import log_action, get_audit_logs
from concern_service import create_concern, list_concerns, review_concern

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_BEFORE_DEPLOYMENT")
ADMIN_SETUP_KEY = os.getenv("ADMIN_SETUP_KEY", "")
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:5500").split(",") if origin.strip()]
ALGORITHM = "HS256"

if JWT_SECRET == "CHANGE_ME_BEFORE_DEPLOYMENT":
    print("WARNING: Configure JWT_SECRET before deployment.")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="officer", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False)
    aapar_id = Column(String(80), index=True, nullable=False)
    email = Column(String(254), index=True, nullable=False)
    phone = Column(String(20), index=True, nullable=False)
    institution = Column(String(200), nullable=False)
    risk_score = Column(Float, default=0.0)
    status = Column(String(20), default="verified", nullable=False)
    reason = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(80))
    entity_id = Column(Integer)
    details = Column(Text)
    ip_address = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)

class Concern(Base):
    __tablename__ = "concerns"
    id = Column(Integer, primary_key=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    message = Column(Text, nullable=False)
    corrected_name = Column(String(160))
    corrected_email = Column(String(254))
    corrected_phone = Column(String(20))
    corrected_aapar_id = Column(String(80))
    status = Column(String(20), default="pending")
    admin_note = Column(Text)
    reviewed_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)

class AdminRegisterIn(RegisterIn):
    setup_key: str

class StudentIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    aapar_id: str = Field(min_length=3, max_length=80)
    email: EmailStr
    phone: str = Field(pattern=r"^[6-9][0-9]{9}$")
    institution: str = Field(min_length=2, max_length=200)

class StudentOut(BaseModel):
    id: int
    name: str
    aapar_id: str
    email: str
    phone: str
    institution: str
    risk_score: float
    status: str
    reason: str
    created_at: datetime
    class Config:
        from_attributes = True

class StatusIn(BaseModel):
    status: str

class ConcernIn(BaseModel):
    student_id: int
    message: str = Field(min_length=5, max_length=2000)
    corrected_name: Optional[str] = None
    corrected_email: Optional[EmailStr] = None
    corrected_phone: Optional[str] = None
    corrected_aapar_id: Optional[str] = None

class ConcernReviewIn(BaseModel):
    approve: bool
    admin_note: Optional[str] = Field(default=None, max_length=2000)

def hash_password(value):
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()

def verify_password(value, hashed):
    try:
        return bcrypt.checkpw(value.encode(), hashed.encode())
    except (ValueError, TypeError):
        return False

def make_token(user):
    return jwt.encode({"sub": user.username, "role": user.role,
                       "exp": datetime.now(timezone.utc) + timedelta(hours=12)},
                      JWT_SECRET, algorithm=ALGORITHM)

def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    try:
        username = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM]).get("sub")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

def officer_only(user=Depends(current_user)):
    if user.role != "officer":
        raise HTTPException(403, "Officers only")
    return user

def admin_only(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admins only")
    return user

def ip(request):
    return request.client.host if request.client else None

app = FastAPI(title="NextGen Intelligence API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS,
                   allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health():
    return {"status": "ok", "service": "NextGen Intelligence API"}

@app.post("/auth/register")
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    # Public registration can create officers only; it cannot grant admin access.
    if db.query(User).filter_by(username=data.username).first():
        raise HTTPException(409, "Username already exists")
    user = User(username=data.username, hashed_password=hash_password(data.password), role="officer")
    db.add(user); db.commit(); db.refresh(user)
    log_action(user.id, "ACCOUNT_CREATED", "user", user.id, "Officer account created", ip(request))
    return {"message": "Officer account created", "role": "officer"}

@app.post("/auth/register-admin")
def register_admin(data: AdminRegisterIn, request: Request, db: Session = Depends(get_db)):
    if not ADMIN_SETUP_KEY or data.setup_key != ADMIN_SETUP_KEY:
        raise HTTPException(403, "Admin setup key is invalid or not configured")
    if db.query(User).filter_by(username=data.username).first():
        raise HTTPException(409, "Username already exists")
    user = User(username=data.username, hashed_password=hash_password(data.password), role="admin")
    db.add(user); db.commit(); db.refresh(user)
    log_action(user.id, "ADMIN_ACCOUNT_CREATED", "user", user.id, "Admin account created", ip(request))
    return {"message": "Admin account created", "role": "admin"}

@app.post("/auth/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Incorrect username or password")
    log_action(user.id, "LOGIN", "user", user.id, "Successful login", ip(request))
    return {"access_token": make_token(user), "token_type": "bearer", "role": user.role}

@app.get("/auth/me")
def me(user=Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

def score_student(db, data):
    others = [{"name": s.name, "aapar_id": s.aapar_id, "email": s.email,
               "phone": s.phone, "institution": s.institution} for s in db.query(Student).all()]
    result = predict(data.model_dump(), others)
    return result["risk_score"], ("flagged" if result["risk_score"] >= 0.5 else "verified"), "; ".join(result["reasons"])

@app.post("/students", response_model=StudentOut)
def add_student(data: StudentIn, request: Request, db: Session = Depends(get_db), user=Depends(officer_only)):
    score, initial_status, reason = score_student(db, data)
    row = Student(**data.model_dump(), risk_score=score, status=initial_status,
                  reason=reason, created_by=user.id)
    db.add(row); db.commit(); db.refresh(row)
    log_action(user.id, "STUDENT_CREATED", "student", row.id, f"risk={score}; {initial_status}", ip(request))
    return row

@app.get("/students", response_model=list[StudentOut])
def get_students(status: Optional[str] = None, db: Session = Depends(get_db), user=Depends(current_user)):
    query = db.query(Student)
    if status:
        query = query.filter(Student.status == status)
    return query.order_by(Student.id.desc()).all()

@app.patch("/students/{student_id}/status")
def set_status(student_id: int, data: StatusIn, request: Request,
               db: Session = Depends(get_db), user=Depends(officer_only)):
    status = data.status.lower()
    if status not in ("accepted", "rejected"):
        raise HTTPException(422, "Status must be accepted or rejected")
    student = db.get(Student, student_id)
    if not student:
        raise HTTPException(404, "Student not found")
    previous = student.status
    student.status = status
    db.commit()
    log_action(user.id, "STUDENT_STATUS_CHANGED", "student", student.id,
               f"{previous} -> {status}", ip(request))
    return {"id": student.id, "status": status}

@app.get("/admin/stats")
def stats(db: Session = Depends(get_db), user=Depends(admin_only)):
    total = db.query(Student).count()
    flagged = db.query(Student).filter_by(status="flagged").count()
    verified = db.query(Student).filter_by(status="verified").count()
    accepted = db.query(Student).filter_by(status="accepted").count()
    rejected = db.query(Student).filter_by(status="rejected").count()
    return {"total": total, "flagged": flagged, "verified": verified,
            "accepted": accepted, "rejected": rejected,
            "flag_rate": round(flagged / total, 2) if total else 0}

@app.get("/graph")
def graph(db: Session = Depends(get_db), user=Depends(admin_only)):
    records = db.query(Student).all()
    g = nx.MultiGraph()
    for s in records:
        g.add_node(s.id, name=s.name, status=s.status)
    for field in ("phone", "email", "aapar_id"):
        groups = {}
        for s in records:
            value = getattr(s, field)
            if value: groups.setdefault(value, []).append(s.id)
        for ids in groups.values():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    g.add_edge(ids[i], ids[j], reason=f"same {field}")
    return {"nodes": [{"id": n, **d} for n, d in g.nodes(data=True)],
            "edges": [{"source": u, "target": v, "reason": d["reason"]} for u, v, d in g.edges(data=True)],
            "suspicious_clusters": [sorted(c) for c in nx.connected_components(g) if len(c) > 1]}

@app.get("/admin/audit-logs")
def audit_logs(limit: int = 50, user=Depends(admin_only)):
    return get_audit_logs(max(1, min(limit, 200)))

@app.post("/concerns")
def post_concern(data: ConcernIn, request: Request, db: Session = Depends(get_db), user=Depends(current_user)):
    if not db.get(Student, data.student_id):
        raise HTTPException(404, "Student not found")
    result = create_concern(data.student_id, data.message, data.corrected_name,
        str(data.corrected_email) if data.corrected_email else None,
        data.corrected_phone, data.corrected_aapar_id, ip(request))
    if not result["ok"]:
        raise HTTPException(400, result["error"])
    return result

@app.get("/concerns")
def get_concerns(status: Optional[str] = None, user=Depends(admin_only)):
    return list_concerns(status)

@app.patch("/concerns/{concern_id}/review")
def concern_review(concern_id: int, data: ConcernReviewIn, request: Request,
                   user=Depends(admin_only)):
    result = review_concern(concern_id, user.id, data.approve, data.admin_note, ip(request))
    if not result["ok"]:
        raise HTTPException(404, result["error"])
    return result
