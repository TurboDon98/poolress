from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
import shutil
import uuid
import os
from pathlib import Path
from datetime import datetime, timedelta
import secrets
import hashlib

from .db import SessionLocal, engine, Base
from .models import ProjectFile, ProjectMeta, User, UserSession
from .parser import parse_project_meta

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TurboProject 2.0 Backend")

# CORS
origins = [
    "http://localhost:5173",
    "http://localhost:5176",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5176",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "storage" / "projects"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTS = {".mpp", ".mpt", ".mpx", ".xml"}

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helpers
def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    s = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(s), 100_000)
    return s, dk.hex()

def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    try:
        _, h = _hash_password(password, salt)
        return h == expected_hash
    except Exception:
        return False

def _issue_session(db, user_id: int, user_agent: str | None = None, days: int = 30) -> str:
    token = secrets.token_hex(32)
    now = datetime.utcnow()
    expires = now + timedelta(days=days)
    sess = UserSession(user_id=user_id, token=token, user_agent=(user_agent or ''), created_at=now, last_seen=now, expires_at=expires)
    db.add(sess)
    db.commit()
    return token

def _get_token_from_auth(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1].strip() or None
    return None

def _get_current_user(db, token: str | None):
    if not token:
        return None
    sess = db.query(UserSession).filter(UserSession.token == token).first()
    if not sess:
        return None
    if sess.expires_at and sess.expires_at < datetime.utcnow():
        try:
            db.delete(sess)
            db.commit()
        except Exception:
            pass
        return None
    try:
        sess.last_seen = datetime.utcnow()
        db.commit()
    except Exception:
        pass
    return db.query(User).filter(User.id == sess.user_id).first()

def _is_allowed(name: str, content_type: str | None) -> bool:
    ext = Path(name).suffix.lower()
    if ext in ALLOWED_EXTS:
        return True
    if content_type == "application/vnd.ms-project":
        return True
    return False

def _project_name_from_upload(original_filename: str, meta: Optional[dict]) -> str:
    try:
        n = (meta or {}).get("name")
    except Exception:
        n = None
    if n is None:
        n = ""
    n = str(n).strip()
    if n:
        return n
    try:
        return Path(original_filename).stem.strip()
    except Exception:
        return ""

def _collect_and_delete_projects_by_name(db, project_name: str) -> list[str]:
    norm = (project_name or "").strip()
    if not norm:
        return []
    norm_lower = norm.lower()
    stale_paths: list[str] = []
    rows = (
        db.query(ProjectFile.id, ProjectFile.stored_path)
        .join(ProjectMeta, ProjectMeta.file_id == ProjectFile.id)
        .filter(func.lower(ProjectMeta.name) == norm_lower)
        .distinct()
        .all()
    )
    file_ids = [r[0] for r in rows]
    for _, stored_path in rows:
        if stored_path:
            stale_paths.append(stored_path)
    if file_ids:
        db.query(ProjectMeta).filter(ProjectMeta.file_id.in_(file_ids)).delete(synchronize_session=False)
        db.query(ProjectFile).filter(ProjectFile.id.in_(file_ids)).delete(synchronize_session=False)
    
    # Also clean up orphans
    orphan_pfs = (
        db.query(ProjectFile)
        .outerjoin(ProjectMeta, ProjectMeta.file_id == ProjectFile.id)
        .filter(ProjectMeta.id.is_(None))
        .all()
    )
    for pf in orphan_pfs:
        try:
            stem = Path(pf.original_name).stem.strip().lower()
        except Exception:
            stem = ""
        if stem and stem == norm_lower:
            if pf.stored_path:
                stale_paths.append(pf.stored_path)
            db.delete(pf)

    return stale_paths

# ======== AUTH ENDPOINTS ========

@app.post("/api/auth/register")
def auth_register(payload: dict = Body(...), req: Request = None, db: Session = Depends(get_db)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные")
    email = str(payload.get("email") or "").strip().lower()
    username = str(payload.get("username") or "").strip() or None
    full_name = str(payload.get("full_name") or "").strip() or None
    # Extended fields
    department = str(payload.get("department") or "").strip() or None
    position = str(payload.get("position") or "").strip() or None
    
    password = str(payload.get("password") or "")
    role = str(payload.get("role") or "").strip() or None
    
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Требуется корректная почта")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Слишком короткий пароль")
        
    exists = db.query(User).filter((User.email == email) | ((username is not None) & (User.username == username))).first()
    if exists:
        raise HTTPException(status_code=409, detail="Пользователь уже существует")
        
    salt, ph = _hash_password(password)
    user = User(
        email=email, 
        username=username, 
        full_name=full_name, 
        department=department,
        position=position,
        role=role, 
        password_salt=salt, 
        password_hash=ph, 
        created_at=datetime.utcnow(), 
        updated_at=datetime.utcnow(), 
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    ua = req.headers.get("User-Agent")
    token = _issue_session(db, user.id, ua)
    return {
        "ok": True, 
        "user": {
            "id": user.id, 
            "email": user.email, 
            "username": user.username, 
            "full_name": user.full_name, 
            "department": user.department,
            "position": user.position,
            "role": user.role
        }, 
        "token": token
    }

@app.post("/api/auth/login")
def auth_login(payload: dict = Body(...), req: Request = None, db: Session = Depends(get_db)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные")
    identifier = str(payload.get("email") or payload.get("username") or "").strip().lower()
    password = str(payload.get("password") or "")
    if not identifier or not password:
        raise HTTPException(status_code=400, detail="Требуются логин и пароль")
        
    user = db.query(User).filter((User.email == identifier) | (User.username == identifier)).first()
    if not user or not _verify_password(password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверные учетные данные")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Пользователь отключен")
        
    ua = req.headers.get("User-Agent")
    token = _issue_session(db, user.id, ua)
    return {
        "ok": True, 
        "user": {
            "id": user.id, 
            "email": user.email, 
            "username": user.username, 
            "full_name": user.full_name, 
            "role": user.role
        }, 
        "token": token
    }

@app.get("/api/auth/me")
def auth_me(req: Request, db: Session = Depends(get_db)):
    auth = req.headers.get("Authorization")
    token = _get_token_from_auth(auth)
    user = _get_current_user(db, token)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return {
        "ok": True, 
        "user": {
            "id": user.id, 
            "email": user.email, 
            "username": user.username, 
            "full_name": user.full_name, 
            "department": user.department,
            "position": user.position,
            "role": user.role
        }
    }

@app.post("/api/auth/logout")
def auth_logout(req: Request, db: Session = Depends(get_db)):
    auth = req.headers.get("Authorization")
    token = _get_token_from_auth(auth)
    if not token:
        return {"ok": True}
    sess = db.query(UserSession).filter(UserSession.token == token).first()
    if sess:
        db.delete(sess)
        db.commit()
    return {"ok": True}

# ======== PROJECTS ENDPOINTS ========

@app.post("/api/projects/upload")
async def upload_projects(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    accepted: list[dict] = []
    rejected: list[dict] = []
    stale_paths: list[str] = []
    
    for f in files:
        if not _is_allowed(f.filename, f.content_type):
            rejected.append({"name": f.filename, "reason": "unsupported_type"})
            continue
        safe_name = f.filename.replace("/", "_").replace("\\", "_")
        target = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"
        try:
            with target.open("wb") as out:
                shutil.copyfileobj(f.file, out)
            size = target.stat().st_size

            meta = parse_project_meta(target)
            project_name = _project_name_from_upload(f.filename, meta)

            tx = db.begin_nested()
            try:
                stale_for_this = _collect_and_delete_projects_by_name(db, project_name)

                pf = ProjectFile(
                    original_name=f.filename,
                    stored_name=target.name,
                    stored_path=str(target),
                    content_type=f.content_type,
                    size_bytes=size,
                )
                db.add(pf)
                db.flush()
                pm = ProjectMeta(
                    file_id=pf.id,
                    name=(project_name or "").strip() or None,
                    author=(meta.get("author") if meta else None),
                    resources=(meta.get("resources") if meta else None),
                    start_date=(meta.get("start_date") if meta else None),
                    finish_date=(meta.get("finish_date") if meta else None),
                    actual_finish_date=(meta.get("actual_finish_date") if meta else None),
                    percent_complete=(meta.get("percent_complete") if meta else None),
                )
                db.add(pm)
                tx.commit()

                stale_paths.extend(stale_for_this)
                accepted.append({"name": f.filename, "stored_as": target.name})
            except Exception:
                tx.rollback()
                rejected.append({"name": f.filename, "reason": "write_failed"})
                try:
                    if target.exists():
                        target.unlink()
                except Exception:
                    pass
            continue
        except Exception:
            rejected.append({"name": f.filename, "reason": "write_failed"})
            try:
                if target.exists():
                    target.unlink()
            except Exception:
                pass
    
    db.commit()
    
    for p in stale_paths:
        try:
            pp = Path(p)
            if pp.exists():
                pp.unlink()
        except Exception:
            pass
            
    return {"ok": True, "accepted": accepted, "rejected": rejected}

@app.get("/api/projects/files")
def list_project_files(db: Session = Depends(get_db)):
    rows = db.query(ProjectFile).order_by(ProjectFile.uploaded_at.desc()).all()
    data = [
        {
            "id": r.id,
            "original_name": r.original_name,
            "stored_name": r.stored_name,
            "stored_path": r.stored_path,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
            "uploaded_at": r.uploaded_at.isoformat(),
            "project": None,
        }
        for r in rows
    ]
    for item in data:
        m = db.query(ProjectMeta).filter(ProjectMeta.file_id == item["id"]).order_by(ProjectMeta.created_at.desc()).first()
        if m:
            item["project"] = {
                "name": m.name,
                "author": m.author,
                "resources": m.resources,
                "start_date": m.start_date.isoformat() if m.start_date else None,
                "finish_date": m.finish_date.isoformat() if m.finish_date else None,
                "actual_finish_date": m.actual_finish_date.isoformat() if m.actual_finish_date else None,
                "percent_complete": m.percent_complete,
            }
        else:
            # Fallback metadata parsing if not in DB? Or just return null
            pass
            
    return {"items": data}

@app.delete("/api/projects/files/{file_id}")
def delete_project_file(file_id: int, db: Session = Depends(get_db)):
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not pf:
        raise HTTPException(status_code=404, detail="not_found")
    try:
        p = Path(pf.stored_path)
        if p.exists():
            p.unlink()
    except Exception:
        pass
    db.query(ProjectMeta).filter(ProjectMeta.file_id == file_id).delete()
    db.delete(pf)
    db.commit()
    return {"ok": True}
