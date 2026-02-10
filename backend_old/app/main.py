from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from pathlib import Path
import shutil
import uuid
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
import subprocess
import sys
from sqlalchemy import func, text
try:
    from .db import SessionLocal, engine, Base
    from .models import ProjectFile, ProjectMeta, ResourcePerson, ResourceState, WorkCalendar, User, UserSession
except ImportError:
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app.db import SessionLocal, engine, Base
    from app.models import ProjectFile, ProjectMeta, ResourcePerson, ResourceState, WorkCalendar, User, UserSession
from datetime import datetime
import datetime as _dt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/hello")
def hello():
    return {"message": "Hello from Python backend"}

_db_ready = False
_db_error = None

def _format_db_error(e: Exception) -> str:
    try:
        v = getattr(e, "orig", e)
    except Exception:
        v = e
    if isinstance(v, UnicodeDecodeError) or isinstance(e, UnicodeDecodeError):
        u = v if isinstance(v, UnicodeDecodeError) else (e if isinstance(e, UnicodeDecodeError) else None)
        sample_hex = None
        cp1251_preview = None
        cp866_preview = None
        if u is not None:
            try:
                raw = u.object if isinstance(u.object, (bytes, bytearray)) else None
                if raw is not None:
                    start = max(0, int(getattr(u, "start", 0)) - 80)
                    end = min(len(raw), int(getattr(u, "end", 0)) + 80)
                    sample = bytes(raw[start:end])
                    sample_hex = sample.hex()
                    try:
                        cp1251_preview = sample.decode("cp1251", errors="replace")
                    except Exception:
                        cp1251_preview = None
                    try:
                        cp866_preview = sample.decode("cp866", errors="replace")
                    except Exception:
                        cp866_preview = None
            except Exception:
                pass
        parts = [
            "UnicodeDecodeError при попытке вывести текст ошибки подключения к Postgres.",
            "TCP порт 5432 у тебя доступен, значит дальше проверяем SSL/параметры libpq.",
            "Попробуй на сервере бэкенда в .env: PGSSLMODE=disable и перезапусти backend.",
        ]
        if sample_hex:
            parts.append(f"raw_hex={sample_hex}")
        if cp1251_preview:
            parts.append(f"raw_cp1251={cp1251_preview}")
        if cp866_preview:
            parts.append(f"raw_cp866={cp866_preview}")
        return " | ".join(parts)
    try:
        return str(v)
    except UnicodeDecodeError:
        return (
            "Ошибка декодирования текста ошибки при подключении к Postgres. "
            "На Windows это часто означает, что реальная сетевая/SSL-ошибка пришла в кодировке cp1251. "
            "Проверь доступность 194.67.127.103:5432 с сервера бэкенда командой "
            "Test-NetConnection 194.67.127.103 -Port 5432."
        )

@app.on_event("startup")
def _startup_db_check():
    global _db_ready, _db_error
    try:
        Base.metadata.create_all(engine)
        _ensure_project_meta_author_column()
        _ensure_project_meta_actual_finish_column()
        _db_ready = True
        _db_error = None
    except Exception as e:
        _db_ready = False
        _db_error = _format_db_error(e)

# ======== AUTH HELPERS ========
import secrets, hashlib, os
from datetime import timedelta
from fastapi import Request

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

# ======== AUTH ENDPOINTS ========
@app.post("/api/auth/register")
def auth_register(payload: dict = Body(...), req: Request = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные")
    email = str(payload.get("email") or "").strip().lower()
    username = str(payload.get("username") or "").strip() or None
    full_name = str(payload.get("full_name") or "").strip() or None
    password = str(payload.get("password") or "")
    role = str(payload.get("role") or "").strip() or None
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Требуется корректная почта")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Слишком короткий пароль")
    db = SessionLocal()
    try:
        exists = db.query(User).filter((User.email == email) | ((username is not None) & (User.username == username))).first()
        if exists:
            raise HTTPException(status_code=409, detail="Пользователь уже существует")
        salt, ph = _hash_password(password)
        user = User(email=email, username=username, full_name=full_name, role=role, password_salt=salt, password_hash=ph, created_at=datetime.utcnow(), updated_at=datetime.utcnow(), is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        ua = None
        try:
            ua = req.headers.get("User-Agent")
        except Exception:
            ua = None
        token = _issue_session(db, user.id, ua)
        return {"ok": True, "user": {"id": user.id, "email": user.email, "username": user.username, "full_name": user.full_name, "role": user.role}, "token": token}
    finally:
        db.close()

@app.post("/api/auth/login")
def auth_login(payload: dict = Body(...), req: Request = None):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные")
    identifier = str(payload.get("email") or payload.get("username") or "").strip().lower()
    password = str(payload.get("password") or "")
    if not identifier or not password:
        raise HTTPException(status_code=400, detail="Требуются логин и пароль")
    db = SessionLocal()
    try:
        user = db.query(User).filter((User.email == identifier) | (User.username == identifier)).first()
        if not user or not _verify_password(password, user.password_salt, user.password_hash):
            raise HTTPException(status_code=401, detail="Неверные учетные данные")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Пользователь отключен")
        ua = None
        try:
            ua = req.headers.get("User-Agent")
        except Exception:
            ua = None
        token = _issue_session(db, user.id, ua)
        return {"ok": True, "user": {"id": user.id, "email": user.email, "username": user.username, "full_name": user.full_name, "role": user.role}, "token": token}
    finally:
        db.close()

@app.get("/api/auth/me")
def auth_me(req: Request):
    auth = None
    try:
        auth = req.headers.get("Authorization")
    except Exception:
        auth = None
    token = _get_token_from_auth(auth)
    db = SessionLocal()
    try:
        user = _get_current_user(db, token)
        if not user:
            raise HTTPException(status_code=401, detail="Не авторизован")
        return {"ok": True, "user": {"id": user.id, "email": user.email, "username": user.username, "full_name": user.full_name, "role": user.role}}
    finally:
        db.close()

@app.post("/api/auth/logout")
def auth_logout(req: Request):
    auth = None
    try:
        auth = req.headers.get("Authorization")
    except Exception:
        auth = None
    token = _get_token_from_auth(auth)
    if not token:
        return {"ok": True}
    db = SessionLocal()
    try:
        sess = db.query(UserSession).filter(UserSession.token == token).first()
        if sess:
            try:
                db.delete(sess)
                db.commit()
            except Exception:
                pass
        return {"ok": True}
    finally:
        db.close()

@app.get("/api/health")
def health():
    global _db_ready, _db_error
    db_ok = bool(_db_ready)
    err = _db_error
    if not db_ok:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
            err = None
            _db_ready = True
            _db_error = None
        except Exception as e:
            db_ok = False
            err = _format_db_error(e)
            _db_ready = False
            _db_error = err
    return {"backend_ok": True, "db_ok": db_ok, "db_error": err}

@app.get("/api/sys/user")
def sys_user():
    try:
        import os, getpass, socket, platform
        try:
            username = os.getlogin()
        except Exception:
            try:
                username = getpass.getuser()
            except Exception:
                username = None
        hostname = socket.gethostname()
        email = None
        full_name = None
        try:
            r = subprocess.run(["whoami.exe", "/UPN"], capture_output=True, text=True)
            if r.returncode == 0:
                cand = (r.stdout or r.stderr or "").strip()
                if "@" in cand and "." in cand:
                    email = cand
        except Exception:
            pass
        try:
            ps = [
                "powershell",
                "-NoProfile",
                "-Command",
                "try { (Get-CimInstance -ClassName Win32_UserAccount -Filter \"Name='$env:USERNAME'\").FullName } catch { '' }"
            ]
            r2 = subprocess.run(ps, capture_output=True, text=True)
            if r2.returncode == 0:
                fn = (r2.stdout or r2.stderr or "").strip()
                if fn:
                    full_name = fn
        except Exception:
            pass
        return {"username": username, "hostname": hostname, "platform": platform.system(), "email": email, "full_name": full_name}
    except Exception:
        return {"username": None, "hostname": None, "platform": None, "email": None, "full_name": None}

def _default_work_calendar() -> dict:
    return {
        "name": "Основной календарь",
        "timezone": None,
        "workWeek": {
            "mon": [{"start": "09:00", "end": "18:00"}],
            "tue": [{"start": "09:00", "end": "18:00"}],
            "wed": [{"start": "09:00", "end": "18:00"}],
            "thu": [{"start": "09:00", "end": "18:00"}],
            "fri": [{"start": "09:00", "end": "18:00"}],
            "sat": [],
            "sun": [],
        },
        "exceptions": [],
    }

def _load_work_calendar() -> dict:
    db = SessionLocal()
    try:
        row = db.query(WorkCalendar).filter(WorkCalendar.id == 1).first()
        data = None
        if row and row.data_json:
            try:
                data = json.loads(row.data_json)
            except Exception:
                data = None
        if not isinstance(data, dict):
            data = _default_work_calendar()
        return data
    finally:
        db.close()

@app.get("/api/settings/calendar")
def get_work_calendar():
    db = SessionLocal()
    try:
        row = db.query(WorkCalendar).filter(WorkCalendar.id == 1).first()
        data = None
        if row and row.data_json:
            try:
                data = json.loads(row.data_json)
            except Exception:
                data = None
        if not isinstance(data, dict):
            data = _default_work_calendar()
        return {"ok": True, "calendar": data}
    finally:
        db.close()

@app.put("/api/settings/calendar")
def save_work_calendar(payload: dict = Body(...)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные календаря")
    cal = payload.get("calendar", payload)
    if not isinstance(cal, dict):
        raise HTTPException(status_code=400, detail="Некорректные данные календаря")
    data_json = json.dumps(cal, ensure_ascii=False)
    db = SessionLocal()
    try:
        row = db.query(WorkCalendar).filter(WorkCalendar.id == 1).first()
        if not row:
            row = WorkCalendar(id=1, name=cal.get("name"))
            db.add(row)
        row.name = cal.get("name")
        row.data_json = data_json
        row.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
    return {"ok": True, "calendar": cal}

def _normalize_calendar_data(data: dict | None) -> dict:
    base = data if isinstance(data, dict) else {}
    work_week = base.get("workWeek") if isinstance(base.get("workWeek"), dict) else {}
    exceptions = base.get("exceptions") if isinstance(base.get("exceptions"), list) else []
    holidays = base.get("holidays") if isinstance(base.get("holidays"), list) else []
    return {
        "name": base.get("name") or "Основной календарь",
        "timezone": base.get("timezone"),
        "workWeek": work_week,
        "exceptions": exceptions,
        "holidays": holidays,
        "holidaySource": base.get("holidaySource"),
    }

def _save_calendar_data(cal: dict) -> dict:
    data_json = json.dumps(cal, ensure_ascii=False)
    db = SessionLocal()
    try:
        row = db.query(WorkCalendar).filter(WorkCalendar.id == 1).first()
        if not row:
            row = WorkCalendar(id=1, name=cal.get("name"))
            db.add(row)
        row.name = cal.get("name")
        row.data_json = data_json
        row.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
    return cal

def _extract_holidays_from_project(prj) -> list[str]:
    at = _get_aspose_tasks()
    dates: set[str] = set()
    try:
        calendars = list(getattr(prj, "calendars", []) or [])
    except Exception:
        calendars = []

    def _get_date(v):
        try:
            if v is None:
                return None
            if hasattr(v, "date"):
                return v.date()
            if isinstance(v, _dt.datetime):
                return v.date()
            if isinstance(v, _dt.date):
                return v
            return None
        except Exception:
            return None

    def _is_non_working_exception(exc) -> bool:
        try:
            working = getattr(exc, "working", None)
            if working is False:
                return True
            is_working = getattr(exc, "is_working", None)
            if is_working is False:
                return True
        except Exception:
            pass
        try:
            wts = getattr(exc, "working_times", None)
            if wts is not None:
                try:
                    return len(list(wts)) == 0
                except Exception:
                    return False
        except Exception:
            pass
        return False

    def _iter_exc_dates(exc):
        try:
            start = getattr(exc, "from_date", None) or getattr(exc, "start", None) or getattr(exc, "start_date", None)
        except Exception:
            start = None
        try:
            finish = getattr(exc, "to_date", None) or getattr(exc, "finish", None) or getattr(exc, "end_date", None)
        except Exception:
            finish = None
        sd = _get_date(start)
        fd = _get_date(finish) or sd
        if sd is None:
            return []
        if fd is None:
            fd = sd
        if fd < sd:
            sd, fd = fd, sd
        out = []
        cur = sd
        while cur <= fd:
            out.append(cur)
            cur = cur + _dt.timedelta(days=1)
        return out

    for cal in calendars:
        try:
            exceptions = list(getattr(cal, "exceptions", []) or [])
        except Exception:
            exceptions = []
        for exc in exceptions:
            try:
                if not _is_non_working_exception(exc):
                    continue
            except Exception:
                continue
            for d in _iter_exc_dates(exc):
                try:
                    dates.add(d.isoformat())
                except Exception:
                    continue

    out = sorted(dates)
    return out

@app.post("/api/settings/calendar/upload-mpp")
async def upload_calendar_mpp(file: UploadFile = File(...)):
    if not file.filename or not _is_allowed(file.filename, file.content_type):
        raise HTTPException(status_code=400, detail="Требуется файл MS Project: .mpp, .mpt, .mpx, .xml")
    data = await file.read()
    suffix = Path(file.filename).suffix.lower() if file.filename else ""
    if suffix not in ALLOWED_EXTS:
        suffix = ".mpp"
    tmp_path = TMP_DIR / f"{uuid.uuid4().hex}{suffix}"
    with tmp_path.open("wb") as out:
        out.write(data)

    tmp_copy = None
    try:
        prj, tmp_copy = _aspose_open_project(tmp_path)
        holidays = _extract_holidays_from_project(prj)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Не удалось разобрать MPP: {e}")
    finally:
        try:
            if tmp_copy and tmp_copy.exists():
                tmp_copy.unlink()
        except Exception:
            pass
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

    current = _load_work_calendar()
    cal = _normalize_calendar_data(current)
    cal["holidays"] = holidays
    cal["holidaySource"] = {
        "fileName": file.filename,
        "uploadedAt": datetime.utcnow().isoformat(),
        "count": len(holidays),
    }
    cal = _save_calendar_data(cal)
    years = sorted({int(d[:4]) for d in holidays if isinstance(d, str) and len(d) >= 4 and d[:4].isdigit()})
    return {"ok": True, "calendar": cal, "years": years}

ALLOWED_EXTS = {".mpp", ".mpt", ".mpx", ".xml"}
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "storage" / "projects"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR = Path(__file__).resolve().parent.parent / "storage" / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

def _is_allowed(name: str, content_type: str | None) -> bool:
    ext = Path(name).suffix.lower()
    if ext in ALLOWED_EXTS:
        return True
    if content_type == "application/vnd.ms-project":
        return True
    return False

def _ensure_db_schema():
    try:
        Base.metadata.create_all(engine)
        _ensure_project_meta_author_column()
        _ensure_project_meta_actual_finish_column()
    except UnicodeDecodeError as e:
        raise RuntimeError(
            "Ошибка кодировки при подключении к Postgres. "
            "Проверь переменные окружения DATABASE_URL/PG* и задай их заново только ASCII-символами. "
            "Если Postgres настроен с WIN1251, попробуй задать $env:PGCLIENTENCODING='WIN1251' или перевести кластер/БД на UTF8."
        ) from e
    except Exception as e:
        try:
            from sqlalchemy.exc import OperationalError
        except Exception:
            OperationalError = None
        if OperationalError is not None and isinstance(e, OperationalError):
            msg = str(getattr(e, "orig", e))
            if "connection refused" in msg.lower() or "could not connect to server" in msg.lower():
                raise RuntimeError(
                    "Postgres недоступен (соединение отклонено). Запусти сервер Postgres и проверь порт 5432."
                ) from e
            if "no password supplied" in msg or "password authentication failed" in msg:
                raise RuntimeError(
                    "Postgres требует пароль. Установи PGPASSWORD или DATABASE_URL и перезапусти backend."
                ) from e
        raise

def _ensure_project_meta_author_column():
    try:
        with engine.begin() as conn:
            if engine.dialect.name == "sqlite":
                rows = conn.execute(text("PRAGMA table_info(project_meta)")).fetchall()
                cols = {r[1] for r in rows}
                if "author" not in cols:
                    conn.execute(text("ALTER TABLE project_meta ADD COLUMN author VARCHAR"))
            else:
                conn.execute(text("ALTER TABLE project_meta ADD COLUMN IF NOT EXISTS author VARCHAR"))
    except Exception:
        pass

def _ensure_project_meta_actual_finish_column():
    try:
        with engine.begin() as conn:
            if engine.dialect.name == "sqlite":
                rows = conn.execute(text("PRAGMA table_info(project_meta)")).fetchall()
                cols = {r[1] for r in rows}
                if "actual_finish_date" not in cols:
                    conn.execute(text("ALTER TABLE project_meta ADD COLUMN actual_finish_date DATETIME"))
            else:
                conn.execute(text("ALTER TABLE project_meta ADD COLUMN IF NOT EXISTS actual_finish_date TIMESTAMP"))
    except Exception:
        pass

_aspose_probe_done = False
_aspose_available = False
_aspose_error = None

def _probe_aspose():
    global _aspose_probe_done, _aspose_available, _aspose_error
    if _aspose_probe_done:
        return _aspose_available, _aspose_error
    try:
        code = "import aspose.tasks as at; print(getattr(at, '__version__', 'ok'))"
        res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        if res.returncode == 0:
            _aspose_available = True
            _aspose_error = None
        else:
            _aspose_available = False
            err = (res.stderr or res.stdout or "").strip()
            if not err:
                err = f"import_failed_code_{res.returncode}"
            _aspose_error = err
    except Exception as e:
        _aspose_available = False
        _aspose_error = str(e)
    _aspose_probe_done = True
    return _aspose_available, _aspose_error

def _ensure_aspose_available():
    ok, err = _probe_aspose()
    if not ok:
        raise RuntimeError(f"Aspose.Tasks недоступен: {err or 'unknown_error'}")

def _get_aspose_tasks():
    _ensure_aspose_available()
    import aspose.tasks as at
    return at

def _apply_aspose_license():
    try:
        at = _get_aspose_tasks()
        lic = at.License()
        candidate = Path(__file__).resolve().parent.parent / 'Aspose.Tasks.lic'
        if candidate.exists():
            lic.set_license(str(candidate))
    except Exception:
        pass

_apply_aspose_license()

def safe_date(v):
    try:
        if v is None:
            return None
        if hasattr(v, 'isoformat'):
            return v.isoformat()
        return str(v)
    except Exception:
        return None

def _aspose_open_project(path: Path):
    at = _get_aspose_tasks()
    src = path
    tmp_copy = None
    try:
        if any(ord(ch) > 127 for ch in str(src)):
            tmp_copy = TMP_DIR / f"{uuid.uuid4().hex}{src.suffix or ''}"
            shutil.copyfile(str(src), str(tmp_copy))
            return at.Project(str(tmp_copy)), tmp_copy
        return at.Project(str(src)), None
    except Exception:
        if tmp_copy and tmp_copy.exists():
            try:
                tmp_copy.unlink()
            except Exception:
                pass
        raise

def parse_project_meta_aspose(path: Path) -> Optional[dict]:
    try:
        prj, tmp_copy = _aspose_open_project(path)
    except Exception:
        return None
    name = None
    percent = None
    author = None
    try:
        name = getattr(prj, 'name', None)
    except Exception:
        name = None
    try:
        if not name:
            name = getattr(prj.root_task, 'name', None)
    except Exception:
        pass
    try:
        percent = getattr(prj.root_task, 'percent_complete', None)
    except Exception:
        percent = None
    try:
        author = getattr(prj, 'author', None)
    except Exception:
        author = None
    if not author:
        try:
            at = _get_aspose_tasks()
            author = prj.get(at.Prj.AUTHOR)
        except Exception:
            author = author
    resources_set = set()
    try:
        for r in getattr(prj, 'resources', []):
            rn = getattr(r, 'name', None)
            if rn:
                resources_set.add(rn)
    except Exception:
        pass
    if not resources_set:
        try:
            for a in getattr(prj, 'resource_assignments', []):
                try:
                    res = getattr(a, 'resource', None)
                    rn = getattr(res, 'name', None) if res else None
                    if rn:
                        resources_set.add(rn)
                except Exception:
                    continue
        except Exception:
            pass
    start_date = None
    finish_date = None
    try:
        start_date = getattr(prj, 'start_date', None)
        finish_date = getattr(prj, 'finish_date', None)
    except Exception:
        start_date = None
        finish_date = None

    min_start = None
    max_finish = None
    max_actual_finish = None
    res_from_tasks = set()
    pc_sum = 0.0
    pc_cnt = 0
    try:
        at = _get_aspose_tasks()
        stack = list(getattr(prj.root_task, 'children', []))
        while stack:
            t = stack.pop()
            try:
                for ch in getattr(t, 'children', []):
                    stack.append(ch)
            except Exception:
                pass
            sd = getattr(t, 'start', None)
            fd = getattr(t, 'finish', None)
            if sd is not None:
                if min_start is None or sd < min_start:
                    min_start = sd
            if fd is not None:
                if max_finish is None or fd > max_finish:
                    max_finish = fd
            af = None
            try:
                af = t.get(at.Tsk.ACTUAL_FINISH)
            except Exception:
                af = getattr(t, 'actual_finish', None)
            if af is not None:
                try:
                    if max_actual_finish is None or af > max_actual_finish:
                        max_actual_finish = af
                except Exception:
                    pass
            rn_str = getattr(t, 'resource_names', None)
            if rn_str:
                for n in str(rn_str).split(','):
                    nn = n.strip()
                    if nn:
                        res_from_tasks.add(nn)
            pc_val = getattr(t, 'percent_complete', None)
            if pc_val is not None:
                try:
                    pc_sum += float(pc_val)
                    pc_cnt += 1
                except Exception:
                    pass
    except Exception:
        pass
    if start_date is None and min_start is not None:
        start_date = min_start
    if finish_date is None and max_finish is not None:
        finish_date = max_finish
    if not resources_set and res_from_tasks:
        resources_set = res_from_tasks
    if percent is None and pc_cnt > 0:
        percent = pc_sum / pc_cnt
    meta = {
        'name': name,
        'author': author,
        'resources': ', '.join(sorted(resources_set)) if resources_set else None,
        'start_date': start_date,
        'finish_date': finish_date,
        'actual_finish_date': max_actual_finish,
        'percent_complete': percent,
    }
    if tmp_copy and tmp_copy.exists():
        try:
            tmp_copy.unlink()
        except Exception:
            pass
    return meta

def parse_project_meta_xml(path: Path) -> Optional[dict]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        tag = root.tag
        ns = None
        if tag.startswith('{'):
            ns = tag[1:tag.index('}')]
        def q(t: str) -> str:
            return f"{{{ns}}}{t}" if ns else t

        pn_el = root.find(q('Name'))
        pa_el = root.find(q('Author'))
        ps_el = root.find(q('StartDate'))
        pf_el = root.find(q('FinishDate'))

        name = pn_el.text if pn_el is not None else None
        author = pa_el.text if pa_el is not None else None
        percent = None

        min_start = None
        max_finish = None
        percent_sum = 0.0
        percent_count = 0
        max_actual_finish = None
        res_from_tasks: set[str] = set()
        tasks_el = root.find(q('Tasks'))
        if tasks_el is not None:
            for t in tasks_el.findall(q('Task')):
                s = t.find(q('Summary'))
                ol = t.find(q('OutlineLevel'))
                if s is not None and s.text in ('1','True','true') and ol is not None and ol.text in ('1','0'):
                    n = t.find(q('Name'))
                    pc = t.find(q('PercentComplete'))
                    if n is not None and n.text:
                        name = n.text
                    if pc is not None and pc.text:
                        try:
                            percent = float(pc.text)
                        except Exception:
                            percent = None
                st = t.find(q('Start'))
                fn = t.find(q('Finish'))
                af = t.find(q('ActualFinish'))
                def parse_dt_xml(s):
                    from datetime import datetime
                    if not s:
                        return None
                    try:
                        s2 = s.replace('Z','+00:00')
                        return datetime.fromisoformat(s2)
                    except Exception:
                        return None
                if st is not None and st.text:
                    sd = parse_dt_xml(st.text)
                    if sd is not None and (min_start is None or sd < min_start):
                        min_start = sd
                if fn is not None and fn.text:
                    fd = parse_dt_xml(fn.text)
                    if fd is not None and (max_finish is None or fd > max_finish):
                        max_finish = fd
                if af is not None and af.text:
                    ad = parse_dt_xml(af.text)
                    if ad is not None and (max_actual_finish is None or ad > max_actual_finish):
                        max_actual_finish = ad
                rn = t.find(q('ResourceNames'))
                if rn is not None and rn.text:
                    for part in rn.text.split(','):
                        nm = part.strip()
                        if nm:
                            res_from_tasks.add(nm)
                pc = t.find(q('PercentComplete'))
                if pc is not None and pc.text:
                    try:
                        percent_sum += float(pc.text)
                        percent_count += 1
                    except Exception:
                        pass

        resources = None
        resources_el = root.find(q('Resources'))
        if resources_el is not None:
            names = []
            for r in resources_el.findall(q('Resource')):
                n = r.find(q('Name'))
                if n is not None and n.text:
                    names.append(n.text)
            if names:
                resources = ', '.join(sorted(set(names)))
        if not resources and res_from_tasks:
            resources = ', '.join(sorted(res_from_tasks))

        from datetime import datetime
        def parse_dt(s):
            if not s:
                return None
            try:
                s2 = s.replace('Z','+00:00')
                return datetime.fromisoformat(s2)
            except Exception:
                return None

        start_dt = parse_dt(ps_el.text if ps_el is not None else None)
        finish_dt = parse_dt(pf_el.text if pf_el is not None else None)
        if start_dt is None and min_start is not None:
            start_dt = min_start
        if finish_dt is None and max_finish is not None:
            finish_dt = max_finish
        if percent is None and percent_count > 0:
            percent = percent_sum / percent_count
        return {
            'name': name,
            'author': author,
            'resources': resources,
            'start_date': start_dt,
            'finish_date': finish_dt,
            'actual_finish_date': max_actual_finish,
            'percent_complete': percent,
        }
    except Exception:
        return None

def parse_project_meta(path: Path) -> Optional[dict]:
    if path.suffix.lower() == '.xml':
        return parse_project_meta_xml(path)
    try:
        meta = parse_project_meta_aspose(path)
        if meta:
            needs_xml = (
                meta.get('resources') is None or
                meta.get('start_date') is None or
                meta.get('finish_date') is None or
                meta.get('percent_complete') is None or
                meta.get('author') is None
            )
            if not needs_xml:
                return meta
            try:
                at = _get_aspose_tasks()
                prj, tmp_copy = _aspose_open_project(path)
                tmp_xml = TMP_DIR / f"{uuid.uuid4().hex}.xml"
                try:
                    prj.save(str(tmp_xml), at.SaveFileFormat.XML)
                    xml_meta = parse_project_meta_xml(tmp_xml)
                finally:
                    try:
                        if tmp_xml.exists():
                            tmp_xml.unlink()
                        if 'tmp_copy' in locals() and tmp_copy and tmp_copy.exists():
                            tmp_copy.unlink()
                    except Exception:
                        pass
                if xml_meta:
                    return {
                        'name': meta.get('name') or xml_meta.get('name'),
                        'author': meta.get('author') or xml_meta.get('author'),
                        'resources': meta.get('resources') or xml_meta.get('resources'),
                        'start_date': meta.get('start_date') or xml_meta.get('start_date'),
                        'finish_date': meta.get('finish_date') or xml_meta.get('finish_date'),
                        'percent_complete': meta.get('percent_complete') or xml_meta.get('percent_complete'),
                    }
                return meta
            except Exception:
                return meta
    except Exception:
        pass

def _parse_overdue_tasks_xml(path: Path) -> list[dict]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        tag = root.tag
        ns = None
        if tag.startswith('{'):
            ns = tag[1:tag.index('}')]
        def q(t: str) -> str:
            return f"{{{ns}}}{t}" if ns else t
        def parse_dt_xml(s: str):
            if not s:
                return None
            try:
                s2 = s.replace('Z','+00:00')
                return _dt.datetime.fromisoformat(s2)
            except Exception:
                return None
        today = _dt.date.today()
        tasks_el = root.find(q('Tasks'))
        items: list[dict] = []
        if tasks_el is not None:
            for t in tasks_el.findall(q('Task')):
                s = t.find(q('Summary'))
                if s is not None and s.text in ('1','True','true'):
                    continue
                n = t.find(q('Name'))
                name = n.text if n is not None else None
                if not name:
                    continue
                fn = t.find(q('Finish'))
                dl = t.find(q('Deadline'))
                finish_dt = parse_dt_xml(fn.text if fn is not None else None)
                if finish_dt is None:
                    finish_dt = parse_dt_xml(dl.text if dl is not None else None)
                if finish_dt is None:
                    continue
                if finish_dt.date() >= today:
                    continue
                pc = t.find(q('PercentComplete'))
                pc_val = None
                if pc is not None and pc.text:
                    try:
                        pc_val = float(pc.text)
                    except Exception:
                        pc_val = None
                if pc_val is not None and pc_val >= 100:
                    continue
                items.append({
                    "name": name,
                    "finishDate": finish_dt.isoformat(),
                    "percentComplete": pc_val,
                })
        items.sort(key=lambda x: x.get("finishDate") or "")
        return items
    except Exception:
        return []

def _normalize_dt(v):
    try:
        if v is None:
            return None
        if isinstance(v, _dt.datetime):
            return v
        if isinstance(v, _dt.date):
            return _dt.datetime.combine(v, _dt.datetime.min.time())
        s = str(v)
        if not s:
            return None
        s2 = s.replace('Z','+00:00')
        return _dt.datetime.fromisoformat(s2)
    except Exception:
        return None

def _normalize_percent(v):
    try:
        if v is None:
            return None
        f = float(v)
        if f < 0:
            f = 0.0
        # Auto-detect scale: if <= 1.0 treat as 0..1, else assume 0..100
        return f * 100.0 if f <= 1.0 else f
    except Exception:
        return None

def _parse_overdue_tasks_aspose(path: Path) -> list[dict]:
    at = _get_aspose_tasks()
    prj, tmp_copy = _aspose_open_project(path)
    try:
        today = _dt.date.today()
        items: list[dict] = []
        try:
            iterable = getattr(prj, 'tasks', None)
        except Exception:
            iterable = None
        if iterable is not None:
            for t in iterable:
                try:
                    summary = t.get(at.Tsk.SUMMARY)
                except Exception:
                    summary = getattr(t, 'summary', None)
                if summary in (1, True, '1', 'true', 'True'):
                    continue
                # prefer status detection if available
                status = None
                try:
                    status = t.get(at.Tsk.STATUS)
                except Exception:
                    status = getattr(t, 'status', None)
                is_late = False
                try:
                    is_late = (status == getattr(at.TaskStatus, 'LATE', 2)) or (status == 2) or (str(status).upper().endswith('LATE'))
                except Exception:
                    is_late = (status == 2)
                # fallback via date comparison
                if not is_late:
                    try:
                        finish = t.get(at.Tsk.FINISH)
                    except Exception:
                        finish = getattr(t, 'finish', None)
                    finish_dt = _normalize_dt(finish)
                    if finish_dt is None:
                        try:
                            deadline = t.get(at.Tsk.DEADLINE)
                        except Exception:
                            deadline = getattr(t, 'deadline', None)
                        finish_dt = _normalize_dt(deadline)
                    if finish_dt is None or finish_dt.date() >= today:
                        continue
                # percent complete filter
                pc = None
                try:
                    pc = t.get(at.Tsk.PERCENT_COMPLETE)
                except Exception:
                    pc = getattr(t, 'percent_complete', None)
                pc_val = _normalize_percent(pc)
                if pc_val is not None and pc_val >= 100.0:
                    continue
                try:
                    name = t.get(at.Tsk.NAME)
                except Exception:
                    name = getattr(t, 'name', None)
                try:
                    finish = t.get(at.Tsk.FINISH)
                except Exception:
                    finish = getattr(t, 'finish', None)
                finish_dt = _normalize_dt(finish)
                if finish_dt is None:
                    try:
                        deadline = t.get(at.Tsk.DEADLINE)
                    except Exception:
                        deadline = getattr(t, 'deadline', None)
                    finish_dt = _normalize_dt(deadline)
                items.append({
                    "name": str(name) if name is not None else None,
                    "finishDate": finish_dt.isoformat() if finish_dt else None,
                    "percentComplete": pc_val,
                })
        else:
            # Fallback: iterate through root_task children recursively
            def iter_children(task):
                coll = None
                try:
                    coll = getattr(task, 'children', None)
                except Exception:
                    coll = None
                if coll is None:
                    try:
                        coll = task.get_children()
                    except Exception:
                        coll = None
                if coll is None:
                    return []
                try:
                    return list(coll)
                except Exception:
                    pass
                out = []
                try:
                    count = getattr(coll, 'count', None) or getattr(coll, 'size', None) or (len(coll) if hasattr(coll, '__len__') else 0)
                    for i in range(int(count or 0)):
                        it = None
                        try:
                            it = coll[i]
                        except Exception:
                            try:
                                it = coll.get_Item(i)
                            except Exception:
                                it = None
                        if it is not None:
                            out.append(it)
                except Exception:
                    pass
                return out
            stack = []
            try:
                root = getattr(prj, 'root_task', None)
            except Exception:
                root = None
            if root is not None:
                stack.extend(iter_children(root))
            while stack:
                t = stack.pop()
                try:
                    for ch in iter_children(t):
                        stack.append(ch)
                except Exception:
                    pass
                try:
                    summary = t.get(at.Tsk.SUMMARY)
                except Exception:
                    summary = getattr(t, 'is_summary', None)
                if summary in (1, True, '1', 'true', 'True'):
                    continue
                status = None
                try:
                    status = t.get(at.Tsk.STATUS)
                except Exception:
                    status = getattr(t, 'status', None)
                is_late = False
                try:
                    is_late = (status == getattr(at.TaskStatus, 'LATE', 2)) or (status == 2) or (str(status).upper().endswith('LATE'))
                except Exception:
                    is_late = (status == 2)
                if not is_late:
                    try:
                        finish = t.get(at.Tsk.FINISH)
                    except Exception:
                        finish = getattr(t, 'finish', None)
                    finish_dt = _normalize_dt(finish)
                    if finish_dt is None:
                        try:
                            deadline = t.get(at.Tsk.DEADLINE)
                        except Exception:
                            deadline = getattr(t, 'deadline', None)
                        finish_dt = _normalize_dt(deadline)
                    if finish_dt is None or finish_dt.date() >= today:
                        continue
                pc = None
                try:
                    pc = t.get(at.Tsk.PERCENT_COMPLETE)
                except Exception:
                    pc = getattr(t, 'percent_complete', None)
                pc_val = _normalize_percent(pc)
                if pc_val is not None and pc_val >= 100.0:
                    continue
                try:
                    name = t.get(at.Tsk.NAME)
                except Exception:
                    name = getattr(t, 'name', None)
                try:
                    finish = t.get(at.Tsk.FINISH)
                except Exception:
                    finish = getattr(t, 'finish', None)
                finish_dt = _normalize_dt(finish)
                if finish_dt is None:
                    try:
                        deadline = t.get(at.Tsk.DEADLINE)
                    except Exception:
                        deadline = getattr(t, 'deadline', None)
                    finish_dt = _normalize_dt(deadline)
                items.append({
                    "name": str(name) if name is not None else None,
                    "finishDate": finish_dt.isoformat() if finish_dt else None,
                    "percentComplete": pc_val,
                })
        items.sort(key=lambda x: x.get("finishDate") or "")
        if items:
            return items
    finally:
        if tmp_copy and tmp_copy.exists():
            try:
                tmp_copy.unlink()
            except Exception:
                pass
    try:
        at = _get_aspose_tasks()
        prj, tmp_copy = _aspose_open_project(path)
        tmp_xml = TMP_DIR / f"{uuid.uuid4().hex}.xml"
        try:
            prj.save(str(tmp_xml), at.SaveFileFormat.XML)
            return _parse_overdue_tasks_xml(tmp_xml)
        finally:
            try:
                if tmp_xml.exists():
                    tmp_xml.unlink()
                if 'tmp_copy' in locals() and tmp_copy and tmp_copy.exists():
                    tmp_copy.unlink()
            except Exception:
                pass
    except Exception:
        pass
    return []

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

@app.post("/api/projects/upload")
async def upload_projects(files: List[UploadFile] = File(...)):
    accepted: list[dict] = []
    rejected: list[dict] = []
    db = SessionLocal()
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
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    for p in stale_paths:
        try:
            pp = Path(p)
            if pp.exists():
                pp.unlink()
        except Exception:
            pass
    await ws_manager.broadcast({"type": "projects_changed"})
    return {"ok": True, "accepted": accepted, "rejected": rejected}

@app.get("/api/projects/files")
def list_project_files():
    db = SessionLocal()
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
            actual_finish = m.actual_finish_date
            if actual_finish is None:
                parsed = None
                try:
                    parsed = parse_project_meta(Path(item["stored_path"]))
                except Exception:
                    parsed = None
                if parsed and parsed.get("actual_finish_date"):
                    actual_finish = parsed.get("actual_finish_date")
                    try:
                        m.actual_finish_date = actual_finish
                        db.add(m)
                    except Exception:
                        pass
            try:
                if actual_finish is not None and getattr(actual_finish, "year", 1) < 1900:
                    actual_finish = None
            except Exception:
                pass
            item["project"] = {
                "name": m.name,
                "author": m.author,
                "resources": m.resources,
                "start_date": m.start_date.isoformat() if m.start_date else None,
                "finish_date": m.finish_date.isoformat() if m.finish_date else None,
                "actual_finish_date": actual_finish.isoformat() if actual_finish else None,
                "percent_complete": m.percent_complete,
            }
        else:
            meta = None
            try:
                meta = parse_project_meta(Path(item["stored_path"]))
            except Exception:
                meta = None
            if meta:
                sd = meta.get('start_date')
                fd = meta.get('finish_date')
                afd = meta.get('actual_finish_date')
                item["project"] = {
                    "name": meta.get('name'),
                    "author": meta.get('author'),
                    "resources": meta.get('resources'),
                    "start_date": sd.isoformat() if sd else None,
                    "finish_date": fd.isoformat() if fd else None,
                    "actual_finish_date": afd.isoformat() if afd else None,
                    "percent_complete": meta.get('percent_complete'),
                }
            else:
                try:
                    from pathlib import Path as _P
                    base = _P(item["original_name"]).stem
                    item["project"] = {
                        "name": base,
                        "author": None,
                        "resources": None,
                        "start_date": None,
                        "finish_date": None,
                        "actual_finish_date": None,
                        "percent_complete": None,
                    }
                except Exception:
                    item["project"] = None
    try:
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return {"items": data}

@app.get("/api/projects/overdue_tasks")
def project_overdue_tasks(file_id: int):
    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    db.close()
    if not pf:
        raise HTTPException(status_code=404, detail="not_found")
    p = Path(pf.stored_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="file_not_found")
    try:
        if p.suffix.lower() == '.xml':
            items = _parse_overdue_tasks_xml(p)
        else:
            items = _parse_overdue_tasks_aspose(p)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"parse_failed: {e}")
    return {"items": items, "count": len(items)}

@app.get("/api/projects/shift_tasks")
def project_shift_tasks(file_id: int, start: str, finish: str):
    def to_date(v: str):
        try:
            return _dt.date.fromisoformat(v)
        except Exception:
            return None

    s = to_date(start)
    f = to_date(finish)
    if s is None or f is None:
        raise HTTPException(status_code=400, detail="invalid_date")
    if f < s:
        raise HTTPException(status_code=400, detail="invalid_range")

    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not pf:
        db.close()
        raise HTTPException(status_code=404, detail="not_found")
    meta = db.query(ProjectMeta).filter(ProjectMeta.file_id == pf.id).order_by(ProjectMeta.created_at.desc()).first()
    db.close()

    p = Path(pf.stored_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="file_not_found")

    try:
        at = _get_aspose_tasks()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"aspose_unavailable: {e}")

    prj, tmpc = _aspose_open_project(p)
    try:
        proj_name = None
        try:
            proj_name = getattr(prj, "name", None)
        except Exception:
            proj_name = None
        if not proj_name:
            try:
                proj_name = prj.root_task.get(at.Tsk.NAME)
            except Exception:
                proj_name = None
        if not proj_name and meta:
            proj_name = meta.name
        if not proj_name:
            proj_name = pf.original_name

        proj_percent = None
        if meta:
            proj_percent = getattr(meta, "percent_complete", None)
        if proj_percent is None:
            try:
                proj_percent = prj.get(at.Prj.PERCENT_COMPLETE)
            except Exception:
                proj_percent = None
        if proj_percent is None:
            try:
                proj_percent = getattr(prj, "percent_complete", None)
            except Exception:
                proj_percent = None
        if proj_percent is None:
            try:
                proj_percent = getattr(prj.root_task, "percent_complete", None)
            except Exception:
                proj_percent = None

        proj_finish = safe_date(getattr(prj, "finish_date", None))
        range_start = _dt.datetime(s.year, s.month, s.day)
        range_end = _dt.datetime(f.year, f.month, f.day) + _dt.timedelta(days=1)

        by_res = _resource_check_collect(
            prj,
            at,
            range_start,
            range_end,
            0.0,
            project_info={
                "key": f"bank:{pf.id}",
                "name": proj_name,
                "fileId": pf.id,
                "source": "bank",
                "percentComplete": proj_percent,
                "finishDate": proj_finish,
            },
            allowed_resource_names=None,
        )
    finally:
        try:
            if tmpc and tmpc.exists():
                tmpc.unlink()
        except Exception:
            pass

    resources_out = []
    for rn, entry in (by_res or {}).items():
        tasks_map = entry.get("tasks") or {}
        tasks_out = list(tasks_map.values()) if isinstance(tasks_map, dict) else []
        tasks_out.sort(key=lambda x: ((x.get("start") or ""), (x.get("finish") or ""), str(x.get("name") or "")))
        resources_out.append(
            {
                "name": entry.get("name") or rn,
                "tasks": tasks_out,
            }
        )
    resources_out.sort(key=lambda x: str(x.get("name") or ""))

    return {
        "ok": True,
        "period": {"startDate": s.isoformat(), "finishDate": f.isoformat()},
        "project": {"name": proj_name, "percentComplete": proj_percent, "finishDate": proj_finish},
        "resources": resources_out,
    }

@app.get("/api/projects/debug_parse/{file_id}")
def debug_parse(file_id: int):
    import sys
    info: dict = {"python": sys.version, "aspose_import": False}
    ok, err = _probe_aspose()
    if ok:
        at = _get_aspose_tasks()
        info["aspose_import"] = True
        info["aspose_version"] = getattr(at, "__version__", None)
    else:
        info["aspose_error"] = err or "import_failed"
    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not pf:
        db.close()
        raise HTTPException(status_code=404, detail="not_found")
    p = Path(pf.stored_path)
    meta = None
    err = None
    try:
        meta = parse_project_meta(p)
    except Exception as e:
        err = str(e)
    at_open_ok = False
    at_open_err = None
    try:
        prj, tmpc = _aspose_open_project(p)
        at_open_ok = True
        try:
            at = _get_aspose_tasks()
            def sget(obj, prop):
                try:
                    return obj.get(prop)
                except Exception:
                    return None
            info["root_name"] = sget(prj.root_task, at.Tsk.NAME)
            info["root_percent"] = sget(prj.root_task, at.Tsk.PERCENT_COMPLETE)
            info["proj_start"] = sget(prj, at.Prj.START_DATE)
            info["proj_finish"] = sget(prj, at.Prj.FINISH_DATE)
            # counts
            rc = 0
            try:
                for _ in prj.resources:
                    rc += 1
            except Exception:
                rc = -1
            tc = 0
            try:
                for _ in prj.tasks:
                    tc += 1
            except Exception:
                tc = -1
            info["resources_count"] = rc
            info["tasks_count"] = tc
        except Exception:
            pass
        if tmpc and tmpc.exists():
            try: tmpc.unlink()
            except Exception: pass
    except Exception as e:
        at_open_err = str(e)
    db.close()
    if not meta:
        return {"ok": True, "file": pf.stored_name, "meta": None, "info": info | {"parse_error": err, "open_ok": at_open_ok, "open_error": at_open_err}}
    sd = meta.get('start_date')
    fd = meta.get('finish_date')
    return {
        "ok": True,
        "file": pf.stored_name,
        "meta": {
            "name": meta.get('name'),
            "resources": meta.get('resources'),
            "start_date": (sd.isoformat() if hasattr(sd, 'isoformat') else str(sd)) if sd else None,
            "finish_date": (fd.isoformat() if hasattr(fd, 'isoformat') else str(fd)) if fd else None,
            "percent_complete": meta.get('percent_complete'),
        },
        "info": info,
    }

@app.get("/api/projects/debug_tasks/{file_id}")
def debug_tasks(file_id: int):
    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    db.close()
    if not pf:
        raise HTTPException(status_code=404, detail="not_found")
    p = Path(pf.stored_path)
    out: dict = {}
    try:
        at = _get_aspose_tasks()
        prj, tmpc = _aspose_open_project(p)
        try:
            out["root_name"] = prj.root_task.get(at.Tsk.NAME)
        except Exception as e:
            out["root_name_error"] = str(e)
        try:
            out["proj_start"] = prj.get(at.Prj.START_DATE)
            out["proj_finish"] = prj.get(at.Prj.FINISH_DATE)
        except Exception as e:
            out["proj_dates_error"] = str(e)
        names = []
        cnt = 0
        for t in prj.tasks:
            try:
                n = t.get(at.Tsk.NAME)
            except Exception as e:
                out.setdefault("task_get_error", str(e))
                n = None
            if n:
                names.append(n)
                cnt += 1
                if cnt >= 10:
                    break
        out["tasks_sample"] = names
        rc_names = []
        try:
            for r in prj.resources:
                rn = r.get(at.Rsc.NAME)
                if rn:
                    rc_names.append(rn)
        except Exception:
            pass
        out["resources_sample"] = rc_names[:10]
        if tmpc and tmpc.exists():
            try: tmpc.unlink()
            except Exception: pass
    except Exception as e:
        out["error"] = str(e)
    return out

@app.get("/api/projects/debug_introspect/{file_id}")
def debug_introspect(file_id: int):
    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    db.close()
    if not pf:
        raise HTTPException(status_code=404, detail="not_found")
    p = Path(pf.stored_path)
    info: dict = {}
    try:
        at = _get_aspose_tasks()
        prj, tmpc = _aspose_open_project(p)
        def filt(keys):
            return sorted([k for k in keys if not k.startswith('_')])
        def pick(keys):
            return [k for k in keys if any(x in k.lower() for x in ["name","start","finish","percent","resource","tasks","children"])]
        info["project_keys"] = pick(filt(dir(prj)))
        info["root_task_keys"] = pick(filt(dir(prj.root_task)))
        try:
            first_task = None
            for t in prj.tasks:
                first_task = t
                break
            if first_task:
                info["task_keys"] = pick(filt(dir(first_task)))
        except Exception as e:
            info["iter_tasks_error"] = str(e)
        try:
            first_res = None
            for r in prj.resources:
                first_res = r
                break
            if first_res:
                info["resource_keys"] = pick(filt(dir(first_res)))
        except Exception:
            pass
        if tmpc and tmpc.exists():
            try: tmpc.unlink()
            except Exception: pass
    except Exception as e:
        info["error"] = str(e)
    return info

@app.delete("/api/projects/files/{file_id}")
async def delete_project_file(file_id: int):
    db = SessionLocal()
    pf = db.query(ProjectFile).filter(ProjectFile.id == file_id).first()
    if not pf:
        db.close()
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
    db.close()
    await ws_manager.broadcast({"type": "projects_changed"})
    return {"ok": True}
class WSManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)
    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)
    async def broadcast(self, payload: dict):
        data = json.dumps(payload)
        for ws in list(self.clients):
            try:
                await ws.send_text(data)
            except Exception:
                self.disconnect(ws)

ws_manager = WSManager()

@app.websocket('/ws/projects')
async def ws_projects(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

def parse_resources_hierarchy(path: Path) -> dict:
    try:
        at = _get_aspose_tasks()
        prj = at.Project(str(path))
        groups: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
        seen: set[tuple] = set()

        def add_resource(name, group, dept, position, rate):
            if not name:
                return
            rate_str = None
            try:
                rate_str = str(rate) if rate is not None else None
            except Exception:
                rate_str = None
            key = (
                (name or "").strip(),
                (group or ""),
                (dept or ""),
                (position or ""),
                (rate_str or ""),
            )
            if key in seen:
                return
            seen.add(key)
            g = group or ""
            d = dept or ""
            groups[g][d].append({
                "name": name,
                "position": position,
                "rate": rate_str,
            })

        dept_keywords = ('отдел', 'служба', 'цех', 'участок', 'производство', 'департамент', 'блок', 'группа')
        position_keywords = ('менеджер', 'начальник', 'инженер', 'специалист', 'мастер', 'директор', 'оператор', 'водитель', 'экономист', 'бухгалтер', 'технолог', 'кладовщик')
        for r in prj.resources:
            name = getattr(r, 'name', None)
            group = getattr(r, 'group', None)
            dept = getattr(r, 'cost_center', None)
            position = None
            rate = getattr(r, 'standard_rate', None)
            try:
                vals = []
                for ea in getattr(r, 'extended_attributes', []) or []:
                    v = None
                    try:
                        v = getattr(ea, 'text_value', None) or getattr(ea, 'value', None) or getattr(ea, 'numeric_value', None)
                    except Exception:
                        v = None
                    if v:
                        vals.append(str(v))
                for val in vals:
                    low = val.lower()
                    if not dept and any(k in low for k in dept_keywords):
                        dept = val
                    elif not position and any(k in low for k in position_keywords):
                        position = val
                if not dept and vals:
                    dept = vals[0]
                if not position and len(vals) > 1:
                    position = vals[1]
            except Exception:
                pass
            if not dept:
                try:
                    for oc in getattr(r, 'outline_codes', []) or []:
                        v = None
                        try:
                            v = getattr(oc, 'value', None)
                            if hasattr(v, 'value'):
                                v = getattr(v, 'value', None)
                        except Exception:
                            v = None
                        if v:
                            dept = str(v)
                            break
                except Exception:
                    pass
            add_resource(name, group, dept, position, rate)

        for a in prj.resource_assignments:
            res = getattr(a, 'resource', None)
            if not res:
                continue
            name = getattr(res, 'name', None)
            group = getattr(res, 'group', None)
            dept = getattr(res, 'cost_center', None)
            position = None
            rate = getattr(res, 'standard_rate', None)
            add_resource(name, group, dept, position, rate)

        if not groups:
            try:
                tmp_xml = TMP_DIR / f"{uuid.uuid4().hex}.xml"
                prj.save(str(tmp_xml), at.SaveFileFormat.XML)
                import xml.etree.ElementTree as ET
                root = ET.parse(tmp_xml).getroot()
                tag = root.tag
                ns = None
                if tag.startswith('{'):
                    ns = tag[1:tag.index('}')]
                def q(t: str) -> str:
                    return f"{{{ns}}}{t}" if ns else t
                resources_el = root.find(q('Resources'))
                if resources_el is not None:
                    for r in resources_el.findall(q('Resource')):
                        n_el = r.find(q('Name'))
                        g_el = r.find(q('Group'))
                        t1_el = r.find(q('Text1'))
                        t2_el = r.find(q('Text2'))
                        t3_el = r.find(q('Text3'))
                        rate_el = r.find(q('StandardRate'))
                        name = n_el.text if n_el is not None else None
                        group = g_el.text if g_el is not None else None
                        dept = None
                        for el in (t1_el, t2_el, t3_el):
                            if el is not None and el.text:
                                dept = el.text
                                break
                        position = None
                        for el in (t2_el, t3_el):
                            if el is not None and el.text:
                                position = el.text
                                break
                        rate_val = None
                        if rate_el is not None and rate_el.text:
                            try:
                                rate_val = rate_el.text
                            except Exception:
                                rate_val = None
                        add_resource(name, group, dept, position, rate_val)
            finally:
                try:
                    if 'tmp_xml' in locals() and tmp_xml.exists():
                        tmp_xml.unlink()
                except Exception:
                    pass

        out = []
        for gname, depts in groups.items():
            ds = []
            for dname, res_list in depts.items():
                res_list_sorted = sorted(res_list, key=lambda x: (x.get("name") or ""))
                ds.append({"name": dname, "resources": res_list_sorted})
            ds_sorted = sorted(ds, key=lambda x: (x.get("name") or ""))
            out.append({"name": gname, "departments": ds_sorted})
        out_sorted = sorted(out, key=lambda x: (x.get("name") or ""))
        return {"groups": out_sorted}
    except Exception:
        return {"groups": []}

@app.post("/api/analyze-msproject")
async def analyze_msproject(file: UploadFile = File(...)):
    try:
        tsk = _get_aspose_tasks()
        Project = tsk.Project
        ConstraintType = tsk.ConstraintType
        TimeUnitType = tsk.TimeUnitType
        BaselineType = tsk.BaselineType
    except Exception as e:
        return {
            "error": str(e),
            "projectName": None,
            "projectManager": None,
            "projectCurator": None,
            "projectPercentComplete": None,
            "overview": None,
            "overdueTasksZeroPercent": [],
            "missingPredecessorsTasks": [],
            "invalidConstraintTasks": [],
            "longDurationTasks": [],
            "summaryTasksLongerThanMonth": [],
            "baselines": [],
            "projectFinishDeviationDays": None,
            "projectStartDate": None,
            "projectFinishDate": None,
        }
    if not file.filename or not file.filename.lower().endswith('.mpp'):
        raise HTTPException(status_code=400, detail="Требуется файл MS Project с расширением .mpp")
    data = await file.read()
    tmp_path = TMP_DIR / f"{uuid.uuid4().hex}.mpp"
    with tmp_path.open('wb') as out:
        out.write(data)
    try:
        project = Project(str(tmp_path))
    except Exception as e:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        return {"error": f"Failed to open project: {e}"}

    name = getattr(project, "name", None)
    manager = getattr(project, "manager", None)
    curator = None
    try:
        custom_props = getattr(project, "custom_props", None)
        if custom_props is not None:
            try:
                keys = list(custom_props.keys()) if hasattr(custom_props, "keys") else []
                for k in keys:
                    kl = str(k).lower()
                    if kl in ("curator", "куратор"):
                        try:
                            curator = str(custom_props[k])
                        except Exception:
                            curator = None
                        break
            except Exception:
                pass
    except Exception:
        pass

    root = getattr(project, "root_task", None)
    percent_complete = None
    if root is not None:
        try:
            percent_complete = getattr(root, "percent_complete", None)
        except Exception:
            percent_complete = None

    def children(task):
        try:
            return list(task.children)
        except Exception:
            try:
                return list(task.get_children())
            except Exception:
                return []

    tasks = []
    if root is not None:
        stack = children(root)
        while stack:
            t = stack.pop(0)
            tasks.append(t)
            stack[0:0] = children(t)

    today = _dt.datetime.now().date()
    task_by_id = {}
    for _t in tasks:
        try:
            tid = getattr(_t, "id", None)
        except Exception:
            tid = None
        if tid is not None:
            task_by_id[tid] = _t

    def is_summary(t):
        try:
            return bool(getattr(t, "is_summary", False))
        except Exception:
            return False

    def is_inactive(t):
        try:
            a = getattr(t, "active", None)
            if a is not None:
                return not bool(a)
        except Exception:
            pass
        try:
            ia = getattr(t, "is_active", None)
            if ia is not None:
                return not bool(ia)
        except Exception:
            pass
        try:
            ina = getattr(t, "is_inactive", None)
            if ina is not None:
                return bool(ina)
        except Exception:
            pass
        return False

    overdue_zero = []
    for t in tasks:
        if is_summary(t):
            continue
        pc = getattr(t, "percent_complete", 0) or 0
        finish = getattr(t, "finish", None)
        fid = getattr(t, "id", None)
        name_t = getattr(t, "name", None)
        try:
            fdate = finish.date() if isinstance(finish, _dt.datetime) else finish
        except Exception:
            fdate = None
        if pc == 0 and fdate and fdate < today:
            overdue_zero.append({"id": fid, "name": name_t, "finish": safe_date(finish), "percentComplete": pc})

    missing_pred = []
    for t in tasks:
        if is_summary(t):
            continue
        try:
            if bool(getattr(t, "is_recurring", False)):
                continue
        except Exception:
            pass
        preds = getattr(t, "predecessors", None)
        count = 0
        try:
            count = len(list(preds)) if preds is not None else 0
        except Exception:
            count = getattr(preds, "count", 0) if preds is not None else 0
        is_milestone = bool(getattr(t, "is_milestone", False))
        if count == 0 and not is_milestone:
            missing_pred.append({
                "id": getattr(t, "id", None),
                "name": getattr(t, "name", None),
                "start": safe_date(getattr(t, "start", None)),
                "finish": safe_date(getattr(t, "finish", None)),
                "percentComplete": getattr(t, "percent_complete", 0) or 0,
            })

    invalid_constraints = []
    for t in tasks:
        if is_summary(t):
            continue
        ct = getattr(t, "constraint_type", None)
        if ct is not None:
            try:
                if ct != ConstraintType.AS_SOON_AS_POSSIBLE:
                    invalid_constraints.append({
                        "id": getattr(t, "id", None),
                        "name": getattr(t, "name", None),
                        "constraint": str(ct),
                        "start": safe_date(getattr(t, "start", None)),
                        "finish": safe_date(getattr(t, "finish", None)),
                        "percentComplete": getattr(t, "percent_complete", 0) or 0,
                    })
            except Exception:
                pass

    succ_missing = []
    rev_index = {}
    for t in tasks:
        preds = getattr(t, "predecessors", None)
        try:
            links = list(preds) if preds is not None else []
        except Exception:
            links = []
        for l in links:
            try:
                pid = getattr(getattr(l, "source_task", None), "id", None)
            except Exception:
                pid = None
            if pid is not None:
                rev_index.setdefault(pid, 0)
                rev_index[pid] += 1
    for t in tasks:
        if is_summary(t):
            continue
        try:
            if bool(getattr(t, "is_recurring", False)):
                continue
        except Exception:
            pass
        is_milestone = bool(getattr(t, "is_milestone", False))
        if is_milestone:
            continue
        tid = getattr(t, "id", None)
        if rev_index.get(tid, 0) == 0:
            succ_missing.append({
                "id": tid,
                "name": getattr(t, "name", None),
                "start": safe_date(getattr(t, "start", None)),
                "finish": safe_date(getattr(t, "finish", None)),
                "percentComplete": getattr(t, "percent_complete", 0) or 0,
            })

    def duration_days(d) -> float:
        if d is None:
            return 0.0
        try:
            return d.convert(TimeUnitType.DAY).to_double()
        except Exception:
            try:
                unit = getattr(d, "time_unit", None)
                val = float(getattr(d, "to_double", lambda: 0.0)())
                if unit in (TimeUnitType.DAY, TimeUnitType.DAY_ESTIMATED):
                    return val
                if unit in (TimeUnitType.HOUR, TimeUnitType.HOUR_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    return (val * 60.0) / mpd
                if unit in (TimeUnitType.MINUTE, TimeUnitType.MINUTE_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    return val / mpd
                if unit in (TimeUnitType.WEEK, TimeUnitType.WEEK_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    mpw = float(getattr(project, "minutes_per_week", 2400))
                    return val * (mpw / mpd)
                return 0.0
            except Exception:
                return 0.0

    long_duration = []
    for t in tasks:
        if is_summary(t):
            continue
        dur = getattr(t, "duration", None)
        if duration_days(dur) > 10:
            long_duration.append({
                "id": getattr(t, "id", None),
                "name": getattr(t, "name", None),
                "durationDays": duration_days(dur),
                "start": safe_date(getattr(t, "start", None)),
                "finish": safe_date(getattr(t, "finish", None)),
                "percentComplete": getattr(t, "percent_complete", 0) or 0,
            })

    summary_long_month = []
    for t in tasks:
        if not is_summary(t):
            continue
        start = getattr(t, "start", None)
        finish = getattr(t, "finish", None)
        if start and finish:
            try:
                diff = (finish - start).days
            except Exception:
                diff = 0
            if diff > 31:
                summary_long_month.append({"id": getattr(t, "id", None), "name": getattr(t, "name", None), "start": safe_date(start), "finish": safe_date(finish), "percentComplete": getattr(t, "percent_complete", 0) or 0})

    missing_after_summary = []
    root_id = getattr(root, "id", None)
    for t in tasks:
        if not is_summary(t):
            continue
        if root_id is not None and getattr(t, "id", None) == root_id:
            continue
        ch = children(t)
        has_council = False
        has_zero_milestone = False
        zero_m_id = None
        zero_m_name = None
        for c in ch:
            nm = str(getattr(c, "name", "") or "")
            if nm.strip().lower() == "совет по качеству":
                has_council = True
            dur = getattr(c, "duration", None)
            is_m = bool(getattr(c, "is_milestone", False))
            if is_m and duration_days(dur) == 0:
                has_zero_milestone = True
                zero_m_id = getattr(c, "id", None)
                zero_m_name = getattr(c, "name", None)
        if not has_council or not has_zero_milestone:
            missing_after_summary.append({
                "summaryId": getattr(t, "id", None),
                "summaryName": getattr(t, "name", None),
                "summaryStart": safe_date(getattr(t, "start", None)),
                "summaryFinish": safe_date(getattr(t, "finish", None)),
                "missingCouncil": not has_council,
                "missingZeroMilestone": not has_zero_milestone,
                "zeroMilestoneId": zero_m_id,
                "zeroMilestoneName": zero_m_name,
                "summaryPercentComplete": getattr(t, "percent_complete", 0) or 0,
            })
    quality_council_check = {"missingAfterSummary": missing_after_summary}

    baselines = []
    start_date = getattr(project, "start_date", None)
    finish_date = getattr(project, "finish_date", None)
    deviation_days = None

    last_bl_finish_dt = None
    root_baselines = []
    try:
        rb = getattr(root, "baselines", None)
        root_baselines = list(rb) if rb is not None else []
    except Exception:
        root_baselines = []

    def baseline_save_time_by_index(idx: int):
        bt = None
        try:
            bt = getattr(BaselineType, "BASELINE") if idx == 0 else getattr(BaselineType, f"BASELINE{idx}")
        except Exception:
            bt = None
        if bt is None:
            try:
                bt = getattr(BaselineType, "Baseline") if idx == 0 else getattr(BaselineType, f"Baseline{idx}")
            except Exception:
                bt = None
        if bt is None:
            return None
        try:
            return project.get_baseline_save_time(bt)
        except Exception:
            try:
                return project.GetBaselineSaveTime(bt)
            except Exception:
                return None

    if root_baselines:
        for idx, bl in enumerate(root_baselines):
            bfinish = getattr(bl, "finish", None)
            baselines.append({
                "name": "Baseline" if idx == 0 else f"Baseline{idx}",
                "created": safe_date(baseline_save_time_by_index(idx)),
                "finish": safe_date(bfinish),
            })
        try:
            last_bl_finish_dt = getattr(root_baselines[-1], "finish", None)
        except Exception:
            last_bl_finish_dt = None
    else:
        by_index = {}
        for t in tasks:
            tbls = []
            try:
                tbls = list(getattr(t, "baselines", None) or [])
            except Exception:
                tbls = []
            for idx, bl in enumerate(tbls):
                bfinish = getattr(bl, "finish", None)
                if idx not in by_index:
                    by_index[idx] = []
                by_index[idx].append(bfinish)
        for idx in sorted(by_index.keys()):
            finishes = by_index[idx]
            best_finish = None
            for f in finishes:
                try:
                    if f is not None and (best_finish is None or f > best_finish):
                        best_finish = f
                except Exception:
                    pass
            baselines.append({
                "name": "Baseline" if idx == 0 else f"Baseline{idx}",
                "created": safe_date(baseline_save_time_by_index(idx)),
                "finish": safe_date(best_finish),
            })
        try:
            if baselines:
                last_idx = max(by_index.keys()) if by_index else None
                if last_idx is not None:
                    finishes = by_index.get(last_idx) or []
                    for f in finishes:
                        if f is not None and (last_bl_finish_dt is None or f > last_bl_finish_dt):
                            last_bl_finish_dt = f
        except Exception:
            last_bl_finish_dt = None

    def to_date_any(x):
        try:
            if isinstance(x, _dt.datetime):
                return x.date()
            if isinstance(x, _dt.date):
                return x
        except Exception:
            pass
        return None

    try:
        fd = to_date_any(finish_date)
        ld = to_date_any(last_bl_finish_dt)
        deviation_days = (fd - ld).days if (fd is not None and ld is not None) else None
    except Exception:
        deviation_days = None

    total_tasks = len([t for t in tasks if not is_summary(t)])
    completed_tasks = len([t for t in tasks if (getattr(t, "percent_complete", 0) or 0) >= 100])
    overview = f"Всего задач: {total_tasks}. Завершено: {completed_tasks}. Просрочено с 0%: {len(overdue_zero)}."
    inactive_ids = []
    for t in tasks:
        tid = getattr(t, "id", None)
        if tid is not None and is_inactive(t):
            inactive_ids.append(tid)

    short_reqs = [
        "разработка тз",
        "согласование и утверждение тз",
    ]
    short_found = set()
    for t in tasks:
        nm = str(getattr(t, "name", "") or "").lower().strip()
        for r in short_reqs:
            if nm == r:
                short_found.add(r)
    short_missing = [r for r in short_reqs if r not in short_found]
    short_tz_check = {"ok": len(short_missing) == 0, "missing": [
        "Разработка ТЗ" if short_reqs[0] in short_missing else None,
        "Согласование и утверждение ТЗ" if short_reqs[1] in short_missing else None,
    ]}
    short_tz_check["missing"] = [x for x in short_tz_check["missing"] if x]

    try:
        p = locals().get('tmp_path') or globals().get('tmp_path')
        if p is not None:
            from pathlib import Path
            if isinstance(p, Path):
                if p.exists():
                    p.unlink()
            else:
                import os
                sp = str(p)
                if os.path.exists(sp):
                    os.unlink(sp)
    except Exception:
        pass

    return {
        "projectName": name,
        "projectManager": manager,
        "projectCurator": curator,
        "projectPercentComplete": percent_complete,
        "overview": overview,
        "allTaskIds": list(task_by_id.keys()),
        "inactiveTaskIds": inactive_ids,
        "overdueTasksZeroPercent": overdue_zero,
        "missingPredecessorsTasks": missing_pred,
        "missingSuccessorsTasks": succ_missing,
        "invalidConstraintTasks": invalid_constraints,
        "longDurationTasks": long_duration,
        "summaryTasksLongerThanMonth": summary_long_month,
        "qualityCouncilCheck": quality_council_check,
        "shortTZCheck": short_tz_check,
        "baselines": baselines,
        "projectFinishDeviationDays": deviation_days,
        "projectStartDate": safe_date(start_date),
        "projectFinishDate": safe_date(finish_date),
    }

@app.post("/api/resources/extract")
async def extract_resources(files: List[UploadFile] = File(...)):
    all_groups: list = []
    accepted: list = []
    rejected: list = []
    merged: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for f in files:
        if not _is_allowed(f.filename, f.content_type):
            rejected.append({"name": f.filename, "reason": "unsupported_type"})
            continue
        safe_name = f.filename.replace("/", "_").replace("\\", "_")
        target = TMP_DIR / f"{uuid.uuid4().hex}_{safe_name}"
        try:
            with target.open("wb") as out:
                shutil.copyfileobj(f.file, out)
            accepted.append({"name": f.filename, "stored_as": target.name})
            parsed = parse_resources_hierarchy(target)
            for g in parsed.get("groups", []):
                gname = g.get("name") or ""
                for d in g.get("departments", []):
                    dname = d.get("name") or ""
                    for r in d.get("resources", []):
                        merged[gname][dname].append(r)
        except Exception:
            rejected.append({"name": f.filename, "reason": "parse_failed"})
        finally:
            try:
                if target.exists():
                    target.unlink()
            except Exception:
                pass
    groups_out = []
    for gname, depts in merged.items():
        ds = []
        for dname, rlist in depts.items():
            r_sorted = sorted(rlist, key=lambda x: (x.get("name") or ""))
            ds.append({"name": dname, "resources": r_sorted})
        ds_sorted = sorted(ds, key=lambda x: (x.get("name") or ""))
        groups_out.append({"name": gname, "departments": ds_sorted})
    groups_out = sorted(groups_out, key=lambda x: (x.get("name") or ""))
    return {"ok": True, "accepted": accepted, "rejected": rejected, "groups": groups_out}

@app.post("/api/resources/upload_store")
async def upload_store_resources(files: List[UploadFile] = File(...)):
    merged: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    accepted: list = []
    rejected: list = []
    for f in files:
        if not _is_allowed(f.filename, f.content_type):
            rejected.append({"name": f.filename, "reason": "unsupported_type"})
            continue
        safe_name = f.filename.replace("/", "_").replace("\\", "_")
        target = TMP_DIR / f"{uuid.uuid4().hex}_{safe_name}"
        try:
            with target.open("wb") as out:
                shutil.copyfileobj(f.file, out)
            accepted.append({"name": f.filename, "stored_as": target.name})
            parsed = parse_resources_hierarchy(target)
            for g in parsed.get("groups", []):
                gname = g.get("name") or ""
                for d in g.get("departments", []):
                    dname = d.get("name") or ""
                    for r in d.get("resources", []):
                        merged[gname][dname].append(r)
        except Exception:
            rejected.append({"name": f.filename, "reason": "parse_failed"})
        finally:
            try:
                if target.exists():
                    target.unlink()
            except Exception:
                pass
    groups_out = []
    for gname, depts in merged.items():
        ds = []
        for dname, rlist in depts.items():
            r_sorted = sorted(rlist, key=lambda x: (x.get("name") or ""))
            ds.append({"name": dname, "resources": r_sorted})
        ds_sorted = sorted(ds, key=lambda x: (x.get("name") or ""))
        groups_out.append({"name": gname, "departments": ds_sorted})
    groups_out = sorted(groups_out, key=lambda x: (x.get("name") or ""))

    db = SessionLocal()
    try:
        db.query(ResourcePerson).delete()
        count = 0
        for gname, depts in merged.items():
            for dname, rlist in depts.items():
                for r in rlist:
                    try:
                        rp = ResourcePerson(
                            name=(r.get("name") or "").strip(),
                            group=(gname or None),
                            department=(dname or None),
                            position=r.get("position"),
                            rate=r.get("rate"),
                        )
                        db.add(rp)
                        count += 1
                    except Exception:
                        continue
        state = db.query(ResourceState).filter(ResourceState.id == 1).first()
        if not state:
            state = ResourceState(id=1)
            db.add(state)
        source_file = None
        if accepted:
            last = accepted[-1]
            source_file = last.get("name") or last.get("stored_as")
        state.current_file_name = source_file
        state.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
    return {"ok": True, "accepted": accepted, "rejected": rejected, "count": count, "source_file": source_file, "groups": groups_out}

@app.get("/api/resources/current")
def get_current_resources():
    db = SessionLocal()
    try:
        rows = db.query(ResourcePerson).all()
        merged: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
        for r in rows:
            gname = (getattr(r, "group", None) or "")
            dname = (getattr(r, "department", None) or "")
            merged[gname][dname].append({
                "name": r.name,
                "position": getattr(r, "position", None),
                "rate": getattr(r, "rate", None),
            })
        groups_out = []
        for gname, depts in merged.items():
            ds = []
            for dname, rlist in depts.items():
                r_sorted = sorted(rlist, key=lambda x: (x.get("name") or ""))
                ds.append({"name": dname, "resources": r_sorted})
            ds_sorted = sorted(ds, key=lambda x: (x.get("name") or ""))
            groups_out.append({"name": gname, "departments": ds_sorted})
        groups_out = sorted(groups_out, key=lambda x: (x.get("name") or ""))
        state = db.query(ResourceState).filter(ResourceState.id == 1).first()
        source_file = state.current_file_name if state else None
    finally:
        db.close()
    return {"ok": True, "groups": groups_out, "source_file": source_file}

@app.delete("/api/resources/current")
def clear_current_resources():
    db = SessionLocal()
    try:
        db.query(ResourcePerson).delete()
        state = db.query(ResourceState).filter(ResourceState.id == 1).first()
        if state:
            state.current_file_name = None
            state.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
    return {"ok": True}

def _resource_check_collect(
    prj,
    at,
    range_start: datetime,
    range_end: datetime,
    calendar_month_hours: float,
    project_info: dict | None = None,
    allowed_resource_names: set[str] | None = None,
) -> dict[str, dict]:
    TimeUnitType = at.TimeUnitType
    try:
        mpd = float(getattr(prj, "minutes_per_day", 480) or 480)
    except Exception:
        mpd = 480.0
    try:
        mpw = float(getattr(prj, "minutes_per_week", 2400) or 2400)
    except Exception:
        mpw = 2400.0

    def duration_hours(d) -> float:
        if d is None:
            return 0.0
        try:
            return float(d.convert(TimeUnitType.HOUR).to_double())
        except Exception:
            try:
                unit = getattr(d, "time_unit", None)
                val = float(getattr(d, "to_double", lambda: 0.0)())
                if unit in (TimeUnitType.HOUR, TimeUnitType.HOUR_ESTIMATED):
                    return val
                if unit in (TimeUnitType.MINUTE, TimeUnitType.MINUTE_ESTIMATED):
                    return val / 60.0
                if unit in (TimeUnitType.DAY, TimeUnitType.DAY_ESTIMATED):
                    return val * (mpd / 60.0)
                if unit in (TimeUnitType.WEEK, TimeUnitType.WEEK_ESTIMATED):
                    return val * (mpw / 60.0)
                return 0.0
            except Exception:
                return 0.0

    def duration_text_hours(s: str) -> float:
        st = (s or "").strip()
        if not st:
            return 0.0
        up = st.upper()
        if up.startswith("P"):
            import re
            mobj = re.fullmatch(
                r"P"
                r"(?:(?P<y>\d+(?:\.\d+)?)Y)?"
                r"(?:(?P<mo>\d+(?:\.\d+)?)M)?"
                r"(?:(?P<w>\d+(?:\.\d+)?)W)?"
                r"(?:(?P<d>\d+(?:\.\d+)?)D)?"
                r"(?:T"
                r"(?:(?P<h>\d+(?:\.\d+)?)H)?"
                r"(?:(?P<mi>\d+(?:\.\d+)?)M)?"
                r"(?:(?P<se>\d+(?:\.\d+)?)S)?"
                r")?$",
                up,
            )
            if mobj:
                years = float(mobj.group("y") or 0.0)
                months = float(mobj.group("mo") or 0.0)
                weeks = float(mobj.group("w") or 0.0)
                days = float(mobj.group("d") or 0.0)
                hours = float(mobj.group("h") or 0.0)
                minutes = float(mobj.group("mi") or 0.0)
                seconds = float(mobj.group("se") or 0.0)
                total_days = (years * 365.0) + (months * 30.0) + (weeks * 7.0) + days
                return (total_days * 24.0) + hours + (minutes / 60.0) + (seconds / 3600.0)
        try:
            import re
            mobj = re.fullmatch(r"(?P<n>\d+(?:[.,]\d+)?)\s*(?P<u>H|HR|HRS|HOUR|HOURS|Ч|ЧАС|ЧАСОВ|M|MIN|MINS|MINUTE|MINUTES|МИН|С|SEC|SECS|SECOND|SECONDS)\.?\s*", up)
            if mobj:
                n = float(mobj.group("n").replace(",", "."))
                u = mobj.group("u")
                if u in ("H", "HR", "HRS", "HOUR", "HOURS", "Ч", "ЧАС", "ЧАСОВ"):
                    return n
                if u in ("M", "MIN", "MINS", "MINUTE", "MINUTES", "МИН"):
                    return n / 60.0
                if u in ("С", "SEC", "SECS", "SECOND", "SECONDS"):
                    return n / 3600.0
        except Exception:
            pass
        try:
            v = float(st.replace(",", "."))
            return v if v > 0 else 0.0
        except Exception:
            return 0.0

    def value_hours(v) -> float:
        if v is None:
            return 0.0
        try:
            if isinstance(v, _dt.timedelta):
                return float(v.total_seconds()) / 3600.0
        except Exception:
            pass
        try:
            return duration_hours(v)
        except Exception:
            pass
        try:
            return duration_text_hours(str(v))
        except Exception:
            return 0.0

    def to_dt(v):
        if v is None:
            return None
        try:
            if isinstance(v, datetime):
                try:
                    return v.replace(tzinfo=None)
                except Exception:
                    return v
        except Exception:
            pass
        try:
            if isinstance(v, _dt.date):
                return datetime(v.year, v.month, v.day)
        except Exception:
            pass
        try:
            yy = getattr(v, "year", None)
            mm = getattr(v, "month", None)
            dd = getattr(v, "day", None)
            if yy is not None and mm is not None and dd is not None:
                hh = getattr(v, "hour", 0) or 0
                mi = getattr(v, "minute", 0) or 0
                ss = getattr(v, "second", 0) or 0
                us = getattr(v, "microsecond", 0) or 0
                return datetime(int(yy), int(mm), int(dd), int(hh), int(mi), int(ss), int(us))
        except Exception:
            pass
        try:
            s = str(v)
            if not s:
                return None
            s2 = s.strip()
            try:
                return datetime.fromisoformat(s2.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass
            patterns = [
                "%d.%m.%Y %H:%M:%S",
                "%d.%m.%Y %H:%M",
                "%d.%m.%y %H:%M:%S",
                "%d.%m.%y %H:%M",
                "%d.%m.%Y",
                "%d.%m.%y",
                "%m/%d/%Y %H:%M:%S",
                "%m/%d/%Y %H:%M",
                "%m/%d/%y %H:%M:%S",
                "%m/%d/%y %H:%M",
                "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %I:%M %p",
                "%m/%d/%y %I:%M:%S %p",
                "%m/%d/%y %I:%M %p",
            ]
            for fmt in patterns:
                try:
                    return datetime.strptime(s2, fmt)
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def to_float(v) -> float:
        if v is None:
            return 0.0
        try:
            if isinstance(v, (int, float)):
                return float(v)
        except Exception:
            pass
        try:
            s = str(v).replace(",", ".").strip()
            return float(s) if s else 0.0
        except Exception:
            return 0.0

    def overlap_fraction(seg_start: datetime, seg_end: datetime, rs: datetime, re: datetime) -> float:
        if seg_end <= seg_start:
            return 0.0
        os = seg_start if seg_start > rs else rs
        oe = seg_end if seg_end < re else re
        if oe <= os:
            return 0.0
        try:
            total = (seg_end - seg_start).total_seconds()
            part = (oe - os).total_seconds()
            if total <= 0:
                return 0.0
            f = part / total
            if f < 0:
                return 0.0
            if f > 1:
                return 1.0
            return float(f)
        except Exception:
            return 0.0

    def assignment_hours_in_range(a, t, total_wh: float) -> float:
        td = getattr(a, "timephased_data", None)
        got_any = False
        hours_sum = 0.0
        if td is not None:
            try:
                parts = list(td)
            except Exception:
                parts = []
            for p in parts:
                try:
                    ps = to_dt(getattr(p, "start", None))
                    pf = to_dt(getattr(p, "finish", None))
                    pv = getattr(p, "value", None)
                    if ps is None:
                        continue
                    if pf is None or pf <= ps:
                        if ps >= range_start and ps < range_end:
                            vh = value_hours(pv)
                            if vh > 0:
                                got_any = True
                                hours_sum += vh
                        continue
                    frac = overlap_fraction(ps, pf, range_start, range_end)
                    if frac <= 0:
                        continue
                    vh = value_hours(pv)
                    if vh <= 0:
                        continue
                    got_any = True
                    hours_sum += vh * frac
                except Exception:
                    continue
        if got_any:
            return float(hours_sum) if hours_sum > 0 else 0.0

        st = to_dt(getattr(a, "start", None)) or to_dt(getattr(t, "start", None))
        fn = to_dt(getattr(a, "finish", None)) or to_dt(getattr(t, "finish", None))
        if st is not None and fn is not None and fn > st:
            frac = overlap_fraction(st, fn, range_start, range_end)
            return float(total_wh * frac) if frac > 0 else 0.0

        if st is not None and st >= range_start and st < range_end:
            return float(total_wh)
        return 0.0

    def assignment_cost_in_range(a, t, total_cost: float, total_wh: float, wh: float) -> float:
        if total_cost <= 0:
            return 0.0
        if total_wh > 0 and wh > 0:
            frac = wh / total_wh
            if frac < 0:
                frac = 0.0
            if frac > 1:
                frac = 1.0
            return float(total_cost) * float(frac)

        st = to_dt(getattr(a, "start", None)) or to_dt(getattr(t, "start", None))
        fn = to_dt(getattr(a, "finish", None)) or to_dt(getattr(t, "finish", None))
        if st is not None and fn is not None and fn > st:
            frac = overlap_fraction(st, fn, range_start, range_end)
            return float(total_cost) * float(frac) if frac > 0 else 0.0
        if st is not None and st >= range_start and st < range_end:
            return float(total_cost)
        return 0.0

    def assignment_units_percent(a) -> float:
        try:
            u = a.get(at.Asn.UNITS)
        except Exception:
            try:
                u = getattr(a, "units", None)
            except Exception:
                u = None
        val = to_float(u)
        if val <= 0:
            return 0.0
        # Aspose/MSP can store units as fraction (1.0 == 100%) or percent (100)
        if val <= 1.0:
            val = val * 100.0
        if val > 10000.0:
            # clamp obviously bad values
            val = 100.0
        if val < 0.0:
            val = 0.0
        if val > 100.0:
            val = 100.0
        return float(val)

    def res_name(r) -> str | None:
        if r is None:
            return None
        try:
            rn = r.get(at.Rsc.NAME)
            rn = str(rn).strip() if rn is not None else ""
            return rn or None
        except Exception:
            try:
                rn = getattr(r, "name", None)
                rn = str(rn).strip() if rn is not None else ""
                return rn or None
            except Exception:
                return None

    def task_info(t) -> dict:
        if t is None:
            return {"id": None, "name": None, "start": None, "finish": None, "percentComplete": None}
        tid = None
        try:
            tid = getattr(t, "id", None)
        except Exception:
            tid = None
        try:
            nm = t.get(at.Tsk.NAME)
        except Exception:
            nm = getattr(t, "name", None)
        return {
            "id": tid,
            "name": nm,
            "start": safe_date(getattr(t, "start", None)),
            "finish": safe_date(getattr(t, "finish", None)),
            "percentComplete": getattr(t, "percent_complete", None),
        }

    project_key = None
    project_name = None
    project_file_id = None
    project_source = None
    project_percent = None
    project_finish = None
    if isinstance(project_info, dict):
        project_key = project_info.get("key")
        project_name = project_info.get("name")
        project_file_id = project_info.get("fileId")
        project_source = project_info.get("source")
        project_percent = project_info.get("percentComplete")
        project_finish = project_info.get("finishDate")
    if not project_key:
        project_key = project_name or "project"
    project_key = str(project_key)

    allowed_norm = None
    if allowed_resource_names:
        allowed_norm = {_norm_resource_name(x) for x in allowed_resource_names if x}

    by_res: dict[str, dict] = {}

    assignments = []
    try:
        assignments = list(getattr(prj, "resource_assignments", None) or [])
    except Exception:
        assignments = []

    no_id_counter = 0
    for a in assignments:
        r = getattr(a, "resource", None)
        t = getattr(a, "task", None)
        rn = res_name(r)
        if not rn:
            continue
        if allowed_norm is not None and _norm_resource_name(rn) not in allowed_norm:
            continue

        w = getattr(a, "work", None)
        if w is None:
            try:
                w = a.get(at.Asn.WORK)
            except Exception:
                w = None
        total_wh = duration_hours(w)
        wh = assignment_hours_in_range(a, t, total_wh)
        if wh <= 0:
            continue

        cost_val = getattr(a, "cost", None)
        if cost_val is None:
            try:
                cost_val = a.get(at.Asn.COST)
            except Exception:
                cost_val = None
        if cost_val is None:
            try:
                cost_val = getattr(a, "actual_cost", None)
            except Exception:
                cost_val = None
        if cost_val is None:
            try:
                cost_val = a.get(at.Asn.ACTUAL_COST)
            except Exception:
                cost_val = None
        total_cost = to_float(cost_val)
        cost_in_range = assignment_cost_in_range(a, t, total_cost, total_wh, wh)

        entry = by_res.get(rn)
        if entry is None:
            entry = {"name": rn, "totalWorkHours": 0.0, "tasks": {}, "projects": {}}
            by_res[rn] = entry
        entry["totalWorkHours"] += wh

        info = task_info(t)
        tid = info.get("id")
        if tid is None:
            no_id_counter += 1
            task_key = f"{project_key}:noid:{no_id_counter}"
        else:
            task_key = f"{project_key}:{tid}"

        tasks_map = entry["tasks"]
        cur = tasks_map.get(task_key)
        if cur is None:
            cur = {**info, "workHours": 0.0, "cost": 0.0, "unitsPercent": assignment_units_percent(a)}
            tasks_map[task_key] = cur
        cur["workHours"] += wh
        cur["cost"] += cost_in_range
        # preserve highest unitsPercent if multiple segments hit within range
        try:
            up = assignment_units_percent(a)
            if up > (cur.get("unitsPercent") or 0.0):
                cur["unitsPercent"] = up
        except Exception:
            pass

        projects_map = entry["projects"]
        proj_entry = projects_map.get(project_key)
        if proj_entry is None:
            proj_entry = {
                "key": project_key,
                "name": project_name,
                "fileId": project_file_id,
                "source": project_source,
                "percentComplete": project_percent,
                "finishDate": project_finish,
                "totalWorkHours": 0.0,
                "tasks": {},
            }
            projects_map[project_key] = proj_entry
        proj_entry["totalWorkHours"] += wh

        proj_tasks_map = proj_entry["tasks"]
        if tid is None:
            proj_task_key = f"noid:{no_id_counter}"
        else:
            proj_task_key = str(tid)
        proj_task = proj_tasks_map.get(proj_task_key)
        if proj_task is None:
            proj_task = {**info, "workHours": 0.0, "cost": 0.0}
            proj_tasks_map[proj_task_key] = proj_task
        proj_task["workHours"] += wh
        proj_task["cost"] += cost_in_range

    try:
        for r in prj.resources:
            rn = res_name(r)
            if not rn:
                continue
            if allowed_norm is not None and _norm_resource_name(rn) not in allowed_norm:
                continue
            if rn not in by_res:
                by_res[rn] = {"name": rn, "totalWorkHours": 0.0, "tasks": {}, "projects": {}}
            entry = by_res.get(rn)
            if entry is not None:
                projects_map = entry.get("projects")
                if isinstance(projects_map, dict) and project_key not in projects_map:
                    projects_map[project_key] = {
                        "key": project_key,
                        "name": project_name,
                        "fileId": project_file_id,
                        "source": project_source,
                    "percentComplete": project_percent,
                    "finishDate": project_finish,
                        "totalWorkHours": 0.0,
                        "tasks": {},
                    }
    except Exception:
        pass

    return by_res

def _resource_check_merge(dst: dict[str, dict], src: dict[str, dict]) -> dict[str, dict]:
    for rn, entry in (src or {}).items():
        if rn not in dst:
            dst[rn] = entry
            continue
        target = dst[rn]
        target["totalWorkHours"] = float(target.get("totalWorkHours") or 0.0) + float(entry.get("totalWorkHours") or 0.0)

        t_tasks = target.get("tasks")
        if not isinstance(t_tasks, dict):
            t_tasks = {}
            target["tasks"] = t_tasks
        s_tasks = entry.get("tasks") or {}
        if isinstance(s_tasks, dict):
            for tk, tv in s_tasks.items():
                cur = t_tasks.get(tk)
                if cur is None:
                    t_tasks[tk] = tv
                else:
                    cur["workHours"] = float(cur.get("workHours") or 0.0) + float(tv.get("workHours") or 0.0)

        t_projects = target.get("projects")
        if not isinstance(t_projects, dict):
            t_projects = {}
            target["projects"] = t_projects
        s_projects = entry.get("projects") or {}
        if isinstance(s_projects, dict):
            for pk, pv in s_projects.items():
                curp = t_projects.get(pk)
                if curp is None:
                    t_projects[pk] = pv
                else:
                    curp["totalWorkHours"] = float(curp.get("totalWorkHours") or 0.0) + float(pv.get("totalWorkHours") or 0.0)
                    if curp.get("percentComplete") is None and pv.get("percentComplete") is not None:
                        curp["percentComplete"] = pv.get("percentComplete")
                    if curp.get("finishDate") is None and pv.get("finishDate") is not None:
                        curp["finishDate"] = pv.get("finishDate")
                    c_tasks = curp.get("tasks")
                    if not isinstance(c_tasks, dict):
                        c_tasks = {}
                        curp["tasks"] = c_tasks
                    p_tasks = pv.get("tasks") or {}
                    if isinstance(p_tasks, dict):
                        for tk, tv in p_tasks.items():
                            ct = c_tasks.get(tk)
                            if ct is None:
                                c_tasks[tk] = tv
                            else:
                                ct["workHours"] = float(ct.get("workHours") or 0.0) + float(tv.get("workHours") or 0.0)
    return dst

def _resource_check_finalize(by_res: dict[str, dict], calendar_month_hours: float) -> list[dict]:
    resources_out: list[dict] = []
    for rn, entry in (by_res or {}).items():
        tasks_map = entry.get("tasks") or {}
        tasks_out = list(tasks_map.values()) if isinstance(tasks_map, dict) else []
        tasks_out.sort(key=lambda x: (-(float(x.get("workHours") or 0.0)), str(x.get("name") or "")))

        projects_map = entry.get("projects") or {}
        projects_out: list[dict] = []
        if isinstance(projects_map, dict):
            for pk, pv in projects_map.items():
                p_tasks_map = pv.get("tasks") or {}
                p_tasks_out = list(p_tasks_map.values()) if isinstance(p_tasks_map, dict) else []
                p_tasks_out.sort(key=lambda x: (-(float(x.get("workHours") or 0.0)), str(x.get("name") or "")))
                p_total = float(pv.get("totalWorkHours") or 0.0)
                if p_total <= 0:
                    continue
                projects_out.append(
                    {
                        "key": pv.get("key") or pk,
                        "name": pv.get("name"),
                        "fileId": pv.get("fileId"),
                        "source": pv.get("source"),
                        "percentComplete": pv.get("percentComplete"),
                        "finishDate": pv.get("finishDate"),
                        "totalWorkHours": p_total,
                        "tasks": p_tasks_out,
                    }
                )
        projects_out.sort(key=lambda x: (-(float(x.get("totalWorkHours") or 0.0)), str(x.get("name") or "")))

        uploaded_wh = 0.0
        for p in projects_out:
            if (p.get("source") or "") == "uploaded":
                uploaded_wh += float(p.get("totalWorkHours") or 0.0)
        if uploaded_wh <= 0:
            continue
        cap = float(calendar_month_hours) if calendar_month_hours > 0 else 0.0
        util = None
        if cap > 0:
            util = (float(entry.get("totalWorkHours") or 0.0) / cap) * 100.0
        total_wh = float(entry.get("totalWorkHours") or 0.0)
        resources_out.append(
            {
                "name": entry.get("name") or rn,
                "totalWorkHours": total_wh,
                "capacityHours": cap,
                "utilizationPct": util,
                "tasks": tasks_out,
                "projects": projects_out,
            }
        )
    resources_out.sort(key=lambda x: (-(float(x.get("totalWorkHours") or 0.0)), str(x.get("name") or "")))
    return resources_out

def _split_resource_names(v: str | None) -> list[str]:
    if not v:
        return []
    s = str(v).replace(";", ",")
    out: list[str] = []
    for part in s.split(","):
        x = part.strip()
        if x:
            out.append(x)
    return out

def _norm_resource_name(v: str | None) -> str:
    if not v:
        return ""
    s = " ".join(str(v).strip().split())
    return s.casefold()

@app.get("/api/resources/person_projects")
def get_person_projects(name: str):
    q = (name or "").strip()
    if not q:
        return {"ok": True, "items": []}
    qn = _norm_resource_name(q)
    db = SessionLocal()
    try:
        base_q = (
            db.query(ProjectMeta, ProjectFile)
            .join(ProjectFile, ProjectFile.id == ProjectMeta.file_id)
            .filter(ProjectMeta.resources.isnot(None))
            .order_by(ProjectFile.uploaded_at.desc())
        )
        rows = base_q.filter(ProjectMeta.resources.like(f"%{q}%")).limit(1000).all()
        if not rows:
            rows = base_q.limit(1000).all()
        items: list[dict] = []
        for meta, pf in rows:
            names = [_norm_resource_name(x) for x in _split_resource_names(getattr(meta, "resources", None))]
            if qn not in names:
                continue
            items.append(
                {
                    "fileId": pf.id,
                    "fileName": pf.original_name,
                    "projectName": meta.name or pf.original_name,
                    "startDate": safe_date(meta.start_date),
                    "finishDate": safe_date(meta.finish_date),
                    "percentComplete": meta.percent_complete,
                    "uploadedAt": safe_date(pf.uploaded_at),
                }
            )
    finally:
        db.close()
    return {"ok": True, "items": items}

@app.get("/api/resources/debug_counts")
def resources_debug_counts(path: str):
    try:
        at = _get_aspose_tasks()
        prj = at.Project(path)
        rc = 0
        ac = 0
        try:
            rc = sum(1 for _ in prj.resources)
        except Exception:
            rc = -1
        try:
            ac = sum(1 for _ in prj.resource_assignments)
        except Exception:
            ac = -1
        return {"ok": True, "resources_count": rc, "assignments_count": ac}
    except Exception:
        return {"ok": False}

@app.post("/api/resource-check/analyze")
async def resource_check_analyze(file: UploadFile = File(...), year: int | None = None, month: int | None = None):
    if not file.filename or not _is_allowed(file.filename, file.content_type):
        raise HTTPException(status_code=400, detail="Требуется файл MS Project: .mpp, .mpt, .mpx, .xml")

    data = await file.read()
    suffix = Path(file.filename).suffix.lower() if file.filename else ""
    if suffix not in ALLOWED_EXTS:
        suffix = ".mpp"
    tmp_path = TMP_DIR / f"{uuid.uuid4().hex}{suffix}"
    with tmp_path.open("wb") as out:
        out.write(data)

    tmp_copy = None
    try:
        try:
            at = _get_aspose_tasks()
        except Exception as e:
            raise RuntimeError(f"Aspose.Tasks недоступен: {e}") from e

        try:
            prj, tmp_copy = _aspose_open_project(tmp_path)
        except Exception as e:
            raise RuntimeError(f"Не удалось открыть проект: {e}") from e

        now_dt = datetime.now()
        y = int(year) if year is not None else now_dt.year
        m = int(month) if month is not None else now_dt.month
        if m < 1 or m > 12:
            raise HTTPException(status_code=400, detail="Некорректный месяц")
        if y < 1900 or y > 2200:
            raise HTTPException(status_code=400, detail="Некорректный год")
        range_start = datetime(y, m, 1)
        if m == 12:
            range_end = datetime(y + 1, 1, 1)
        else:
            range_end = datetime(y, m + 1, 1)

        def parse_hhmm(v: str) -> int | None:
            s = str(v or "").strip()
            if not s:
                return None
            parts = s.split(":")
            if len(parts) != 2:
                return None
            try:
                hh = int(parts[0])
                mm = int(parts[1])
            except Exception:
                return None
            if hh < 0 or hh > 23 or mm < 0 or mm > 59:
                return None
            return hh * 60 + mm

        def intervals_hours(intervals) -> float:
            if not isinstance(intervals, list):
                return 0.0
            total = 0.0
            for it in intervals:
                if not isinstance(it, dict):
                    continue
                st = parse_hhmm(it.get("start"))
                fn = parse_hhmm(it.get("end"))
                if st is None or fn is None:
                    continue
                if fn <= st:
                    continue
                total += (fn - st) / 60.0
            return float(total)

        def calc_calendar_hours(cal: dict) -> float:
            work_week = cal.get("workWeek") if isinstance(cal, dict) else None
            work_week = work_week if isinstance(work_week, dict) else {}
            exceptions = cal.get("exceptions") if isinstance(cal, dict) else None
            exceptions = exceptions if isinstance(exceptions, list) else []
            exc_by_date: dict[str, dict] = {}
            for item in exceptions:
                if isinstance(item, str):
                    exc_by_date[item] = {"working": False}
                    continue
                if not isinstance(item, dict):
                    continue
                d = item.get("date") or item.get("day")
                if isinstance(d, str) and d:
                    exc_by_date[d] = item
            def day_key(dt: datetime) -> str:
                wk = dt.weekday()
                if wk == 0:
                    return "mon"
                if wk == 1:
                    return "tue"
                if wk == 2:
                    return "wed"
                if wk == 3:
                    return "thu"
                if wk == 4:
                    return "fri"
                if wk == 5:
                    return "sat"
                return "sun"

            total = 0.0
            cur = range_start
            one_day = _dt.timedelta(days=1)
            while cur < range_end:
                dstr = cur.date().isoformat()
                exc = exc_by_date.get(dstr)
                if exc is not None:
                    working = exc.get("working")
                    if working is False or exc.get("isWorking") is False or exc.get("work") is False:
                        cur += one_day
                        continue
                    exc_intervals = exc.get("intervals")
                    if isinstance(exc_intervals, list):
                        total += intervals_hours(exc_intervals)
                        cur += one_day
                        continue
                key = day_key(cur)
                intervals = work_week.get(key, [])
                total += intervals_hours(intervals)
                cur += one_day
            return float(total)

        def calc_holiday_calendar_hours(cal: dict) -> float:
            holidays = cal.get("holidays") if isinstance(cal, dict) else None
            holidays = holidays if isinstance(holidays, list) else []
            if not holidays:
                return 0.0
            holiday_set = {str(s) for s in holidays if isinstance(s, str) and s.startswith(f"{y}-")}
            total = 0.0
            cur = range_start
            one_day = _dt.timedelta(days=1)
            while cur < range_end:
                wk = cur.weekday()
                dstr = cur.date().isoformat()
                if wk < 5 and dstr not in holiday_set:
                    total += 8.0
                cur += one_day
            return float(total)

        work_calendar = _load_work_calendar()
        holiday_hours = calc_holiday_calendar_hours(work_calendar)
        calendar_month_hours = holiday_hours if holiday_hours > 0 else calc_calendar_hours(work_calendar)

        proj_name = None
        try:
            proj_name = getattr(prj, "name", None)
        except Exception:
            proj_name = None
        if not proj_name:
            try:
                proj_name = prj.root_task.get(at.Tsk.NAME)
            except Exception:
                proj_name = None
        proj_percent = None
        try:
            proj_percent = prj.get(at.Prj.PERCENT_COMPLETE)
        except Exception:
            proj_percent = None
        if proj_percent is None:
            try:
                proj_percent = getattr(prj, "percent_complete", None)
            except Exception:
                proj_percent = None
        if proj_percent is None:
            try:
                proj_percent = getattr(prj.root_task, "percent_complete", None)
            except Exception:
                proj_percent = None
        proj_finish = safe_date(getattr(prj, "finish_date", None))
        if not proj_finish:
            try:
                proj_finish = safe_date(prj.get(at.Prj.FINISH_DATE))
            except Exception:
                proj_finish = None

        resources_map: dict[str, dict] = {}
        base_map = _resource_check_collect(
            prj,
            at,
            range_start,
            range_end,
            calendar_month_hours,
            project_info={
                "key": "uploaded",
                "name": proj_name,
                "source": "uploaded",
                "percentComplete": proj_percent,
                "finishDate": proj_finish,
            },
            allowed_resource_names=None,
        )
        _resource_check_merge(resources_map, base_map)

        base_names = set(base_map.keys())
        base_norm = {_norm_resource_name(x) for x in base_names if x}

        uploaded_name_keys = {
            _norm_resource_name(proj_name),
            _norm_resource_name(Path(file.filename).stem if file.filename else ""),
            _norm_resource_name(file.filename or ""),
        }

        db = SessionLocal()
        try:
            rows = (
                db.query(ProjectMeta, ProjectFile)
                .join(ProjectFile, ProjectFile.id == ProjectMeta.file_id)
                .order_by(ProjectFile.uploaded_at.desc())
                .limit(1000)
                .all()
            )
            for meta, pf in rows:
                res_names = _split_resource_names(getattr(meta, "resources", None))
                if base_norm and res_names:
                    has_match = False
                    for nm in res_names:
                        if _norm_resource_name(nm) in base_norm:
                            has_match = True
                            break
                    if not has_match:
                        continue
                    if _norm_resource_name(meta.name or "") in uploaded_name_keys:
                        continue
                    if _norm_resource_name(pf.original_name or "") in uploaded_name_keys:
                        continue
                    if not pf.stored_path:
                        continue
                    p = Path(pf.stored_path)
                    try:
                        bank_root = UPLOAD_DIR.resolve()
                        prj_path = p.resolve()
                        if prj_path != bank_root and bank_root not in prj_path.parents:
                            continue
                    except Exception:
                        continue
                    if not p.exists():
                        continue
                    tmp_bank = None
                    try:
                        bank_prj, tmp_bank = _aspose_open_project(p)
                        bank_map = _resource_check_collect(
                            bank_prj,
                            at,
                            range_start,
                            range_end,
                            calendar_month_hours,
                            project_info={
                                "key": f"bank:{pf.id}",
                                "name": meta.name or pf.original_name,
                                "fileId": pf.id,
                                "source": "bank",
                                "percentComplete": getattr(meta, "percent_complete", None),
                                "finishDate": safe_date(getattr(meta, "finish_date", None)),
                            },
                            allowed_resource_names=base_names if base_names else None,
                        )
                        _resource_check_merge(resources_map, bank_map)
                    except Exception:
                        continue
                    finally:
                        try:
                            if tmp_bank and tmp_bank.exists():
                                tmp_bank.unlink()
                        except Exception:
                            pass
        finally:
            db.close()

        resources_out = _resource_check_finalize(resources_map, calendar_month_hours)

        return {
            "ok": True,
            "period": {
                "year": y,
                "month": m,
                "startDate": range_start.date().isoformat(),
                "finishDate": (range_end - _dt.timedelta(days=1)).date().isoformat(),
            },
            "calendar": {
                "name": work_calendar.get("name") if isinstance(work_calendar, dict) else None,
                "timezone": work_calendar.get("timezone") if isinstance(work_calendar, dict) else None,
                "monthHours": float(calendar_month_hours) if calendar_month_hours > 0 else 0.0,
            },
            "project": {
                "name": proj_name,
                "startDate": safe_date(getattr(prj, "start_date", None)),
                "finishDate": safe_date(getattr(prj, "finish_date", None)),
            },
            "resources": resources_out,
        }
    except HTTPException:
        raise
    except Exception as e:
        err = str(e)
        try:
            import traceback
            tb = traceback.format_exc()
        except Exception:
            tb = None
        try:
            msg = f"resource_check_analyze error: {err}"
            if tb:
                msg = f"{msg}\n{tb}"
            print(msg, file=sys.stderr)
        except Exception:
            pass
        return {"ok": False, "error": err}
    finally:
        try:
            if tmp_copy and tmp_copy.exists():
                tmp_copy.unlink()
        except Exception:
            pass
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

@app.post("/api/pk/final/analyze")
async def pk_final_analyze(file: UploadFile = File(...)):
    from typing import Any, Dict, List
    if not file.filename or not file.filename.lower().endswith('.mpp'):
        raise HTTPException(status_code=400, detail="Требуется файл MS Project с расширением .mpp")
    try:
        tsk = _get_aspose_tasks()
        Project = tsk.Project
        ConstraintType = tsk.ConstraintType
        TimeUnitType = tsk.TimeUnitType
    except Exception as e:
        return {"error": str(e)}
    data = await file.read()
    tmp_path = TMP_DIR / f"{uuid.uuid4().hex}.mpp"
    with tmp_path.open('wb') as out:
        out.write(data)
    try:
        project = Project(str(tmp_path))
    except Exception as e:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        return {"error": f"Failed to open project: {e}"}
    root = getattr(project, "root_task", None)
    def children(task) -> List[Any]:
        try:
            return list(task.children)
        except Exception:
            try:
                return list(task.get_children())
            except Exception:
                return []
    tasks: List[Any] = []
    if root is not None:
        stack = children(root)
        while stack:
            t = stack.pop(0)
            tasks.append(t)
            stack[0:0] = children(t)
    task_by_id: Dict[Any, Any] = {}
    for _t in tasks:
        try:
            tid = getattr(_t, "id", None)
        except Exception:
            tid = None
        if tid is not None:
            task_by_id[tid] = _t
    def is_summary(t) -> bool:
        try:
            return bool(getattr(t, "is_summary", False))
        except Exception:
            return False
    def is_recurring(t) -> bool:
        try:
            return bool(getattr(t, "is_recurring", False))
        except Exception:
            return False
    def duration_days(d) -> float:
        if d is None:
            return 0.0
        try:
            return d.convert(TimeUnitType.DAY).to_double()
        except Exception:
            try:
                unit = getattr(d, "time_unit", None)
                val = float(getattr(d, "to_double", lambda: 0.0)())
                if unit in (TimeUnitType.DAY, TimeUnitType.DAY_ESTIMATED):
                    return val
                if unit in (TimeUnitType.HOUR, TimeUnitType.HOUR_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    return (val * 60.0) / mpd
                if unit in (TimeUnitType.MINUTE, TimeUnitType.MINUTE_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    return val / mpd
                if unit in (TimeUnitType.WEEK, TimeUnitType.WEEK_ESTIMATED):
                    mpd = float(getattr(project, "minutes_per_day", 480))
                    mpw = float(getattr(project, "minutes_per_week", 2400))
                    return val * (mpw / mpd)
                return 0.0
            except Exception:
                return 0.0
    top_children = children(root) if root is not None else []
    top_level_summary_check = {"ok": True, "violations": []}
    if top_children:
        if len(top_children) > 1:
            for i, t in enumerate(top_children):
                if i == 0:
                    continue
                top_level_summary_check["violations"].append({"id": getattr(t, "id", None), "name": getattr(t, "name", None), "percentComplete": getattr(t, "percent_complete", 0) or 0})
            top_level_summary_check["ok"] = len(top_level_summary_check["violations"]) == 0
    req_names = [
        "Провести установочное совещание",
        "Провести совещание по сдаче проекта заказчику/инвестору",
        "Начало проекта",
        "Проект завершен",
    ]
    found = []
    missing = []
    name_map = {n.lower(): n for n in req_names}
    for rn in req_names:
        missing.append(rn)
    for t in tasks:
        nm = str(getattr(t, "name", "") or "")
        lnm = nm.lower().strip()
        if lnm in name_map:
            found.append({"name": name_map[lnm], "id": getattr(t, "id", None)})
            try:
                missing.remove(name_map[lnm])
            except Exception:
                pass
    required_tasks_check = {"ok": len(missing) == 0, "found": found, "missing": missing}
    pred_missing = []
    succ_missing = []
    invalid_constraints = []
    for t in tasks:
        if is_summary(t) or is_recurring(t):
            continue
        preds = getattr(t, "predecessors", None)
        pc = 0
        try:
            pc = len(list(preds)) if preds is not None else 0
        except Exception:
            pc = getattr(preds, "count", 0) if preds is not None else 0
        is_milestone = bool(getattr(t, "is_milestone", False))
        if pc == 0 and not is_milestone:
            pred_missing.append({"id": getattr(t, "id", None), "name": getattr(t, "name", None), "percentComplete": getattr(t, "percent_complete", 0) or 0})
        ct = getattr(t, "constraint_type", None)
        try:
            if ct is not None and ct != ConstraintType.AS_SOON_AS_POSSIBLE:
                invalid_constraints.append({"id": getattr(t, "id", None), "name": getattr(t, "name", None), "percentComplete": getattr(t, "percent_complete", 0) or 0})
        except Exception:
            pass
    rev_index = {}
    for t in tasks:
        preds = getattr(t, "predecessors", None)
        try:
            links = list(preds) if preds is not None else []
        except Exception:
            links = []
        for l in links:
            try:
                pid = getattr(getattr(l, "source_task", None), "id", None)
            except Exception:
                pid = None
            if pid is not None:
                rev_index.setdefault(pid, 0)
                rev_index[pid] += 1
    for t in tasks:
        if is_summary(t) or is_recurring(t):
            continue
        is_milestone = bool(getattr(t, "is_milestone", False))
        if is_milestone:
            continue
        tid = getattr(t, "id", None)
        if rev_index.get(tid, 0) == 0:
            succ_missing.append({"id": tid, "name": getattr(t, "name", None), "percentComplete": getattr(t, "percent_complete", 0) or 0})
    predecessors_and_successors_check = {
        "ok": (len(pred_missing) == 0 and len(succ_missing) == 0 and len(invalid_constraints) == 0),
        "missingPredecessors": pred_missing,
        "missingSuccessors": succ_missing,
        "invalidConstraints": invalid_constraints,
    }

    long_tasks = []
    for t in tasks:
        if is_summary(t):
            continue
        dur = getattr(t, "duration", None)
        if duration_days(dur) > 10:
            long_tasks.append({
                "id": getattr(t, "id", None),
                "name": getattr(t, "name", None),
                "durationDays": duration_days(dur),
                "start": safe_date(getattr(t, "start", None)),
                "finish": safe_date(getattr(t, "finish", None)),
                "percentComplete": getattr(t, "percent_complete", 0) or 0,
            })
    long_duration_check = {"longTasks": long_tasks}
    summary_violations = []
    root_id = getattr(root, "id", None)
    for t in tasks:
        if not is_summary(t):
            continue
        if root_id is not None and getattr(t, "id", None) == root_id:
            continue
        start = getattr(t, "start", None)
        finish = getattr(t, "finish", None)
        if start and finish:
            try:
                diff = (finish - start).days
            except Exception:
                diff = 0
            if diff > 31:
                summary_violations.append({"id": getattr(t, "id", None), "name": getattr(t, "name", None), "start": safe_date(start), "finish": safe_date(finish), "percentComplete": getattr(t, "percent_complete", 0) or 0})
    summary_month_check = {"violations": summary_violations}
    missing_after_summary = []
    for t in tasks:
        if not is_summary(t):
            continue
        if root_id is not None and getattr(t, "id", None) == root_id:
            continue
        ch = children(t)
        has_council = False
        has_zero_milestone = False
        for c in ch:
            nm = str(getattr(c, "name", "") or "")
            if nm.strip().lower() == "совет по качеству":
                has_council = True
            dur = getattr(c, "duration", None)
            is_m = bool(getattr(c, "is_milestone", False))
            if is_m and duration_days(dur) == 0:
                has_zero_milestone = True
        if not has_council or not has_zero_milestone:
            missing_after_summary.append({
                "summaryId": getattr(t, "id", None),
                "summaryName": getattr(t, "name", None),
                "missingCouncil": not has_council,
                "missingZeroMilestone": not has_zero_milestone,
                "summaryPercentComplete": getattr(t, "percent_complete", 0) or 0,
            })
    quality_council_check = {"missingAfterSummary": missing_after_summary}
    overallocated = []
    seen_ids = set()
    flagged = set()
    for t in tasks:
        try:
            if bool(getattr(t, "has_overallocated_resource", False)):
                tid = getattr(t, "id", None)
                if tid is not None:
                    flagged.add(tid)
        except Exception:
            pass
    assignments = []
    try:
        assignments = list(getattr(project, "resource_assignments", None) or [])
    except Exception:
        assignments = []
    by_task = {}
    for a in assignments:
        r = getattr(a, "resource", None)
        t = getattr(a, "task", None)
        if r is None or t is None:
            continue
        ov = False
        try:
            ov = bool(getattr(r, "overallocated", False))
        except Exception:
            ov = bool(getattr(r, "is_overallocated", False))
        if not ov:
            continue
        tid = getattr(t, "id", None)
        if tid is None:
            continue
        entry = by_task.get(tid)
        if entry is None:
            entry = {"id": tid, "name": getattr(t, "name", None), "resourceNames": set()}
            by_task[tid] = entry
        rn = getattr(r, "name", None)
        if rn:
            entry["resourceNames"].add(str(rn))
    for tid, entry in by_task.items():
        if tid not in seen_ids:
            seen_ids.add(tid)
            tb = task_by_id.get(entry["id"])
            overallocated.append({
                "id": entry["id"],
                "name": entry["name"],
                "resourceNames": sorted(list(entry["resourceNames"])),
                "start": safe_date(getattr(tb, "start", None)) if tb is not None else None,
                "finish": safe_date(getattr(tb, "finish", None)) if tb is not None else None,
                "percentComplete": (getattr(tb, "percent_complete", 0) or 0) if tb is not None else 0,
            })
    for t in tasks:
        tid = getattr(t, "id", None)
        if tid in flagged and tid not in by_task and tid not in seen_ids:
            seen_ids.add(tid)
            overallocated.append({
                "id": tid,
                "name": getattr(t, "name", None),
                "resourceNames": [],
                "start": safe_date(getattr(t, "start", None)),
                "finish": safe_date(getattr(t, "finish", None)),
                "percentComplete": getattr(t, "percent_complete", 0) or 0,
            })
    overallocation_check = {"overallocatedTasks": overallocated}
    pname = str(getattr(project, "name", "") or "").lower()
    def has_any_task_keyword(words: List[str]) -> bool:
        for t in tasks:
            nm = str(getattr(t, "name", "") or "").lower()
            for w in words:
                if w in nm:
                    return True
        return False
    dev_applicable = ("разработ" in pname) or ("усовершенств" in pname)
    tests_ok = has_any_task_keyword(["испыт", "тест", "опроб", "проверка"]) if dev_applicable else True
    product_dev_tests_check = {"applicable": dev_applicable, "ok": tests_ok, "missing": [] if tests_ok else ["этап проведения испытаний"]}
    sales_ok = (has_any_task_keyword(["обуч"]) and has_any_task_keyword(["продаж", "sales"])) if dev_applicable else True
    product_dev_sales_training_check = {"applicable": dev_applicable, "ok": sales_ok, "missing": [] if sales_ok else ["обучение отдела продаж"]}
    has_ispytanie_task = False
    import re
    _isp_pat = re.compile(r"\bиспыт[а-яё]*\b", re.IGNORECASE)
    for t in tasks:
        nm = str(getattr(t, "name", "") or "")
        if _isp_pat.search(nm):
            has_ispytanie_task = True
            break
    org_applicable = ("организац" in pname and "производ" in pname)
    org_5s_ok = (has_any_task_keyword(["5с", "5s"]) and has_any_task_keyword(["организац", "рабоч", "мест"])) if org_applicable else True
    org_production_5s_check = {"applicable": org_applicable, "ok": org_5s_ok, "missing": [] if org_5s_ok else ["организация рабочих мест по 5С"]}
    ext_applicable = ("внеш" in pname and "заказ" in pname)
    has_tz = has_any_task_keyword(["рассмотр", "тз"]) if ext_applicable else True
    has_pack = has_any_task_keyword(["упаковоч", "лист"]) if ext_applicable else True
    ext_ok = (has_tz and has_pack) if ext_applicable else True
    missing_ext = []
    if ext_applicable:
        if not has_tz:
            missing_ext.append("рассмотрение ТЗ")
        if not has_pack:
            missing_ext.append("разработка упаковочного листа")
    external_order_docs_check = {"applicable": ext_applicable, "ok": ext_ok, "missing": missing_ext}
    research_applicable = ("нир" in pname) or ("окр" in pname) or ("ниокр" in pname) or ("постановка на производ" in pname)
    reqs = [
        "разработка тз в соответствии с техническими требованиями. тэт, тэо, гост",
        "согласование и утверждение тз",
    ]
    found_reqs = set()
    for t in tasks:
        nm = str(getattr(t, "name", "") or "").lower().strip()
        for r in reqs:
            if nm == r:
                found_reqs.add(r)
    missing_reqs = [r for r in reqs if r not in found_reqs]
    research_docs_check = {"applicable": research_applicable, "ok": (not research_applicable or len(missing_reqs) == 0), "missing": [
        "Разработка ТЗ в соответствии с техническими требованиями.  ТЭТ, ТЭО, ГОСТ" if reqs[0] in missing_reqs else None,
        "Согласование и утверждение ТЗ" if reqs[1] in missing_reqs else None,
    ]}
    research_docs_check["missing"] = [x for x in research_docs_check["missing"] if x]
    short_reqs = [
        "разработка тз",
        "согласование и утверждение тз",
    ]
    short_found = set()
    for t in tasks:
        nm = str(getattr(t, "name", "") or "").lower().strip()
        for r in short_reqs:
            if nm == r:
                short_found.add(r)
    short_missing = [r for r in short_reqs if r not in short_found]
    short_tz_check = {"ok": len(short_missing) == 0, "missing": [
        "Разработка ТЗ" if short_reqs[0] in short_missing else None,
        "Согласование и утверждение ТЗ" if short_reqs[1] in short_missing else None,
    ]}
    short_tz_check["missing"] = [x for x in short_tz_check["missing"] if x]
    try:
        tmp_path.unlink()
    except Exception:
        pass
    return {
        "projectName": getattr(project, "name", None),
        "topLevelSummaryCheck": top_level_summary_check,
        "requiredTasksCheck": required_tasks_check,
        "predecessorsAndSuccessorsCheck": predecessors_and_successors_check,
        "longDurationCheck": long_duration_check,
        "longDurationTasks": long_tasks,
        "summaryMonthCheck": summary_month_check,
        "qualityCouncilCheck": quality_council_check,
        "overallocationCheck": overallocation_check,
        "productDevTestsCheck": product_dev_tests_check,
        "productDevSalesTrainingCheck": product_dev_sales_training_check,
        "orgProduction5SCheck": org_production_5s_check,
        "externalOrderDocsCheck": external_order_docs_check,
        "researchDocsCheck": research_docs_check,
        "shortTZCheck": short_tz_check,
        "hasIspytanieTask": has_ispytanie_task,
    }

if __name__ == "__main__":
    import os
    import uvicorn
    host = os.getenv("BACKEND_HOST", "192.168.1.20")
    try:
        port = int(os.getenv("BACKEND_PORT", "8000"))
    except Exception:
        port = 8000
    uvicorn.run("app.main:app", host=host, port=port)
