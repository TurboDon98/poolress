from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path
import os
from urllib.parse import quote_plus

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

if load_dotenv is not None:
    _dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    _encoding = "utf-8-sig"
    try:
        with open(_dotenv_path, "rb") as _f:
            _bom = _f.read(2)
        if _bom in (b"\xff\xfe", b"\xfe\xff"):
            _encoding = "utf-16"
    except Exception:
        pass
    try:
        load_dotenv(dotenv_path=_dotenv_path, encoding=_encoding)
    except UnicodeDecodeError:
        load_dotenv(dotenv_path=_dotenv_path, encoding="cp1251")

DB_PATH = Path(__file__).resolve().parent.parent / "storage" / "db.sqlite3"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def _normalize_db_url(url: str) -> str:
    v = (url or "").strip().strip('"').strip("'")
    if not v:
        return ""
    if v.startswith("postgres://"):
        return "postgresql+psycopg2://" + v[len("postgres://"):]
    if v.startswith("postgresql://"):
        return "postgresql+psycopg2://" + v[len("postgresql://"):]
    return v

def _default_postgres_url() -> str:
    host = (os.environ.get("PGHOST") or "localhost").strip() or "localhost"
    port = (os.environ.get("PGPORT") or "5432").strip() or "5432"
    db = (os.environ.get("PGDATABASE") or "poolresc").strip() or "poolresc"
    user = (os.environ.get("PGUSER") or "RD").strip() or "RD"
    password = os.environ.get("PGPASSWORD")
    if password:
        return f"postgresql+psycopg2://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{db}"
    return f"postgresql+psycopg2://{quote_plus(user)}@{host}:{port}/{db}"

def _default_sqlite_url() -> str:
    return f"sqlite:///{DB_PATH}"

_env_db_url = _normalize_db_url(os.environ.get("DATABASE_URL", "") or os.environ.get("PG_DSN", ""))
_force_postgres = (os.environ.get("FORCE_POSTGRES") or "").strip().lower() in ("1", "true", "yes", "on")
_has_pg_password = bool((os.environ.get("PGPASSWORD") or "").strip())

if _env_db_url:
    DATABASE_URL = _env_db_url
elif _force_postgres or _has_pg_password:
    DATABASE_URL = _default_postgres_url()
else:
    DATABASE_URL = _default_sqlite_url()

if DATABASE_URL.startswith("sqlite:"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    _pg_client_encoding = (os.environ.get("PGCLIENTENCODING") or "UTF8").strip() or "UTF8"
    _pg_sslmode = (os.environ.get("PGSSLMODE") or "").strip()
    _pg_connect_timeout = (os.environ.get("PGCONNECT_TIMEOUT") or "").strip()
    _connect_args: dict = {"options": f"-c client_encoding={_pg_client_encoding}"}
    if _pg_sslmode:
        _connect_args["sslmode"] = _pg_sslmode
    if _pg_connect_timeout:
        try:
            _connect_args["connect_timeout"] = int(_pg_connect_timeout)
        except Exception:
            pass
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        connect_args=_connect_args,
    )

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
