"""
Database session management — SQLite for MVP, PostgreSQL later.
"""

import os
import shutil
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

RAW_DB_URL = os.environ.get("DATABASE_URL")

if RAW_DB_URL:
    # Ensure standard postgresql:// driver prefix for SQLAlchemy
    if RAW_DB_URL.startswith("postgres://"):
        DATABASE_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)
    else:
        DATABASE_URL = RAW_DB_URL
    is_sqlite = False
else:
    db_name = "aegis.db"
    bundled_path = Path(__file__).resolve().parent.parent / db_name
    if not bundled_path.exists():
        fallback = Path(__file__).resolve().parent.parent / "aegisshield.db"
        if fallback.exists():
            bundled_path = fallback

    # On Vercel serverless runtime, only /tmp is writable
    if os.environ.get("VERCEL"):
        writable_path = Path("/tmp") / db_name
        if not writable_path.exists() and bundled_path.exists():
            try:
                shutil.copyfile(bundled_path, writable_path)
            except Exception:
                writable_path = bundled_path
        DATABASE_URL = f"sqlite:///{writable_path}"
    else:
        DATABASE_URL = f"sqlite:///{bundled_path}"
    is_sqlite = True

engine_args = {"echo": False}
if is_sqlite:
    engine_args["connect_args"] = {"check_same_thread": False, "timeout": 30}

engine = create_engine(DATABASE_URL, **engine_args)


if is_sqlite:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        if os.environ.get("VERCEL"):
            cursor.execute("PRAGMA journal_mode=MEMORY")
        else:
            cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
