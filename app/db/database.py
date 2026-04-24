"""
Database initialization and session management.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.db.models import Base
from app.utils.config import get_config


_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        config = get_config()
        db_path = config["DB_PATH"]
        # Ensure parent dir exists
        from pathlib import Path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            echo=False,
        )
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal


def get_db() -> Session:
    return get_session_factory()()


def init_db() -> None:
    """Create all tables, then apply any pending column migrations."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _migrate_columns(engine)


def _migrate_columns(engine) -> None:
    """
    Add any new columns to existing tables that are missing (SQLite ALTER TABLE).
    Safe to run on every startup — skips columns that already exist.
    """
    new_rule_cols = [
        ("description", "TEXT"),
        ("rule_group", "VARCHAR(100)"),
        ("rule_tags", "JSON"),
        ("payload_regex", "BOOLEAN DEFAULT 0"),
        ("match_case_sensitive", "BOOLEAN DEFAULT 0"),
        ("log_payload", "BOOLEAN DEFAULT 0"),
        ("is_archived", "BOOLEAN DEFAULT 0"),
        ("version", "INTEGER DEFAULT 1"),
        ("change_log", "JSON"),
    ]
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(
            __import__("sqlalchemy").text("PRAGMA table_info(rules)")
        )}
        for col_name, col_type in new_rule_cols:
            if col_name not in existing:
                conn.execute(__import__("sqlalchemy").text(
                    f"ALTER TABLE rules ADD COLUMN {col_name} {col_type}"
                ))
        conn.commit()
