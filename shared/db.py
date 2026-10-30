"""
Database Layer (SQLAlchemy ORM)
Connects to PostgreSQL as defined in docs/schema.md with automated table initialization,
default seed records, and fallback for local development.
"""
from datetime import datetime, timezone
import json
import logging
from typing import Generator
import uuid

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Text,
    DateTime,
    Float,
    Integer,
    ForeignKey,
    JSON,
    select,
    Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from contextlib import contextmanager

from shared.config import settings

logger = logging.getLogger("cyberrange.db")

Base = declarative_base()


# --- ORM Models matching docs/schema.md & PostgreSQL Init ---

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    labs = relationship("Lab", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    username = Column(Text, nullable=False)
    role = Column(String(32), nullable=False)  # red, blue, soc, admin
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant", back_populates="users")


class AuthCredential(Base):
    """Password credentials kept separate from the existing user profile table."""
    __tablename__ = "auth_credentials"

    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    password_hash = Column(Text, nullable=False)
    is_active = Column(Integer, nullable=False, default=1)
    password_updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User")


class Lab(Base):
    __tablename__ = "labs"

    id = Column(String(64), primary_key=True, default=lambda: f"lab-{uuid.uuid4().hex[:8]}")
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    dockerfile_content = Column(Text, nullable=True)
    compose_content = Column(Text, nullable=True)
    content_hash = Column(String(64), nullable=True)
    build_id = Column(String(64), nullable=True)
    image_tag = Column(Text, nullable=True)
    image_digest = Column(String(128), nullable=True)
    uploaded_by = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(32), default="uploaded")  # uploaded, validating, policy_blocked, policy_checked, building, built, failed, scanning, scan_failed, scan_inconclusive, ready, archived, demo
    build_status = Column(String(32), default="pending")  # pending, building, built, failed, unavailable
    build_logs = Column(Text, nullable=True)
    safety_scan_result = Column(JSON, default=dict)
    vulnerability_scan_result = Column(JSON, default=dict)
    ports = Column(JSON, default=list)
    is_demo = Column(Integer, default=0)
    state_history = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant", back_populates="labs")
    sessions = relationship("SessionModel", back_populates="lab", cascade="all, delete-orphan")


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True)  # sess-xxxxxxxx
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    lab_id = Column(String(64), ForeignKey("labs.id", ondelete="SET NULL"), nullable=True)
    build_id = Column(String(64), nullable=True)
    target_image = Column(Text, nullable=False)
    target_endpoint = Column(Text, nullable=True)
    execution_mode = Column(String(32), default="simulated")
    namespace = Column(String(128), nullable=False)
    status = Column(String(32), default="active")  # creating, active, destroyed, failed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    destroyed_at = Column(DateTime, nullable=True)
    archive_path = Column(Text, nullable=True)
    isolation = Column(JSON, default=dict)
    safety_scan = Column(JSON, nullable=True)

    lab = relationship("Lab", back_populates="sessions")


class NormalizedEventModel(Base):
    """Durable copy of normalized telemetry; JSON payload preserves the source event fields."""
    __tablename__ = "normalized_events"

    event_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(128), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    build_id = Column(String(64), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source_type = Column(String(32), nullable=False, index=True)
    mitre_technique = Column(String(32), nullable=True, index=True)
    provenance = Column(String(32), default="simulated", nullable=True)
    event_payload = Column(JSON, nullable=False)
    persisted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class ScenarioModel(Base):
    __tablename__ = "scenarios"

    id = Column(String(64), primary_key=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    definition_yaml = Column(Text, nullable=False)
    mitre_techniques = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SigmaRuleModel(Base):
    __tablename__ = "sigma_rules"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False)
    name = Column(Text, nullable=False)
    mitre_technique = Column(String(64), nullable=False)
    sigma_yaml = Column(Text, nullable=False)
    compiled_query = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BuildModel(Base):
    __tablename__ = "builds"

    id = Column(String(64), primary_key=True)  # bld-xxxxxxxx
    tenant_id = Column(String(64), nullable=False)
    commit_hash = Column(Text, nullable=False)
    repository = Column(Text, nullable=True)
    branch = Column(String(64), nullable=True)
    image_tag = Column(Text, nullable=False)
    session_id = Column(String(64), nullable=True)
    readiness_score = Column(Float, nullable=True)
    gate_result = Column(String(32), default="pending")  # pass, fail, pending
    coverage_percentage = Column(Float, default=0.0)
    gap_count = Column(Integer, default=0)
    report_markdown = Column(Text, nullable=True)
    score_details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ReadinessScoreModel(Base):
    __tablename__ = "readiness_scores"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(64), nullable=True)
    build_id = Column(String(64), nullable=True)
    tenant_id = Column(String(64), nullable=False)
    coverage_pct = Column(Float, nullable=False)
    avg_detection_latency_sec = Column(Float, nullable=False)
    unresolved_incidents = Column(Integer, default=0)
    score = Column(Float, nullable=False)
    breakdown = Column(JSON, default=dict)
    computed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True)  # INC-xxxxxxxx
    tenant_id = Column(String(64), nullable=False)
    session_id = Column(String(64), nullable=True)
    title = Column(Text, nullable=False)
    mitre_technique = Column(String(64), nullable=True)
    severity = Column(String(32), default="medium")
    status = Column(String(32), default="open")  # open, investigating, contained, resolved, false_positive
    assigned_to = Column(String(64), default="soc1")
    analyst_notes = Column(Text, nullable=True)
    triggering_event = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# --- Database Engine Initialization ---

def create_db_engine():
    """
    Creates SQLAlchemy engine targeting SQLite or PostgreSQL based on settings.DATABASE_BACKEND.
    Defaults to SQLite for local development ('cyberrange.db').
    When set to 'postgres', targets PostgreSQL ('cyberrange-postgres') and falls back to SQLite if unreachable.
    """
    backend = getattr(settings, "DATABASE_BACKEND", "sqlite").lower()
    sqlite_url = "sqlite:///./cyberrange.db"

    if backend == "sqlite":
        logger.info("Using local SQLite database backend (cyberrange.db)")
        return create_engine(sqlite_url, connect_args={"check_same_thread": False})

    db_url = settings.DATABASE_URL
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

    try:
        engine = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            connect_args={"connect_timeout": 2}
        )
        # Test connection
        with engine.connect() as conn:
            pass
        logger.info(f"Connected to PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}")
        return engine
    except Exception as e:
        logger.warning(f"PostgreSQL connection to {db_url} failed ({e}). Falling back to SQLite for local development.")
        return create_engine(sqlite_url, connect_args={"check_same_thread": False})


engine = create_db_engine()

# Enable WAL mode for SQLite to eliminate concurrency-induced corruption on Windows
if engine.dialect.name == "sqlite":
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create tables and idempotently seed the two development tenants and users."""
    Base.metadata.create_all(bind=engine)

    # Automatically add newly introduced columns to existing tables if needed
    try:
        with engine.connect() as conn:
            migration_specs = [
                ("labs", [
                    ("content_hash", "TEXT"),
                    ("build_id", "TEXT"),
                    ("image_digest", "TEXT"),
                    ("build_status", "TEXT DEFAULT 'pending'"),
                    ("build_logs", "TEXT"),
                    ("vulnerability_scan_result", "TEXT"),
                    ("ports", "TEXT"),
                    ("is_demo", "INTEGER DEFAULT 0"),
                    ("state_history", "TEXT"),
                ]),
                ("sessions", [
                    ("target_endpoint", "TEXT"),
                    ("execution_mode", "TEXT DEFAULT 'simulated'"),
                ]),
                ("normalized_events", [
                    ("provenance", "TEXT DEFAULT 'simulated'"),
                ])
            ]
            for table, columns in migration_specs:
                try:
                    if engine.dialect.name == "sqlite":
                        res = conn.exec_driver_sql(f"PRAGMA table_info({table})")
                        existing_cols = {row[1] for row in res.fetchall()}
                    else:
                        res = conn.exec_driver_sql(
                            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'"
                        )
                        existing_cols = {row[0] for row in res.fetchall()}

                    for col_name, col_def in columns:
                        if col_name not in existing_cols:
                            conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                    conn.commit()
                except Exception as ex:
                    logger.debug(f"Schema evolution note for {table}: {ex}")
    except Exception as e:
        logger.debug(f"Schema check error: {e}")

    tenant_specs = {
        "00000000-0000-0000-0000-000000000123": "Default Enterprise (org-123)",
        "00000000-0000-0000-0000-000000000999": "Secondary Enterprise (org-999)",
    }
    user_specs = [
        ("11111111-1111-1111-1111-111111111111", "00000000-0000-0000-0000-000000000123", "red1", "red"),
        ("22222222-2222-2222-2222-222222222222", "00000000-0000-0000-0000-000000000123", "blue1", "blue"),
        ("33333333-3333-3333-3333-333333333333", "00000000-0000-0000-0000-000000000123", "soc1", "soc"),
        ("44444444-4444-4444-4444-444444444444", "00000000-0000-0000-0000-000000000123", "admin1", "admin"),
        ("55555555-5555-5555-5555-555555555555", "00000000-0000-0000-0000-000000000999", "other_tenant_user", "blue"),
    ]
    with SessionLocal() as db:
        for tenant_id, tenant_name in tenant_specs.items():
            if not db.query(Tenant).filter_by(id=tenant_id).first():
                db.add(Tenant(id=tenant_id, name=tenant_name))
        db.commit()
        for user_id, tenant_id, username, role in user_specs:
            if not db.query(User).filter_by(id=user_id).first():
                db.add(User(id=user_id, tenant_id=tenant_id, username=username, role=role))
        db.commit()

        # Seed default dev credentials (admin123) for built-in users if not present
        from shared.auth_routes import _hash_password
        default_hash = _hash_password("admin123")
        for user_id, _, _, _ in user_specs:
            if not db.query(AuthCredential).filter_by(user_id=user_id).first():
                db.add(AuthCredential(
                    user_id=user_id,
                    password_hash=default_hash,
                    is_active=1,
                    password_updated_at=datetime.now(timezone.utc)
                ))
        db.commit()


# Fast dependency for FastAPI
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_context() -> Generator[Session, None, None]:
    """Context manager for background tasks and non-request threads."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
