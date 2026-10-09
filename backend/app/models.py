import datetime
import uuid
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from .database import Base


def generate_id(prefix: str = "obj") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("scan"))
    target = Column(String(1024), nullable=False, index=True)
    target_type = Column(String(32), nullable=False, index=True)  # url, hash, file
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), nullable=False, default="UNKNOWN")
    confidence = Column(Integer, nullable=False, default=0)
    detection_count = Column(Integer, nullable=False, default=0)
    total_engines = Column(Integer, nullable=False, default=0)
    factors_json = Column(Text, nullable=False, default="[]")
    raw_summary_json = Column(Text, nullable=False, default="{}")
    sources_json = Column(Text, nullable=False, default="{}")
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class WatchlistItem(Base):
    __tablename__ = "watchlist"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("watch"))
    target = Column(String(1024), nullable=False, index=True)
    target_type = Column(String(32), nullable=False, default="url")
    added_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_scanned_at = Column(DateTime, nullable=True)
    last_level = Column(String(32), nullable=True)
    last_score = Column(Integer, nullable=True)
    active = Column(Boolean, nullable=False, default=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("alert"))
    target = Column(String(1024), nullable=False, index=True)
    scan_id = Column(String(64), nullable=False)
    previous_scan_id = Column(String(64), nullable=True)
    kind = Column(String(64), nullable=False)  # level_change, score_jump, threat_escalation
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    seen = Column(Boolean, nullable=False, default=False)


class GeolocationCache(Base):
    __tablename__ = "geolocation_cache"

    ip = Column(String(64), primary_key=True)
    response_json = Column(Text, nullable=False)
    fetched_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("gacc"))
    user_session_id = Column(String(128), nullable=False, default="default_user", index=True)
    email_address = Column(String(255), nullable=True)
    encrypted_refresh_token = Column(Text, nullable=False)
    scopes = Column(String(512), nullable=False, default="https://www.googleapis.com/auth/gmail.readonly")
    connected_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


class InboxMessage(Base):
    __tablename__ = "inbox_messages"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("inbox"))
    account_id = Column(String(64), nullable=False, index=True)
    gmail_id = Column(String(128), nullable=False, unique=True, index=True)
    message_id = Column(String(512), nullable=True, index=True)
    subject = Column(String(1024), nullable=True)
    from_address = Column(String(512), nullable=True)
    from_domain = Column(String(255), nullable=True)
    date = Column(String(128), nullable=True)
    scan_id = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class LLMCache(Base):
    __tablename__ = "llm_cache"

    key = Column(String(64), primary_key=True)
    response_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    ttl_hours = Column(Integer, nullable=False, default=168)


