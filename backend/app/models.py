import datetime
import uuid
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
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


# =====================================================================
# PHASE 10: FORENSIC PLATFORM MODELS
# Multi-tenant isolation designed in: every table has tenant_id column
# =====================================================================

class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("node"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    node_type = Column(String(64), nullable=False, index=True)
    value = Column(String(1024), nullable=False, index=True)
    display_value = Column(String(1024), nullable=True)
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_graph_nodes_tenant_type_val", "tenant_id", "node_type", "value", unique=True),
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("edge"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    from_node_id = Column(String(64), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    to_node_id = Column(String(64), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    edge_type = Column(String(64), nullable=False, index=True)
    metadata_json = Column(Text, nullable=True, default="{}")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_graph_edges_dedup", "tenant_id", "from_node_id", "to_node_id", "edge_type", unique=True),
    )


class ForensicEvent(Base):
    __tablename__ = "forensic_events"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("fevt"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    event_timestamp = Column(DateTime, nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    description = Column(String(1024), nullable=False)
    source = Column(String(64), nullable=False)
    evidence_ref = Column(String(255), nullable=False)


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("case"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True, default="")
    status = Column(String(32), nullable=False, default="open", index=True)  # open | resolved | escalated
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


class CaseItem(Base):
    __tablename__ = "case_items"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("citem"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    added_by = Column(String(128), nullable=False, default="system")

    __table_args__ = (
        Index("ix_case_items_dedup", "tenant_id", "case_id", "scan_id", unique=True),
    )


class CaseComment(Base):
    __tablename__ = "case_comments"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("ccmt"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(128), nullable=False, default="system")
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CaseAudit(Base):
    __tablename__ = "case_audit"

    id = Column(String(64), primary_key=True, default=lambda: generate_id("caud"))
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    target = Column(String(255), nullable=False)
    note = Column(Text, nullable=True)
    actor = Column(String(128), nullable=False, default="system")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)



