"""
Retention Policy Purge Service.
Purges stale graph elements and old resolved investigation cases.

Configurable via environment variables:
- GRAPH_RETENTION_DAYS (default 90)
- CASE_RETENTION_DAYS (default 180)

Guardrails:
- Never purges active (unresolved or open/escalated) cases.
- Purge job logs counts ONLY, never node values or sensitive data.
- Cascades items, comments, and audit records on case purge.
"""

from datetime import datetime, timedelta
import logging
import os
from typing import Dict, Optional
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import Case, CaseAudit, CaseComment, CaseItem, GraphEdge, GraphNode

logger = logging.getLogger("threatlens.retention")


def get_retention_days() -> tuple[int, int]:
    """Retrieve retention thresholds in days."""
    try:
        graph_days = int(os.getenv("GRAPH_RETENTION_DAYS", "90"))
    except ValueError:
        graph_days = 90

    try:
        case_days = int(os.getenv("CASE_RETENTION_DAYS", "180"))
    except ValueError:
        case_days = 180

    return graph_days, case_days


def purge_expired(
    tenant_id: Optional[str] = None,
    db: Optional[Session] = None,
) -> Dict[str, int]:
    """
    Purge expired graph nodes/edges and resolved cases older than retention periods.
    Logs counts ONLY. Never purges unresolved/open cases.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        graph_days, case_days = get_retention_days()
        now = datetime.utcnow()
        graph_cutoff = now - timedelta(days=graph_days)
        case_cutoff = now - timedelta(days=case_days)

        # 1. Purge expired Graph Edges
        edge_query = db.query(GraphEdge).filter(GraphEdge.last_seen_at < graph_cutoff)
        if tenant_id:
            edge_query = edge_query.filter(GraphEdge.tenant_id == tenant_id)
        edges_purged = edge_query.delete(synchronize_session=False)

        # 2. Purge expired Graph Nodes
        node_query = db.query(GraphNode).filter(GraphNode.last_seen_at < graph_cutoff)
        if tenant_id:
            node_query = node_query.filter(GraphNode.tenant_id == tenant_id)
        nodes_purged = node_query.delete(synchronize_session=False)

        # 3. Purge expired Resolved Cases (Never delete cases where status != 'resolved')
        case_query = db.query(Case).filter(
            Case.status == "resolved",
            Case.resolved_at.isnot(None),
            Case.resolved_at < case_cutoff,
        )
        if tenant_id:
            case_query = case_query.filter(Case.tenant_id == tenant_id)

        expired_cases = case_query.all()
        cases_purged = len(expired_cases)

        if expired_cases:
            expired_case_ids = [c.id for c in expired_cases]

            # Cascade: delete items, comments, and audit rows
            db.query(CaseItem).filter(CaseItem.case_id.in_(expired_case_ids)).delete(synchronize_session=False)
            db.query(CaseComment).filter(CaseComment.case_id.in_(expired_case_ids)).delete(synchronize_session=False)
            db.query(CaseAudit).filter(CaseAudit.case_id.in_(expired_case_ids)).delete(synchronize_session=False)
            for c in expired_cases:
                db.delete(c)

        db.commit()

        # Log counts ONLY, never node values
        logger.info(
            "Retention purge completed: purged %d graph edges, %d graph nodes, %d resolved cases",
            edges_purged,
            nodes_purged,
            cases_purged,
        )

        return {
            "edges_purged": edges_purged,
            "nodes_purged": nodes_purged,
            "cases_purged": cases_purged,
        }
    except Exception as e:
        logger.exception("Error during retention purge: %s", e)
        db.rollback()
        raise
    finally:
        if close_db:
            db.close()
