"""
Case Management Service.
Handles investigation cases, evidence items, comments, and immutable audit trail.

Multi-tenant isolation:
Every query strictly filters by tenant_id.
Every state-changing action writes a row to case_audit.
"""

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import Case, CaseAudit, CaseComment, CaseItem, Scan, generate_id

logger = logging.getLogger("threatlens.case_management")


def _log_audit(
    db: Session,
    case_id: str,
    action: str,
    target: str,
    note: Optional[str] = None,
    actor: str = "system",
    tenant_id: str = "default",
    user_session_id: Optional[str] = None,
) -> CaseAudit:
    """Record an audit row for any state-changing case action."""
    now = datetime.utcnow()
    audit_entry = CaseAudit(
        id=generate_id("caud"),
        tenant_id=tenant_id,
        user_session_id=user_session_id,
        case_id=case_id,
        action=action,
        target=target,
        note=note,
        actor=actor,
        timestamp=now,
    )
    db.add(audit_entry)
    db.flush()
    return audit_entry


def _serialize_case(c: Case, item_count: int = 0, comment_count: int = 0) -> Dict[str, Any]:
    return {
        "id": c.id,
        "tenant_id": c.tenant_id,
        "title": c.title,
        "description": c.description or "",
        "status": c.status,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        "resolved_at": c.resolved_at.isoformat() if c.resolved_at else None,
        "item_count": item_count,
        "comment_count": comment_count,
    }


def _serialize_item(item: CaseItem, scan: Optional[Scan] = None) -> Dict[str, Any]:
    res = {
        "id": item.id,
        "tenant_id": item.tenant_id,
        "case_id": item.case_id,
        "scan_id": item.scan_id,
        "added_at": item.added_at.isoformat() if item.added_at else None,
        "added_by": item.added_by,
    }
    if scan:
        res["scan"] = {
            "id": scan.id,
            "target": scan.target,
            "target_type": scan.target_type,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "confidence": scan.confidence,
            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
            "is_demo": scan.is_demo,
        }
    return res


def _serialize_comment(cmt: CaseComment) -> Dict[str, Any]:
    return {
        "id": cmt.id,
        "tenant_id": cmt.tenant_id,
        "case_id": cmt.case_id,
        "author": cmt.author,
        "body": cmt.body,
        "created_at": cmt.created_at.isoformat() if cmt.created_at else None,
    }


def _serialize_audit(aud: CaseAudit) -> Dict[str, Any]:
    return {
        "id": aud.id,
        "tenant_id": aud.tenant_id,
        "case_id": aud.case_id,
        "action": aud.action,
        "target": aud.target,
        "note": aud.note,
        "actor": aud.actor,
        "timestamp": aud.timestamp.isoformat() if aud.timestamp else None,
    }


def create_case(
    tenant_id: str = "default",
    title: str = "",
    description: str = "",
    actor: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new case and write initial audit entry."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        now = datetime.utcnow()
        case_row = Case(
            id=generate_id("case"),
            tenant_id=tenant_id,
            user_session_id=user_session_id,
            title=title.strip() or "Untitled Investigation",
            description=description.strip(),
            status="open",
            created_at=now,
            updated_at=now,
            resolved_at=None,
        )
        db.add(case_row)
        db.flush()

        _log_audit(
            db=db,
            case_id=case_row.id,
            action="case_created",
            target=case_row.id,
            note=f"Case created: {case_row.title}",
            actor=actor,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_case(case_row)
    finally:
        if close_db:
            db.close()


def get_case(
    case_id: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve full case details: case + items + comments + audit log."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        # Fetch linked items
        iq = db.query(CaseItem).filter(CaseItem.case_id == case_id, CaseItem.tenant_id == tenant_id)
        if user_session_id is not None:
            iq = iq.filter(CaseItem.user_session_id == user_session_id)
        items = iq.order_by(CaseItem.added_at.desc()).all()
        scan_ids = [it.scan_id for it in items]
        scans_by_id = {}
        if scan_ids:
            scans_q = db.query(Scan).filter(Scan.id.in_(scan_ids))
            if user_session_id is not None:
                scans_q = scans_q.filter(Scan.user_session_id == user_session_id)
            scans = scans_q.all()
            scans_by_id = {s.id: s for s in scans}

        serialized_items = [_serialize_item(it, scans_by_id.get(it.scan_id)) for it in items]

        # Fetch comments
        cmq = db.query(CaseComment).filter(CaseComment.case_id == case_id, CaseComment.tenant_id == tenant_id)
        if user_session_id is not None:
            cmq = cmq.filter(CaseComment.user_session_id == user_session_id)
        comments = cmq.order_by(CaseComment.created_at.asc()).all()
        serialized_comments = [_serialize_comment(c) for c in comments]

        # Fetch audit entries
        aq = db.query(CaseAudit).filter(CaseAudit.case_id == case_id, CaseAudit.tenant_id == tenant_id)
        if user_session_id is not None:
            aq = aq.filter(CaseAudit.user_session_id == user_session_id)
        audits = aq.order_by(CaseAudit.timestamp.desc()).all()
        serialized_audits = [_serialize_audit(a) for a in audits]

        res = _serialize_case(case, item_count=len(items), comment_count=len(comments))
        res["items"] = serialized_items
        res["comments"] = serialized_comments
        res["audit"] = serialized_audits
        return res
    finally:
        if close_db:
            db.close()


def list_cases(
    tenant_id: str = "default",
    status: Optional[str] = None,
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List cases for tenant, optionally filtered by status ('open', 'resolved', 'escalated')."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        query = db.query(Case).filter(Case.tenant_id == tenant_id)
        if user_session_id is not None:
            query = query.filter(Case.user_session_id == user_session_id)
        if status:
            query = query.filter(Case.status == status.lower().strip())

        cases = query.order_by(Case.updated_at.desc()).all()

        results = []
        for c in cases:
            item_q = db.query(CaseItem).filter(CaseItem.case_id == c.id, CaseItem.tenant_id == tenant_id)
            if user_session_id is not None:
                item_q = item_q.filter(CaseItem.user_session_id == user_session_id)
            item_cnt = item_q.count()

            comment_q = db.query(CaseComment).filter(CaseComment.case_id == c.id, CaseComment.tenant_id == tenant_id)
            if user_session_id is not None:
                comment_q = comment_q.filter(CaseComment.user_session_id == user_session_id)
            comment_cnt = comment_q.count()
            results.append(_serialize_case(c, item_count=item_cnt, comment_count=comment_cnt))

        return results
    finally:
        if close_db:
            db.close()


def add_scan_to_case(
    case_id: str,
    scan_id: str,
    tenant_id: str = "default",
    actor: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Add a scan/email to a case. Idempotent: avoids duplicate item rows."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        sq = db.query(Scan).filter(Scan.id == scan_id)
        if user_session_id is not None:
            sq = sq.filter(Scan.user_session_id == user_session_id)
        scan = sq.first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        ei_q = (
            db.query(CaseItem)
            .filter(
                CaseItem.tenant_id == tenant_id,
                CaseItem.case_id == case_id,
                CaseItem.scan_id == scan_id,
            )
        )
        if user_session_id is not None:
            ei_q = ei_q.filter(CaseItem.user_session_id == user_session_id)
        existing_item = ei_q.first()

        now = datetime.utcnow()
        if existing_item:
            return _serialize_item(existing_item, scan)

        item = CaseItem(
            id=generate_id("citem"),
            tenant_id=tenant_id,
            user_session_id=user_session_id,
            case_id=case_id,
            scan_id=scan_id,
            added_at=now,
            added_by=actor,
        )
        db.add(item)
        case.updated_at = now

        _log_audit(
            db=db,
            case_id=case_id,
            action="scan_added",
            target=scan_id,
            note=f"Scan {scan.target[:40]} linked to case",
            actor=actor,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_item(item, scan)
    finally:
        if close_db:
            db.close()


def add_comment(
    case_id: str,
    body: str,
    tenant_id: str = "default",
    author: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Add an analyst comment to a case and log audit row."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        now = datetime.utcnow()
        clean_body = body.strip()
        comment = CaseComment(
            id=generate_id("ccmt"),
            tenant_id=tenant_id,
            user_session_id=user_session_id,
            case_id=case_id,
            author=author,
            body=clean_body,
            created_at=now,
        )
        db.add(comment)
        case.updated_at = now

        _log_audit(
            db=db,
            case_id=case_id,
            action="comment_added",
            target=comment.id,
            note=clean_body[:80],
            actor=author,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_comment(comment)
    finally:
        if close_db:
            db.close()


def escalate_case(
    case_id: str,
    note: str,
    tenant_id: str = "default",
    actor: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Escalate case status to 'escalated' with audit record."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        now = datetime.utcnow()
        case.status = "escalated"
        case.updated_at = now

        _log_audit(
            db=db,
            case_id=case_id,
            action="case_escalated",
            target=case_id,
            note=note.strip(),
            actor=actor,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_case(case)
    finally:
        if close_db:
            db.close()


def resolve_case(
    case_id: str,
    note: str,
    tenant_id: str = "default",
    actor: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Resolve case with required note and set resolved_at timestamp."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        now = datetime.utcnow()
        case.status = "resolved"
        case.resolved_at = now
        case.updated_at = now

        _log_audit(
            db=db,
            case_id=case_id,
            action="case_resolved",
            target=case_id,
            note=note.strip(),
            actor=actor,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_case(case)
    finally:
        if close_db:
            db.close()


def reopen_case(
    case_id: str,
    note: str,
    tenant_id: str = "default",
    actor: str = "system",
    db: Optional[Session] = None,
    user_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Reopen a resolved case."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        cq = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id)
        if user_session_id is not None:
            cq = cq.filter(Case.user_session_id == user_session_id)
        case = cq.first()
        if not case:
            return None

        now = datetime.utcnow()
        case.status = "open"
        case.resolved_at = None
        case.updated_at = now

        _log_audit(
            db=db,
            case_id=case_id,
            action="case_reopened",
            target=case_id,
            note=note.strip(),
            actor=actor,
            tenant_id=tenant_id,
            user_session_id=user_session_id,
        )

        db.commit()
        return _serialize_case(case)
    finally:
        if close_db:
            db.close()
