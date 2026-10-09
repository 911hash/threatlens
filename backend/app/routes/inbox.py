"""
Inbox routes: paginated listing of synced Gmail emails, manual sync triggers with rate limiting,
and full scan forensic detail retrieval.
"""

from datetime import datetime, timedelta
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import GmailAccount, InboxMessage, Scan
from ..routes.analyze import serialize_scan_response
from ..services.gmail_sync import sync_inbox

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/inbox", tags=["Inbox"])


class InboxItemResponse(BaseModel):
    gmail_id: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    date: Optional[str] = None
    risk_score: int
    risk_level: str
    has_geo: bool
    has_ai: bool
    scan_id: str


class SyncResponse(BaseModel):
    status: str
    synced_count: int
    last_sync_at: Optional[str] = None


@router.get("", response_model=List[InboxItemResponse])
def get_inbox_messages(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """
    Get paginated list of synced inbox messages with risk assessment badges.
    """
    offset = (page - 1) * limit
    inbox_items = (
        db.query(InboxMessage)
        .order_by(InboxMessage.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    results: List[InboxItemResponse] = []
    for item in inbox_items:
        scan = db.query(Scan).filter(Scan.id == item.scan_id).first()
        risk_score = scan.risk_score if scan else 0
        risk_level = scan.risk_level if scan else "UNKNOWN"
        has_geo = False
        has_ai = False

        if scan and scan.raw_summary_json:
            try:
                raw_summary = json.loads(scan.raw_summary_json)
                has_geo = bool(raw_summary.get("geo_results"))
                has_ai = bool(
                    raw_summary.get("llm_reasoning")
                    or raw_summary.get("llm_result")
                    or raw_summary.get("ai_analysis")
                )
            except Exception:
                pass

        results.append(
            InboxItemResponse(
                gmail_id=item.gmail_id,
                message_id=item.message_id,
                subject=item.subject or "(No Subject)",
                from_address=item.from_address or "",
                from_domain=item.from_domain or "",
                date=item.date or "",
                risk_score=risk_score,
                risk_level=risk_level,
                has_geo=has_geo,
                has_ai=has_ai,
                scan_id=item.scan_id,
            )
        )

    return results


@router.post("/sync", response_model=SyncResponse)
async def trigger_inbox_sync(db: Session = Depends(get_db)):
    """
    Trigger manual inbox synchronization for active connected Gmail account.
    Enforces a strict 30-second rate limit per account.
    """
    account = (
        db.query(GmailAccount)
        .filter(GmailAccount.user_session_id == "default_user", GmailAccount.is_active == True)
        .first()
    )

    if not account:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "NO_ACCOUNT_CONNECTED", "message": "No active Gmail account is connected."},
        )

    # 30-second rate limit check
    if account.last_sync_at:
        elapsed = (datetime.utcnow() - account.last_sync_at).total_seconds()
        if elapsed < 30:
            remaining = int(30 - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "SYNC_RATE_LIMITED",
                    "message": f"Sync rate limit active. Please wait {remaining} seconds before syncing again.",
                    "retry_after_seconds": remaining,
                },
            )

    try:
        synced_count = await sync_inbox(account, db, max_results=25)
    except Exception as e:
        logger.exception("Manual inbox sync failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "SYNC_FAILED", "message": f"Failed to sync Gmail inbox: {str(e)}"},
        )

    return SyncResponse(
        status="success",
        synced_count=synced_count,
        last_sync_at=account.last_sync_at.isoformat() if account.last_sync_at else None,
    )


@router.get("/{gmail_id}")
def get_inbox_message_detail(gmail_id: str, db: Session = Depends(get_db)):
    """
    Get full forensic scan detail for a specific Gmail inbox email.
    """
    inbox_item = db.query(InboxMessage).filter(InboxMessage.gmail_id == gmail_id).first()
    if not inbox_item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "MESSAGE_NOT_FOUND", "message": f"Inbox message with Gmail ID '{gmail_id}' not found."},
        )

    scan = db.query(Scan).filter(Scan.id == inbox_item.scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_NOT_FOUND", "message": f"Associated forensic scan for Gmail ID '{gmail_id}' not found."},
        )

    scan_resp = serialize_scan_response(scan)
    resp_dict = scan_resp.model_dump()

    # Merge inbox item fields and raw summary forensic details
    resp_dict["gmail_id"] = inbox_item.gmail_id
    resp_dict["message_id"] = inbox_item.message_id
    resp_dict["from_address"] = inbox_item.from_address
    resp_dict["from_domain"] = inbox_item.from_domain
    resp_dict["subject"] = inbox_item.subject
    resp_dict["date"] = inbox_item.date

    raw_summary = resp_dict.get("raw_summary", {})
    resp_dict["auth_result"] = raw_summary.get("auth_result")
    resp_dict["header_analysis"] = raw_summary.get("header_analysis")
    resp_dict["attachments"] = raw_summary.get("attachments", [])
    resp_dict["sanitized_html"] = raw_summary.get("sanitized_html")
    resp_dict["plain_body"] = raw_summary.get("plain_body")
    resp_dict["ai_analysis"] = (
        raw_summary.get("llm_reasoning")
        or raw_summary.get("llm_result")
        or raw_summary.get("ai_analysis")
    )
    resp_dict["llm_result"] = resp_dict["ai_analysis"]
    resp_dict["anonymized_prompt"] = raw_summary.get("anonymized_prompt")
    resp_dict["geo_results"] = raw_summary.get("geo_results", [])

    return resp_dict
