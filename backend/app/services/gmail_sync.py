"""
Gmail Inbox Synchronization Service.
Fetches up to 20 emails from connected Gmail accounts via Google API,
converts Gmail payloads to RFC822 bytes, runs forensic email parsing + geolocation + risk scoring,
and persists scans and inbox messages.
Handles 401 unauthorized errors with token refresh and graceful disconnect.
"""

import base64
from datetime import datetime
from email.message import EmailMessage
import logging
from typing import Any, Dict, List, Optional, Tuple
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

from ..models import GmailAccount, InboxMessage, Scan, generate_id
from ..services.email_forensics import process_email_forensics
from ..services.email_parser import parse_email
from ..services.gmail_oauth import (
    build_credentials_from_refresh_token,
    decrypt_token,
    encrypt_token,
    refresh_if_needed,
)

logger = logging.getLogger(__name__)


def _decode_b64url(data_str: str) -> bytes:
    """Decode base64url data safely handling missing padding."""
    if not data_str:
        return b""
    clean = data_str.strip().replace("-", "+").replace("_", "/")
    rem = len(clean) % 4
    if rem:
        clean += "=" * (4 - rem)
    try:
        return base64.b64decode(clean)
    except Exception:
        return b""


def convert_gmail_message_to_rfc822(msg_data: dict) -> bytes:
    """
    Convert a Gmail API message representation (format='full' or format='raw')
    into standardized RFC822 bytes suitable for existing email_parser.
    """
    # 1. Direct raw format if present
    if "raw" in msg_data and msg_data["raw"]:
        return _decode_b64url(msg_data["raw"])

    # 2. Reconstruct from format='full' payload
    payload = msg_data.get("payload", {})
    headers = payload.get("headers", [])

    msg = EmailMessage()

    # Populate RFC headers
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        if name and value:
            if name.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                continue
            # Handle folded or duplicate headers safely
            try:
                msg[name] = value
            except Exception:
                pass

    # Ensure Message-ID exists
    if not msg.get("Message-ID") and msg_data.get("id"):
        msg["Message-ID"] = f"<{msg_data['id']}@gmail.com>"

    # Helper to extract body parts
    def _extract_parts(part_dict: Dict[str, Any], target_msg: EmailMessage):
        mime_type = part_dict.get("mimeType", "").lower()
        body = part_dict.get("body", {})
        data_str = body.get("data", "")
        filename = part_dict.get("filename", "")
        parts = part_dict.get("parts", [])

        if parts:
            for subpart in parts:
                _extract_parts(subpart, target_msg)
            return

        if filename:
            # Attachment
            att_data = _decode_b64url(data_str) if data_str else b""
            if "/" in mime_type:
                maintype, subtype = mime_type.split("/", 1)
            else:
                maintype, subtype = "application", "octet-stream"
            try:
                target_msg.add_attachment(att_data, maintype=maintype, subtype=subtype, filename=filename)
            except Exception:
                pass
        elif mime_type == "text/html":
            html_text = _decode_b64url(data_str).decode("utf-8", errors="replace")
            try:
                if not target_msg.is_multipart() and not target_msg.get_payload():
                    target_msg.set_content(html_text, subtype="html")
                else:
                    target_msg.add_alternative(html_text, subtype="html")
            except Exception:
                pass
        elif mime_type == "text/plain":
            plain_text = _decode_b64url(data_str).decode("utf-8", errors="replace")
            try:
                if not target_msg.is_multipart() and not target_msg.get_payload():
                    target_msg.set_content(plain_text, subtype="plain")
                else:
                    target_msg.add_alternative(plain_text, subtype="plain")
            except Exception:
                pass
        elif data_str:
            # Other fallback body
            raw_content = _decode_b64url(data_str).decode("utf-8", errors="replace")
            try:
                if not target_msg.is_multipart() and not target_msg.get_payload():
                    target_msg.set_content(raw_content, subtype="plain")
                else:
                    target_msg.add_alternative(raw_content, subtype="plain")
            except Exception:
                pass

    _extract_parts(payload, msg)

    # Fallback default empty content if none was added
    if not msg.get_payload() and not msg.is_multipart():
        try:
            msg.set_content(msg_data.get("snippet", ""), subtype="plain")
        except Exception:
            pass

    return msg.as_bytes()


def get_gmail_service_with_retry(account: GmailAccount, db: Session):
    """
    Build Gmail API service client with automatic 401 token refresh.
    If a second 401 is encountered, marks account disconnected.
    """
    refresh_token = decrypt_token(account.encrypted_refresh_token)
    credentials = build_credentials_from_refresh_token(refresh_token)

    try:
        credentials.refresh(Request())
        # Update encrypted token if refreshed
        if credentials.refresh_token and credentials.refresh_token != refresh_token:
            account.encrypted_refresh_token = encrypt_token(credentials.refresh_token)
            db.commit()
    except (RefreshError, HttpError) as e:
        logger.warning("Token refresh failed for account %s: %s", account.id, e)
        account.is_active = False
        db.commit()
        raise

    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
    return service, credentials


def fetch_messages(
    account: GmailAccount,
    db: Session,
    max_results: int = 25,
    service_override=None,
) -> List[Tuple[str, bytes]]:
    """
    Fetch up to max_results messages from INBOX label via Gmail API.
    Handles 401 error with single retry before marking account disconnected.
    """
    if service_override is not None:
        service = service_override
    else:
        try:
            service, _ = get_gmail_service_with_retry(account, db)
        except Exception:
            return []

    # Execute messages list with 401 handling
    try:
        res = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=max_results,
        ).execute()
    except HttpError as e:
        if e.resp.status == 401:
            logger.warning("Encountered 401 on messages.list, refreshing token...")
            try:
                service, _ = get_gmail_service_with_retry(account, db)
                res = service.users().messages().list(
                    userId="me",
                    labelIds=["INBOX"],
                    maxResults=max_results,
                ).execute()
            except Exception as retry_err:
                logger.error("Second 401 / failure. Marking account disconnected: %s", retry_err)
                account.is_active = False
                db.commit()
                return []
        else:
            logger.error("Gmail API list error: %s", e)
            return []
    except Exception as e:
        logger.error("Error listing Gmail messages: %s", e)
        return []

    msg_items = res.get("messages", [])
    fetched: List[Tuple[str, bytes]] = []

    for item in msg_items:
        msg_id = item.get("id")
        if not msg_id:
            continue

        try:
            try:
                msg_data = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="raw",
                ).execute()
            except Exception:
                msg_data = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="full",
                ).execute()
            rfc822_bytes = convert_gmail_message_to_rfc822(msg_data)
            fetched.append((msg_id, rfc822_bytes))
        except HttpError as e:
            if e.resp.status == 401:
                try:
                    service, _ = get_gmail_service_with_retry(account, db)
                    try:
                        msg_data = service.users().messages().get(
                            userId="me",
                            id=msg_id,
                            format="raw",
                        ).execute()
                    except Exception:
                        msg_data = service.users().messages().get(
                            userId="me",
                            id=msg_id,
                            format="full",
                        ).execute()
                    rfc822_bytes = convert_gmail_message_to_rfc822(msg_data)
                    fetched.append((msg_id, rfc822_bytes))
                except Exception:
                    account.is_active = False
                    db.commit()
                    break
            else:
                logger.warning("Failed to fetch message %s: %s", msg_id, e)
        except Exception as e:
            logger.warning("Error fetching Gmail message %s: %s", msg_id, e)

    return fetched


async def sync_inbox(
    account: GmailAccount,
    db: Session,
    max_results: int = 25,
    service_override=None,
) -> int:
    """
    Fetch new messages from Gmail, skip already stored Message-IDs/gmail_ids,
    run full forensics pipeline, persist scans, and return count of newly ingested messages.
    """
    messages_data = fetch_messages(account, db, max_results=max_results, service_override=service_override)
    new_count = 0

    for gmail_id, raw_bytes in messages_data:
        # 1. Skip if gmail_id already stored
        existing_inbox = db.query(InboxMessage).filter(InboxMessage.gmail_id == gmail_id).first()
        if existing_inbox:
            continue

        # 2. Parse lightweight metadata to extract Message-ID
        parsed = parse_email(raw_bytes)
        target_msg_id = parsed.message_id.strip() if parsed.message_id else None

        if target_msg_id:
            # Skip if Message-ID already stored in inbox_messages or scans
            existing_msg_id = db.query(InboxMessage).filter(InboxMessage.message_id == target_msg_id).first()
            if existing_msg_id:
                continue
            existing_scan = db.query(Scan).filter(Scan.target == target_msg_id).first()
            if existing_scan:
                continue

        # 3. Run full forensic analysis pipeline (Strict Privacy Mode: purely in memory)
        try:
            scan, analysis = await process_email_forensics(
                raw_bytes=raw_bytes,
                filename=f"gmail_{gmail_id}.eml",
                hash_only=False,
                db=db,
                gmail_id=gmail_id,
            )

            # 4. Persist inbox message entry
            inbox_entry = InboxMessage(
                id=generate_id("inbox"),
                account_id=account.id,
                gmail_id=gmail_id,
                message_id=target_msg_id or scan.target,
                subject=parsed.subject or "(No Subject)",
                from_address=parsed.from_address or "",
                from_domain=parsed.from_domain or "",
                date=parsed.date or datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000"),
                scan_id=scan.id,
                created_at=datetime.utcnow(),
            )
            db.add(inbox_entry)
            db.commit()
            new_count += 1
        except Exception as e:
            logger.exception("Error processing email forensic pipeline for gmail_id %s: %s", gmail_id, e)
            db.rollback()

    account.last_sync_at = datetime.utcnow()
    db.commit()

    return new_count
