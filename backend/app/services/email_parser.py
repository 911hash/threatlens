"""
RFC-Compliant Email Parsing Service.

Wraps mail-parser with a resilient fallback mechanism (Python email library)
to ensure it never crashes on corrupted or malformed input.

Constraints strictly preserved:
- Privacy Mode: Email payload and attachments are stream-hashed purely in memory.
- No files or temporary buffers written to disk.
- Header injection prevention: Header fields are HTML-entity-escaped for safe display.
- Attachments are typed, measured, and hashed (SHA-256 / MD5) in memory.
"""

import base64
import email
import email.policy
import hashlib
import mimetypes
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import mailparser
from ..schemas import EmailAttachment, EmailParseResult
from .email_headers import (
    _extract_email_address,
    _extract_ip_from_text,
    escape_header_val,
    escape_headers_dict,
    extract_sender_ips,
)
from .html_sanitizer import sanitize_html

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".ps1xml",
    ".iso",
    ".img",
    ".hta",
    ".cpl",
    ".msc",
    ".jar",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xltm",
    ".lnk",
    ".pif",
}


def _decode_attachment_payload(att: Dict[str, Any]) -> bytes:
    """Safely decode attachment payload in memory without disk I/O."""
    payload = att.get("payload")
    if not payload:
        return b""

    if isinstance(payload, bytes):
        return payload

    encoding = str(att.get("content_transfer_encoding", "")).lower()
    is_binary = att.get("binary", False)

    if encoding == "base64" or is_binary:
        try:
            # Strip whitespace before decoding
            clean_b64 = re.sub(r"\s+", "", str(payload))
            return base64.b64decode(clean_b64)
        except Exception:
            pass

    if isinstance(payload, str):
        return payload.encode("utf-8", errors="replace")

    return b""


def _format_addresses(addr_list: Any) -> List[str]:
    """Convert mailparser address structures into formatted email strings."""
    results: List[str] = []
    if not addr_list:
        return results

    if isinstance(addr_list, list):
        for item in addr_list:
            if isinstance(item, tuple) and len(item) == 2:
                name, addr = item
                if addr:
                    results.append(f"{name} <{addr}>" if name else addr)
                elif name:
                    results.append(name)
            elif isinstance(item, str):
                results.append(item.strip())
    elif isinstance(addr_list, str):
        results.append(addr_list.strip())

    return results


def parse_email(raw_bytes: bytes) -> EmailParseResult:
    """
    Parse email file (.eml or .msg bytes) into a normalized EmailParseResult schema.
    Guarantees no crash on malformed inputs and no disk persistence.
    """
    parse_errors: List[str] = []
    is_malformed = False

    mail_obj = None
    # 1. Primary parse attempt using mail-parser
    try:
        mail_obj = mailparser.parse_from_bytes(raw_bytes)
    except Exception as e:
        parse_errors.append(f"mail-parser failed: {str(e)}")
        is_malformed = True

    # 2. Resilient fallback to Python standard email library if mailparser failed or returned empty
    py_email = None
    try:
        py_email = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as e:
        parse_errors.append(f"Standard email parser encountered errors: {str(e)}")
        is_malformed = True

    # Extract headers
    raw_headers: Dict[str, Any] = {}
    if mail_obj and hasattr(mail_obj, "headers") and isinstance(mail_obj.headers, dict):
        raw_headers = dict(mail_obj.headers)
    elif py_email:
        for k, v in py_email.items():
            if k in raw_headers:
                if isinstance(raw_headers[k], list):
                    raw_headers[k].append(str(v))
                else:
                    raw_headers[k] = [raw_headers[k], str(v)]
            else:
                raw_headers[k] = str(v)

    # Basic header extraction
    subject = None
    date_str = None
    message_id = None
    from_raw = None
    reply_to_raw = None
    to_list: List[str] = []
    cc_list: List[str] = []

    if mail_obj:
        subject = mail_obj.subject or None
        date_str = str(mail_obj.date) if mail_obj.date else None
        message_id = mail_obj.message_id or None
        if mail_obj.from_:
            from_formatted = _format_addresses(mail_obj.from_)
            from_raw = from_formatted[0] if from_formatted else None
        if mail_obj.to:
            to_list = _format_addresses(mail_obj.to)
        if hasattr(mail_obj, "cc") and mail_obj.cc:
            cc_list = _format_addresses(mail_obj.cc)
        if hasattr(mail_obj, "reply_to") and mail_obj.reply_to:
            reply_formatted = _format_addresses(mail_obj.reply_to)
            reply_to_raw = reply_formatted[0] if reply_formatted else None

    # Fallbacks from py_email if any fields missing
    if py_email:
        if not subject and py_email.get("Subject"):
            subject = str(py_email.get("Subject"))
        if not date_str and py_email.get("Date"):
            date_str = str(py_email.get("Date"))
        if not message_id and py_email.get("Message-ID"):
            message_id = str(py_email.get("Message-ID"))
        if not from_raw and py_email.get("From"):
            from_raw = str(py_email.get("From"))
        if not reply_to_raw and py_email.get("Reply-To"):
            reply_to_raw = str(py_email.get("Reply-To"))
        if not to_list and py_email.get("To"):
            to_list = [str(py_email.get("To"))]
        if not cc_list and py_email.get("Cc"):
            cc_list = [str(py_email.get("Cc"))]

    from_addr, from_domain = _extract_email_address(from_raw)

    if not from_raw and not subject and not message_id:
        is_malformed = True
        parse_errors.append("Email lacks standard RFC headers (From, Subject, Message-ID).")

    # Body extraction
    plain_body = None
    html_body = None

    if mail_obj:
        if hasattr(mail_obj, "text_plain") and mail_obj.text_plain:
            plain_body = "\n\n".join(mail_obj.text_plain)
        if hasattr(mail_obj, "text_html") and mail_obj.text_html:
            html_body = "\n\n".join(mail_obj.text_html)

    # Fallback to py_email for body parts
    if py_email and (not plain_body or not html_body):
        try:
            if py_email.is_multipart():
                for part in py_email.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disp.lower():
                        continue
                    if content_type == "text/plain" and not plain_body:
                        plain_body = part.get_content()
                    elif content_type == "text/html" and not html_body:
                        html_body = part.get_content()
            else:
                ct = py_email.get_content_type()
                if ct == "text/plain" and not plain_body:
                    plain_body = py_email.get_content()
                elif ct == "text/html" and not html_body:
                    html_body = py_email.get_content()
        except Exception as e:
            parse_errors.append(f"Body extraction fallback warning: {str(e)}")

    # Sanitize HTML body safely
    sanitized_html = sanitize_html(html_body) if html_body else None

    # Attachments stream-hashed in memory
    attachments: List[EmailAttachment] = []

    if mail_obj and hasattr(mail_obj, "attachments") and mail_obj.attachments:
        for att in mail_obj.attachments:
            try:
                fn = att.get("filename") or att.get("safe_filename") or "unnamed_attachment"
                # Strip directory traversal
                fn = os.path.basename(fn)
                raw_payload = _decode_attachment_payload(att)
                size_bytes = len(raw_payload)
                sha256 = hashlib.sha256(raw_payload).hexdigest()
                md5 = hashlib.md5(raw_payload).hexdigest()
                mime_type = att.get("mail_content_type") or mimetypes.guess_type(fn)[0] or "application/octet-stream"

                # Check extension risk
                _, ext = os.path.splitext(fn.lower())
                is_suspicious = ext in SUSPICIOUS_EXTENSIONS

                attachments.append(
                    EmailAttachment(
                        filename=fn,
                        mime_type=mime_type,
                        size_bytes=size_bytes,
                        sha256=sha256,
                        md5=md5,
                        is_suspicious=is_suspicious,
                    )
                )
            except Exception as att_err:
                parse_errors.append(f"Attachment extraction error: {str(att_err)}")
    elif py_email and py_email.is_multipart():
        # Fallback attachment extraction from py_email
        for part in py_email.walk():
            disp = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp or part.get_filename():
                try:
                    fn = part.get_filename() or "unnamed_attachment"
                    fn = os.path.basename(fn)
                    raw_payload = part.get_payload(decode=True) or b""
                    size_bytes = len(raw_payload)
                    sha256 = hashlib.sha256(raw_payload).hexdigest()
                    md5 = hashlib.md5(raw_payload).hexdigest()
                    mime_type = part.get_content_type() or "application/octet-stream"
                    _, ext = os.path.splitext(fn.lower())
                    is_suspicious = ext in SUSPICIOUS_EXTENSIONS

                    attachments.append(
                        EmailAttachment(
                            filename=fn,
                            mime_type=mime_type,
                            size_bytes=size_bytes,
                            sha256=sha256,
                            md5=md5,
                            is_suspicious=is_suspicious,
                        )
                    )
                except Exception as part_err:
                    parse_errors.append(f"Fallback attachment parse error: {str(part_err)}")

    # Extract sender IPs ordered by hop (closest relay first) and deduplicated
    raw_received: List[str] = []
    if py_email:
        raw_received = [str(r) for r in (py_email.get_all("Received", []) or py_email.get_all("received", []))]
    if not raw_received:
        val = raw_headers.get("Received") or raw_headers.get("received") or []
        if isinstance(val, list):
            raw_received = [str(v) for v in val]
        elif isinstance(val, str):
            raw_received = [val]

    sender_ips = extract_sender_ips(raw_received, raw_headers)

    # Escape all headers for safe display
    safe_headers = escape_headers_dict(raw_headers)

    return EmailParseResult(
        message_id=escape_header_val(message_id) if message_id else None,
        date=escape_header_val(date_str) if date_str else None,
        subject=escape_header_val(subject) if subject else None,
        sender=escape_header_val(from_raw) if from_raw else None,
        from_address=escape_header_val(from_addr) if from_addr else None,
        from_domain=escape_header_val(from_domain) if from_domain else None,
        to_addresses=[escape_header_val(t) for t in to_list],
        cc_addresses=[escape_header_val(c) for c in cc_list],
        reply_to=escape_header_val(reply_to_raw) if reply_to_raw else None,
        headers=safe_headers,
        plain_body=plain_body,
        html_body=html_body,
        sanitized_html=sanitized_html,
        attachments=attachments,
        sender_ips=[escape_header_val(ip) for ip in sender_ips],
        hop_count=len(raw_received),
        is_malformed=is_malformed,
        parse_errors=[escape_header_val(e) for e in parse_errors],
    )
