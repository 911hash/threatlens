"""
Forensic Timeline Service.
Constructs chronological timeline of events per scan:
- domain_registered (from RDAP)
- certificate_issued (from crt.sh)
- email_sent (from email Date header)
- email_delivered (from last Received hop timestamp)
- url_first_seen (from VirusTotal telemetry)
- attachment_first_seen (from VirusTotal telemetry)

Strict Privacy Mode:
Descriptions are plain text referencing scan/indicators, never raw email content.
Missing sources produce no event, not a placeholder.
Timeline is cached in forensic_events table on first build.
"""

from datetime import datetime, timezone
import email.utils
import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import ForensicEvent, Scan, generate_id

logger = logging.getLogger("threatlens.forensic_timeline")


def _parse_timestamp(val: Any) -> Optional[datetime]:
    """Resiliently parse date/timestamp into UTC datetime."""
    if not val:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is not None:
            return val.astimezone(timezone.utc).replace(tzinfo=None)
        return val

    # Unix timestamp (integer / float / numeric string)
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc).replace(tzinfo=None)
        except Exception:
            return None

    s = str(val).strip()
    if s.isdigit():
        try:
            return datetime.fromtimestamp(int(s), tz=timezone.utc).replace(tzinfo=None)
        except Exception:
            pass

    # RFC 2822 Email Date Header e.g. "Mon, 10 Oct 2026 12:00:00 +0000"
    try:
        parsed_email_dt = email.utils.parsedate_to_datetime(s)
        if parsed_email_dt:
            return parsed_email_dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        pass

    # ISO 8601 strings e.g. "2026-10-06T00:00:00Z"
    try:
        clean_iso = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        pass

    return None


def _serialize_event(ev: ForensicEvent) -> Dict[str, Any]:
    return {
        "id": ev.id,
        "tenant_id": ev.tenant_id,
        "scan_id": ev.scan_id,
        "event_timestamp": ev.event_timestamp.isoformat() if ev.event_timestamp else None,
        "category": ev.category,
        "description": ev.description,
        "source": ev.source,
        "evidence_ref": ev.evidence_ref,
    }


def build_timeline(
    scan_id: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
    force_rebuild: bool = False,
    user_session_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Constructs or retrieves cached chronological forensic timeline for a scan.
    Returns list of ForensicEvent sorted ascending by event_timestamp.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        # Check cache if not force rebuild
        if not force_rebuild:
            cached_query = (
                db.query(ForensicEvent)
                .filter(
                    ForensicEvent.scan_id == scan_id,
                    ForensicEvent.tenant_id == tenant_id,
                )
            )
            if user_session_id is not None:
                cached_query = cached_query.filter(ForensicEvent.user_session_id == user_session_id)
            cached = cached_query.order_by(ForensicEvent.event_timestamp.asc()).all()
            if cached:
                return [_serialize_event(e) for e in cached]

        scan_q = db.query(Scan).filter(Scan.id == scan_id)
        if user_session_id is not None:
            scan_q = scan_q.filter(Scan.user_session_id == user_session_id)
        scan = scan_q.first()
        if not scan:
            return []

        raw_summary: Dict[str, Any] = {}
        sources: Dict[str, Any] = {}
        try:
            raw_summary = json.loads(scan.raw_summary_json or "{}")
        except Exception:
            pass
        try:
            sources = json.loads(scan.sources_json or "{}")
        except Exception:
            pass

        events: List[Dict[str, Any]] = []

        # 1. domain_registered (from RDAP domain age)
        rdap_data = None
        if "RDAP" in sources and isinstance(sources["RDAP"], dict):
            rdap_data = sources["RDAP"].get("data")
        elif "rdap" in sources and isinstance(sources["rdap"], dict):
            rdap_data = sources["rdap"].get("data")
        elif "rdap" in raw_summary and isinstance(raw_summary["rdap"], dict):
            rdap_data = raw_summary["rdap"].get("data") or raw_summary["rdap"]

        if rdap_data and isinstance(rdap_data, dict):
            reg_date_str = rdap_data.get("registration_date")
            dt = _parse_timestamp(reg_date_str)
            if dt:
                domain_name = rdap_data.get("domain", "Domain")
                registrar = rdap_data.get("registrar", "Registrar")
                events.append({
                    "event_timestamp": dt,
                    "category": "domain_registered",
                    "description": f"Domain {domain_name} registered via {registrar}",
                    "source": "RDAP",
                    "evidence_ref": scan_id,
                })

        # 2. certificate_issued (from crt.sh)
        crt_data = None
        if "crt.sh" in sources and isinstance(sources["crt.sh"], dict):
            crt_data = sources["crt.sh"].get("data")
        elif "crtsh" in sources and isinstance(sources["crtsh"], dict):
            crt_data = sources["crtsh"].get("data")
        elif "crt_sh" in sources and isinstance(sources["crt_sh"], dict):
            crt_data = sources["crt_sh"].get("data")

        if crt_data and isinstance(crt_data, dict):
            recent_entries = crt_data.get("recent_entries") or []
            if recent_entries and isinstance(recent_entries, list):
                # Earliest or most relevant entry
                for entry in recent_entries:
                    if isinstance(entry, dict) and entry.get("entry_timestamp"):
                        dt = _parse_timestamp(entry.get("entry_timestamp"))
                        if dt:
                            issuer = entry.get("issuer") or "Certificate Authority"
                            events.append({
                                "event_timestamp": dt,
                                "category": "certificate_issued",
                                "description": f"TLS Certificate issued by {issuer[:60]}",
                                "source": "crt.sh",
                                "evidence_ref": scan_id,
                            })
                            break

        # 3. email_sent (from email Date header)
        date_str = raw_summary.get("date")
        if date_str:
            dt = _parse_timestamp(date_str)
            if dt:
                events.append({
                    "event_timestamp": dt,
                    "category": "email_sent",
                    "description": "Email dispatched by sender mail client",
                    "source": "Email Header",
                    "evidence_ref": scan_id,
                })

        # 4. email_delivered (from last Received hop timestamp)
        header_analysis = raw_summary.get("header_analysis") or {}
        hops = header_analysis.get("hops") or []
        if hops and isinstance(hops, list):
            # Evaluate hops for delivery timestamp
            hop_timestamps = []
            for h in hops:
                if isinstance(h, dict) and h.get("timestamp"):
                    h_dt = _parse_timestamp(h.get("timestamp"))
                    if h_dt:
                        hop_timestamps.append(h_dt)
            if hop_timestamps:
                # The latest hop timestamp is the final delivery / intake hop
                delivered_dt = max(hop_timestamps)
                events.append({
                    "event_timestamp": delivered_dt,
                    "category": "email_delivered",
                    "description": "Email received by destination mail transfer agent",
                    "source": "Received Hops",
                    "evidence_ref": scan_id,
                })

        # 5. url_first_seen (from VirusTotal if available)
        vt_url_data = None
        if "VirusTotal" in sources and isinstance(sources["VirusTotal"], dict):
            vt_url_data = sources["VirusTotal"].get("data")
        elif "virustotal" in sources and isinstance(sources["virustotal"], dict):
            vt_url_data = sources["virustotal"].get("data")

        if vt_url_data and isinstance(vt_url_data, dict):
            first_sub = vt_url_data.get("first_submission_date")
            if first_sub:
                dt = _parse_timestamp(first_sub)
                if dt:
                    events.append({
                        "event_timestamp": dt,
                        "category": "url_first_seen",
                        "description": "Indicator first submitted to VirusTotal telemetry",
                        "source": "VirusTotal",
                        "evidence_ref": scan_id,
                    })

        # 6. attachment_first_seen (from VirusTotal if available for attachments)
        attachments = raw_summary.get("attachments") or []
        for att in attachments:
            if isinstance(att, dict) and att.get("vt_first_seen"):
                dt = _parse_timestamp(att.get("vt_first_seen"))
                if dt:
                    events.append({
                        "event_timestamp": dt,
                        "category": "attachment_first_seen",
                        "description": f"Attachment hash ({att.get('filename', 'file')}) first observed on VirusTotal",
                        "source": "VirusTotal",
                        "evidence_ref": scan_id,
                    })
                    break

        # Sort ascending chronologically
        events.sort(key=lambda x: x["event_timestamp"])

        # Cache in forensic_events table
        if force_rebuild:
            del_q = db.query(ForensicEvent).filter(
                ForensicEvent.scan_id == scan_id,
                ForensicEvent.tenant_id == tenant_id,
            )
            if user_session_id is not None:
                del_q = del_q.filter(ForensicEvent.user_session_id == user_session_id)
            del_q.delete()

        persisted_events: List[ForensicEvent] = []
        for ev in events:
            row = ForensicEvent(
                id=generate_id("fevt"),
                tenant_id=tenant_id,
                user_session_id=user_session_id,
                scan_id=scan_id,
                event_timestamp=ev["event_timestamp"],
                category=ev["category"],
                description=ev["description"],
                source=ev["source"],
                evidence_ref=ev["evidence_ref"],
            )
            db.add(row)
            persisted_events.append(row)

        db.commit()

        return [_serialize_event(e) for e in persisted_events]
    finally:
        if close_db:
            db.close()
