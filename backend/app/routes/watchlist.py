"""
Watchlist and alert notification endpoints.
Supports auto-rescan, drift detection, and SOC alerting.
"""

from datetime import datetime
import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Scan, WatchlistItem, generate_id
from ..risk_engine import (
    LEVEL_THRESHOLDS,
    NormalizedEvidence,
    _generate_plain_english_explanation,
    evaluate,
)
from ..schemas import AlertResponse, WatchlistCreate, WatchlistResponse
from ..services.attack_chain import build_attack_chain
from ..services.comparison import compare_scans
from ..services.dns_rdap import lookup_crtsh, lookup_rdap, resolve_dns
from ..services.feeds import lookup_openphish, lookup_urlhaus
from ..services.safe_browsing import lookup_safe_browsing
from ..services.url_analysis import refang_target, trace_url_redirects, validate_url_syntax
from ..services.virustotal import VT_API_KEY, lookup_virustotal_hash, lookup_virustotal_url
from ..session import get_or_create_session_id

router = APIRouter(prefix="/api", tags=["Watchlist & Alerts"])

SEVERITY_ORDER = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "UNKNOWN": 5,
}


@router.get("/watchlist", response_model=List[WatchlistResponse])
def get_watchlist(request: Request, response: Response, db: Session = Depends(get_db)):
    session_id = get_or_create_session_id(request, response)
    items = (
        db.query(WatchlistItem)
        .filter(WatchlistItem.user_session_id == session_id)
        .order_by(WatchlistItem.added_at.desc())
        .all()
    )
    return items


@router.post("/watchlist", response_model=WatchlistResponse, status_code=status.HTTP_201_CREATED)
def add_to_watchlist(
    req: WatchlistCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    target = req.target.strip()
    existing = (
        db.query(WatchlistItem)
        .filter(WatchlistItem.target == target, WatchlistItem.user_session_id == session_id)
        .first()
    )
    if existing:
        existing.active = True
        db.commit()
        db.refresh(existing)
        return existing

    # Find most recent scan for baseline values
    latest_scan = (
        db.query(Scan)
        .filter(Scan.target == target, Scan.user_session_id == session_id)
        .order_by(Scan.timestamp.desc())
        .first()
    )
    if not latest_scan:
        latest_scan = db.query(Scan).filter(Scan.target == target).order_by(Scan.timestamp.desc()).first()

    item = WatchlistItem(
        id=generate_id("watch"),
        user_session_id=session_id,
        target=target,
        target_type=req.target_type,
        added_at=datetime.utcnow(),
        last_scanned_at=latest_scan.timestamp if latest_scan else None,
        last_level=latest_scan.risk_level if latest_scan else None,
        last_score=latest_scan.risk_score if latest_scan else None,
        active=True,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.delete("/watchlist/{id}")
def delete_from_watchlist(
    id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    item = (
        db.query(WatchlistItem)
        .filter(WatchlistItem.id == id, WatchlistItem.user_session_id == session_id)
        .first()
    )
    if not item:
        # Fallback to id if migrated
        item = db.query(WatchlistItem).filter(WatchlistItem.id == id).first()
    if not item:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Watchlist item not found."})
    db.delete(item)
    db.commit()
    return {"message": "Item deleted from watchlist."}


async def perform_watchlist_rescan(item: WatchlistItem, db: Session) -> dict:
    target = item.target
    session_id = item.user_session_id or "migrated_default"
    previous_scan = (
        db.query(Scan)
        .filter(Scan.target == target, Scan.user_session_id == session_id)
        .order_by(Scan.timestamp.desc())
        .first()
    )
    if not previous_scan:
        previous_scan = db.query(Scan).filter(Scan.target == target).order_by(Scan.timestamp.desc()).first()

    # Perform fresh analysis
    is_demo = not bool(VT_API_KEY)
    if item.target_type == "url":
        cleaned_url = refang_target(target)
        try:
            scheme, host, port = validate_url_syntax(cleaned_url)
            redirect_info = await trace_url_redirects(cleaned_url)
        except Exception as e:
            raise HTTPException(status_code=400, detail={"code": "RESCAN_FAILED", "message": str(e)})

        final_domain = redirect_info["final_domain"] or host
        dns_res = await resolve_dns(final_domain)
        rdap_res = await lookup_rdap(final_domain)
        crtsh_res = await lookup_crtsh(final_domain)
        openphish_res = await lookup_openphish(cleaned_url)
        sb_res = await lookup_safe_browsing(cleaned_url)
        urlhaus_res = await lookup_urlhaus(cleaned_url)
        vt_res = await lookup_virustotal_url(cleaned_url)

        # In demo / synthetic target mode, simulate dynamic variation on rescan
        sim_override_score = None
        extra_demo_factor = None
        flagged_rep_lists = None
        if "example-phishing-login.com" in cleaned_url:
            prev_score = previous_scan.risk_score if previous_scan else 82
            prev_det = previous_scan.detection_count if previous_scan else 28
            prev_raw = json.loads(previous_scan.raw_summary_json) if (previous_scan and previous_scan.raw_summary_json) else {}
            prev_hops = prev_raw.get("redirects", {}).get("hop_count", 3)
            prev_rep = set(prev_raw.get("reputation_lists_flagged", ["OpenPhish", "Safe Browsing", "URLhaus"]))

            if prev_score < 92:
                score_step = 3
                det_step = 2
                sim_malicious = min(36, prev_det + det_step)
                sim_override_score = min(92, prev_score + score_step)
                current_hops = 3
                flagged_rep_lists = ["OpenPhish", "Safe Browsing", "URLhaus"]
            else:
                sim_override_score = 92
                sim_malicious = 35 if prev_det >= 36 else 36
                current_hops = 4 if prev_hops == 3 else 3

                if "ThreatFox" not in prev_rep:
                    flagged_rep_lists = ["OpenPhish", "Safe Browsing", "URLhaus", "ThreatFox"]
                    extra_demo_factor = {
                        "id": "rep_threatfox",
                        "group": "REPUTATION_LISTS",
                        "type": "indicator",
                        "severity": "high",
                        "points": 30,
                        "title": "ThreatFox IOC Match [DEMO]",
                        "description": "Domain confirmed in ThreatFox active credential harvesting feed.",
                        "source": "ThreatFox [DEMO]",
                        "evidence_ref": {"threat_type": "phishing_c2", "flagged": True},
                    }
                else:
                    flagged_rep_lists = ["OpenPhish", "Safe Browsing", "URLhaus"]

            if current_hops == 3:
                redirect_info = {
                    "initial_url": cleaned_url,
                    "final_url": "http://malicious-delivery.phish-cdn.xyz/auth",
                    "initial_domain": "service-cdn.example-phishing-login.com",
                    "final_domain": "malicious-delivery.phish-cdn.xyz",
                    "hop_count": 3,
                    "cross_domain": True,
                    "suspicious": True,
                    "hops": [
                        {"hop": 0, "url": cleaned_url, "domain": "service-cdn.example-phishing-login.com", "ip": "104.20.23.154", "status_code": 302},
                        {"hop": 1, "url": "http://cdn-hop.example-gate.org/redirect", "domain": "cdn-hop.example-gate.org", "ip": "104.20.23.158", "status_code": 302},
                        {"hop": 2, "url": "http://auth-collect.phish-cdn.xyz/auth", "domain": "auth-collect.phish-cdn.xyz", "ip": "104.20.23.159", "status_code": 302},
                        {"hop": 3, "url": "http://malicious-delivery.phish-cdn.xyz/auth", "domain": "malicious-delivery.phish-cdn.xyz", "ip": "104.20.23.160", "status_code": 200},
                    ],
                }
            else:
                redirect_info = {
                    "initial_url": cleaned_url,
                    "final_url": "http://malicious-delivery.phish-cdn.xyz/auth",
                    "initial_domain": "service-cdn.example-phishing-login.com",
                    "final_domain": "malicious-delivery.phish-cdn.xyz",
                    "hop_count": 4,
                    "cross_domain": True,
                    "suspicious": True,
                    "hops": [
                        {"hop": 0, "url": cleaned_url, "domain": "service-cdn.example-phishing-login.com", "ip": "104.20.23.154", "status_code": 302},
                        {"hop": 1, "url": "http://cdn-hop.example-gate.org/redirect", "domain": "cdn-hop.example-gate.org", "ip": "104.20.23.158", "status_code": 302},
                        {"hop": 2, "url": "http://traffic-proxy.fast-cdn.org/route", "domain": "traffic-proxy.fast-cdn.org", "ip": "104.20.23.155", "status_code": 302},
                        {"hop": 3, "url": "http://auth-collect.phish-cdn.xyz/auth", "domain": "auth-collect.phish-cdn.xyz", "ip": "104.20.23.159", "status_code": 302},
                        {"hop": 4, "url": "http://malicious-delivery.phish-cdn.xyz/auth", "domain": "malicious-delivery.phish-cdn.xyz", "ip": "104.20.23.160", "status_code": 200},
                    ],
                }

            vt_res["data"] = {
                "malicious": sim_malicious,
                "suspicious": 2,
                "harmless": 40,
                "undetected": 22,
                "total": sim_malicious + 64,
                "categories": ["phishing", "malicious"],
            }
            vt_res["status"] = "ok"
            vt_res["message"] = f"VirusTotal analysis: {sim_malicious} engines flagged target."

            openphish_res["data"] = {"flagged": "OpenPhish" in flagged_rep_lists}
            openphish_res["status"] = "ok"
            openphish_res["message"] = "OpenPhish feed match confirmed." if "OpenPhish" in flagged_rep_lists else "Clean"

            sb_res["data"] = {"flagged": "Safe Browsing" in flagged_rep_lists, "threat_types": ["SOCIAL_ENGINEERING"]}
            sb_res["status"] = "ok"
            sb_res["message"] = "Google Safe Browsing match confirmed." if "Safe Browsing" in flagged_rep_lists else "Clean"

            urlhaus_res["data"] = {"flagged": "URLhaus" in flagged_rep_lists, "threat": "Phishing-Credential-Harvest"}
            urlhaus_res["status"] = "ok"
            urlhaus_res["message"] = "URLhaus active threat match confirmed." if "URLhaus" in flagged_rep_lists else "Clean"
        elif is_demo:
            prev_mal = previous_scan.detection_count if previous_scan else 0
            new_mal = prev_mal + 3 if prev_mal < 30 else max(2, prev_mal - 4)
            vt_res["data"] = {
                "malicious": new_mal,
                "suspicious": 2,
                "harmless": 45,
                "undetected": 20,
                "total": new_mal + 67,
            }
            vt_res["status"] = "ok"
            vt_res["message"] = f"Simulated detection count: {new_mal}"

        norm = NormalizedEvidence(
            target=cleaned_url,
            target_type="url",
            virustotal=vt_res.get("data"),
            safe_browsing=sb_res.get("data"),
            urlhaus=urlhaus_res.get("data"),
            openphish=openphish_res.get("data"),
            rdap=rdap_res.get("data"),
            dns=dns_res.get("data"),
            certificates=crtsh_res.get("data"),
            redirects=redirect_info,
        )
        assessment = evaluate(norm, now=datetime.utcnow())
        if sim_override_score is not None:
            assessment.score = sim_override_score
            # Derive level from score using canonical thresholds
            derived_level = "UNKNOWN"
            for low_bound, high_bound, lvl_name in LEVEL_THRESHOLDS:
                if low_bound <= sim_override_score <= high_bound:
                    derived_level = lvl_name
                    break
            assessment.level = derived_level
            assessment.group_breakdown["AV_DETECTIONS"] = min(50, sim_override_score)
            assessment.group_breakdown["REPUTATION_LISTS"] = min(30, max(0, sim_override_score - 50))
            assessment.group_breakdown["DOMAIN_INFRA"] = max(0, sim_override_score - 80)
            assessment.group_breakdown["BEHAVIOR"] = 0
            assessment.group_breakdown["MITIGATING"] = 0
            if extra_demo_factor:
                from ..risk_engine import Factor
                assessment.factors.append(Factor(**extra_demo_factor))
            assessment.explanation = _generate_plain_english_explanation(
                assessment.score,
                assessment.level,
                assessment.confidence,
                assessment.factors,
                assessment.group_breakdown,
            )

        chain = build_attack_chain(
            cleaned_url,
            "url",
            {
                "redirects": redirect_info,
                "dns": dns_res.get("data", {}),
                "virustotal": vt_res.get("data", {}),
                "explanation": assessment.explanation,
            },
            assessment.level,
        )

        raw_summary = {
            "group_breakdown": assessment.group_breakdown,
            "explanation": assessment.explanation,
            "recommended_action": assessment.recommended_action,
            "redirects": redirect_info,
            "attack_chain": chain.model_dump(),
            "reputation_lists_flagged": flagged_rep_lists if "example-phishing-login.com" in cleaned_url else [
                src for src, res in [("Safe Browsing", sb_res), ("URLhaus", urlhaus_res), ("OpenPhish", openphish_res)]
                if (res.get("data") or {}).get("flagged")
            ],
        }
        sources_dict = {"VirusTotal": vt_res, "DNS": dns_res, "RDAP": rdap_res}
        det_count = vt_res.get("data", {}).get("malicious", 0) if vt_res.get("data") else 0
        total_eng = vt_res.get("data", {}).get("total", 0) if vt_res.get("data") else 0

    else:
        # Hash rescan
        vt_res = await lookup_virustotal_hash(target)
        norm = NormalizedEvidence(target=target, target_type="hash", virustotal=vt_res.get("data"))
        assessment = evaluate(norm, now=datetime.utcnow())
        chain = build_attack_chain(target, "hash", {}, assessment.level)
        raw_summary = {
            "group_breakdown": assessment.group_breakdown,
            "explanation": assessment.explanation,
            "recommended_action": assessment.recommended_action,
            "attack_chain": chain.model_dump(),
        }
        sources_dict = {"VirusTotal": vt_res}
        det_count = vt_res.get("data", {}).get("malicious", 0) if vt_res.get("data") else 0
        total_eng = vt_res.get("data", {}).get("total", 0) if vt_res.get("data") else 0

    # Save new scan
    new_scan = Scan(
        id=generate_id("scan"),
        user_session_id=session_id,
        target=target,
        target_type=item.target_type,
        timestamp=datetime.utcnow(),
        risk_score=assessment.score,
        risk_level=assessment.level,
        confidence=assessment.confidence,
        detection_count=det_count,
        total_engines=total_eng,
        factors_json=json.dumps([f.__dict__ for f in assessment.factors]),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources_dict),
        is_demo=is_demo or ("example-phishing-login.com" in target),
        created_at=datetime.utcnow(),
    )
    db.add(new_scan)

    prev_score = previous_scan.risk_score if previous_scan else item.last_score
    prev_level = previous_scan.risk_level if previous_scan else item.last_level
    prev_scan_id = previous_scan.id if previous_scan else None

    # Check for drift alert
    is_target_demo = is_demo or ("example-phishing-login.com" in target)
    if prev_score is not None:
        score_diff = abs(new_scan.risk_score - prev_score)
        level_changed = (new_scan.risk_level != prev_level) if prev_level else False

        if level_changed or score_diff >= 10 or (is_target_demo and new_scan.risk_score != prev_score):
            prev_sev = SEVERITY_ORDER.get(prev_level, -1) if prev_level else -1
            new_sev = SEVERITY_ORDER.get(new_scan.risk_level, -1)

            if prev_level == new_scan.risk_level:
                kind = "score_change"
                msg = (
                    f"{target} score changed within {new_scan.risk_level} "
                    f"({prev_score}/100 to {new_scan.risk_score}/100)."
                )
            elif new_sev > prev_sev:
                kind = "threat_escalation"
                msg = (
                    f"{target} escalated from {prev_level or 'BASELINE'} ({prev_score}/100) "
                    f"to {new_scan.risk_level} ({new_scan.risk_score}/100)."
                )
            else:
                kind = "threat_downgrade"
                msg = (
                    f"{target} de-escalated from {prev_level} ({prev_score}/100) "
                    f"to {new_scan.risk_level} ({new_scan.risk_score}/100)."
                )

            alert = Alert(
                id=generate_id("alert"),
                user_session_id=session_id,
                target=target,
                scan_id=new_scan.id,
                previous_scan_id=prev_scan_id,
                kind=kind,
                message=msg,
                created_at=datetime.utcnow(),
                seen=False,
            )
            db.add(alert)
    elif new_scan.risk_level in ["HIGH", "CRITICAL"]:
        # First scan of a high/critical target automatically triggers an alert
        msg = f"{target} surfaced with initial {new_scan.risk_level} threat level ({new_scan.risk_score}/100)."
        alert = Alert(
            id=generate_id("alert"),
            user_session_id=session_id,
            target=target,
            scan_id=new_scan.id,
            previous_scan_id=None,
            kind="threat_escalation",
            message=msg,
            created_at=datetime.utcnow(),
            seen=False,
        )
        db.add(alert)

    # Update watchlist row
    item.last_scanned_at = new_scan.timestamp
    item.last_level = new_scan.risk_level
    item.last_score = new_scan.risk_score
    db.commit()

    return {
        "status": "success",
        "message": f"Rescanned {target}",
        "scan_id": new_scan.id,
        "score": new_scan.risk_score,
        "level": new_scan.risk_level,
    }


@router.post("/watchlist/{id}/rescan")
async def rescan_watchlist_item(
    id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    item = (
        db.query(WatchlistItem)
        .filter(WatchlistItem.id == id, WatchlistItem.user_session_id == session_id)
        .first()
    )
    if not item:
        item = db.query(WatchlistItem).filter(WatchlistItem.id == id).first()
    if not item:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Watchlist item not found."})
    return await perform_watchlist_rescan(item, db)


@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    alerts = (
        db.query(Alert)
        .filter(Alert.user_session_id == session_id)
        .order_by(Alert.created_at.desc())
        .limit(50)
        .all()
    )
    return alerts


@router.post("/alerts/read-all")
def mark_all_alerts_read(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    db.query(Alert).filter(Alert.user_session_id == session_id, Alert.seen == False).update({"seen": True})
    db.commit()
    return {"status": "ok"}


@router.post("/alerts/{id}/read")
def mark_alert_read(
    id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    alert = (
        db.query(Alert)
        .filter(Alert.id == id, Alert.user_session_id == session_id)
        .first()
    )
    if not alert:
        alert = db.query(Alert).filter(Alert.id == id).first()
    if alert:
        alert.seen = True
        db.commit()
    return {"status": "ok"}
