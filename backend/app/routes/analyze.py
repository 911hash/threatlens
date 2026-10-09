"""
Analysis endpoints for URLs, hashes, and uploaded files.
Handles SSRF protection, multi-source ingestion, rate limits, and risk scoring.
"""

import email
import email.policy
import hashlib
import html
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scan, generate_id
from ..risk_engine import EVIDENCE_GROUPS, Factor, LEVEL_THRESHOLDS, NormalizedEvidence, evaluate
from ..schemas import (
    AnalyzeHashRequest,
    AnalyzeUrlRequest,
    AttackChainGraph,
    AttackChainLink,
    AttackChainNode,
    EmailAnalysisResponse,
    EmailAuthResult,
    EmailHeaderAnalysis,
    EmailParseResult,
    FactorResponse,
    GeoLocationResponse,
    ScanResponse,
)
from ..services.attack_chain import build_attack_chain
from ..services.dns_rdap import lookup_crtsh, lookup_rdap, resolve_dns
from ..services.email_auth import parse_authentication_results
from ..services.email_headers import analyze_headers
from ..services.email_parser import parse_email
from ..services.email_forensics import process_email_forensics
from ..services.geolocation import geolocate_ip
from ..services.feeds import lookup_openphish, lookup_urlhaus
from ..services.safe_browsing import lookup_safe_browsing
from ..services.url_analysis import (
    InvalidURLError,
    SSRFSecurityError,
    defang_target,
    refang_target,
    trace_url_redirects,
    validate_url_syntax,
)
from ..services.virustotal import (
    ALLOW_FILE_UPLOAD_TO_VT,
    ALLOW_VT_URL_SUBMISSION,
    VT_API_KEY,
    lookup_virustotal_hash,
    lookup_virustotal_url,
)

router = APIRouter(prefix="/api/analyze", tags=["Analyze"])

# Maximum file upload size: 32MB
MAX_FILE_BYTES = 32 * 1024 * 1024


def serialize_scan_response(
    scan: Scan,
    delta_vs_previous: Optional[int] = None,
    level_changed_vs_previous: Optional[bool] = None,
    previous_scan_id: Optional[str] = None,
) -> ScanResponse:
    factors_data = json.loads(scan.factors_json) if scan.factors_json else []
    raw_summary = json.loads(scan.raw_summary_json) if scan.raw_summary_json else {}
    sources = json.loads(scan.sources_json) if scan.sources_json else {}

    factors = [FactorResponse(**f) for f in factors_data]
    group_breakdown = raw_summary.get("group_breakdown", {})
    explanation = raw_summary.get("explanation", "")
    action = raw_summary.get("recommended_action", "")

    # Build or restore attack chain
    attack_chain_data = raw_summary.get("attack_chain")
    if attack_chain_data:
        attack_chain = AttackChainGraph(**attack_chain_data)
    else:
        attack_chain = build_attack_chain(
            target=scan.target,
            target_type=scan.target_type,
            evidence_data=raw_summary,
            risk_level=scan.risk_level,
        )

    return ScanResponse(
        id=scan.id,
        target=scan.target,
        target_type=scan.target_type,
        timestamp=scan.timestamp,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        confidence=scan.confidence,
        detection_count=scan.detection_count,
        total_engines=scan.total_engines,
        factors=factors,
        group_breakdown=group_breakdown,
        raw_summary=raw_summary,
        sources=sources,
        attack_chain=attack_chain,
        is_demo=scan.is_demo,
        explanation=explanation,
        recommended_action=action,
        defanged_target=defang_target(scan.target) if scan.target_type == "url" else None,
        delta_vs_previous=delta_vs_previous,
        level_changed_vs_previous=level_changed_vs_previous,
        previous_scan_id=previous_scan_id,
        geo_results=raw_summary.get("geo_results", []),
    )


@router.post("/url", response_model=ScanResponse)
async def analyze_url(req: AnalyzeUrlRequest, db: Session = Depends(get_db)):
    cleaned_url = refang_target(req.url.strip())

    # 1. SSRF and syntax validation
    try:
        scheme, host, port = validate_url_syntax(cleaned_url)
    except (InvalidURLError, SSRFSecurityError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_URL", "message": str(e)},
        )

    # 2. Trace redirects and perform SSRF check at each hop
    try:
        redirect_info = await trace_url_redirects(cleaned_url)
    except SSRFSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "SSRF_BLOCKED", "message": "This address points to a private or internal network and can't be analyzed."},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "REDIRECT_TRACE_FAILED", "message": f"Unable to analyze URL network destination: {str(e)}"},
        )

    # 3. Query intelligence sources concurrently
    final_domain = redirect_info["final_domain"] or host
    dns_res = await resolve_dns(final_domain)
    rdap_res = await lookup_rdap(final_domain)
    crtsh_res = await lookup_crtsh(final_domain)
    openphish_res = await lookup_openphish(cleaned_url)
    sb_res = await lookup_safe_browsing(cleaned_url)
    urlhaus_res = await lookup_urlhaus(cleaned_url)
    vt_res = await lookup_virustotal_url(cleaned_url)

    # Is demo mode active?
    is_demo = not bool(VT_API_KEY)

    # Check if this is the featured demo URL
    sim_override_score = None
    extra_demo_factor = None
    if "example-phishing-login.com" in cleaned_url:
        latest_scan = db.query(Scan).filter(Scan.target == cleaned_url).order_by(Scan.timestamp.desc()).first()
        prev_score = latest_scan.risk_score if latest_scan else 82
        prev_det = latest_scan.detection_count if latest_scan else 28
        prev_raw = json.loads(latest_scan.raw_summary_json) if (latest_scan and latest_scan.raw_summary_json) else {}
        prev_hops = prev_raw.get("redirects", {}).get("hop_count", 3)
        prev_rep = set(prev_raw.get("reputation_lists_flagged", ["OpenPhish", "Safe Browsing", "URLhaus"]))

        if prev_score < 92:
            # Incremental drift: +3 score per re-scan (+3 to +8), +2 detections (+1 to +4)
            # Strictly capped at 92 score. Re-analyzing multiple times never exceeds 92 or hits 100.
            score_step = 3
            det_step = 2
            sim_malicious = min(36, prev_det + det_step)
            sim_override_score = min(92, prev_score + score_step)
            current_hops = 3
            flagged_rep_lists = ["OpenPhish", "Safe Browsing", "URLhaus"]
        else:
            # Strictly capped at 92: vary reputation sources and redirect hops instead so diff is always nonzero
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
        openphish_res["data"] = {"flagged": "OpenPhish" in flagged_rep_lists}
        sb_res["data"] = {"flagged": "Safe Browsing" in flagged_rep_lists, "threat_types": ["SOCIAL_ENGINEERING"]}
        urlhaus_res["data"] = {"flagged": "URLhaus" in flagged_rep_lists, "threat": "Phishing-Credential-Harvest"}

    # Normalize evidence
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
        ip_reputation={"is_malicious": False, "asn": "Standard ASN"},
    )

    assessment = evaluate(norm, now=datetime.utcnow())
    if sim_override_score is not None:
        assessment.score = sim_override_score
        assessment.level = "CRITICAL"
        assessment.group_breakdown["AV_DETECTIONS"] = 50
        assessment.group_breakdown["REPUTATION_LISTS"] = 30
        assessment.group_breakdown["DOMAIN_INFRA"] = sim_override_score - 80
        assessment.group_breakdown["BEHAVIOR"] = 0
        assessment.group_breakdown["MITIGATING"] = 0
        if extra_demo_factor:
            from ..risk_engine import Factor
            assessment.factors.append(Factor(**extra_demo_factor))

    attack_chain = build_attack_chain(
        target=cleaned_url,
        target_type="url",
        evidence_data={
            "redirects": redirect_info,
            "dns": dns_res.get("data", {}),
            "virustotal": vt_res.get("data", {}),
            "explanation": assessment.explanation,
        },
        risk_level=assessment.level,
    )

    factors_dict = [f.__dict__ for f in assessment.factors]
    raw_summary = {
        "group_breakdown": assessment.group_breakdown,
        "explanation": assessment.explanation,
        "recommended_action": assessment.recommended_action,
        "redirects": redirect_info,
        "attack_chain": attack_chain.model_dump(),
        "reputation_lists_flagged": flagged_rep_lists if "example-phishing-login.com" in cleaned_url else [
            src for src, res in [("Safe Browsing", sb_res), ("URLhaus", urlhaus_res), ("OpenPhish", openphish_res)]
            if (res.get("data") or {}).get("flagged")
        ],
    }
    sources_dict = {
        "VirusTotal": vt_res,
        "Google Safe Browsing": sb_res,
        "URLhaus": urlhaus_res,
        "OpenPhish": openphish_res,
        "RDAP": rdap_res,
        "DNS": dns_res,
        "crt.sh": crtsh_res,
    }

    scan = Scan(
        id=generate_id("scan"),
        target=cleaned_url,
        target_type="url",
        timestamp=datetime.utcnow(),
        risk_score=assessment.score,
        risk_level=assessment.level,
        confidence=assessment.confidence,
        detection_count=vt_res.get("data", {}).get("malicious", 0) if vt_res.get("data") else 0,
        total_engines=vt_res.get("data", {}).get("total", 0) if vt_res.get("data") else 0,
        factors_json=json.dumps(factors_dict),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources_dict),
        is_demo=is_demo or ("example-phishing-login.com" in cleaned_url),
        created_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return serialize_scan_response(scan)


@router.post("/hash", response_model=ScanResponse)
async def analyze_hash(req: AnalyzeHashRequest, db: Session = Depends(get_db)):
    file_hash = req.hash.strip().lower()

    # Validate MD5 / SHA-1 / SHA-256
    if not re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", file_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_HASH", "message": "Invalid hash format. Must be a valid MD5 (32-char), SHA-1 (40-char), or SHA-256 (64-char) hex string."},
        )

    vt_res = await lookup_virustotal_hash(file_hash)
    is_demo = not bool(VT_API_KEY)

    # In demo mode, provide simulated behavior data for known demo hashes
    behavior_data = None
    if is_demo and file_hash.startswith("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:16]):
        # Simulated malicious hash with PowerShell and persistence
        vt_res["data"] = {
            "malicious": 42,
            "suspicious": 5,
            "harmless": 20,
            "undetected": 5,
            "total": 72,
            "reputation": -80,
            "meaningful_name": "DEMO_trojan_dropper.bin",
            "type_description": "Win32 EXE",
            "is_signed": False,
        }
        behavior_data = {
            "powershell_executed": True,
            "powershell_command": "powershell.exe -NoP -NonI -W Hidden -Enc SUVY...",
            "persistence_added": True,
            "persistence_type": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "suspicious_exec": True,
            "exec_details": "Dropped payload in %APPDATA%\\Roaming\\update.exe",
            "network_connection": {"destination": "c2-demo.evil-node.net", "port": 443},
        }

    norm = NormalizedEvidence(
        target=file_hash,
        target_type="hash",
        virustotal=vt_res.get("data"),
        behavior=behavior_data,
        file_metadata=vt_res.get("data"),
    )

    assessment = evaluate(norm, now=datetime.utcnow())
    attack_chain = build_attack_chain(
        target=file_hash,
        target_type="hash",
        evidence_data={"behavior": behavior_data, "virustotal": vt_res.get("data")},
        risk_level=assessment.level,
    )

    factors_dict = [f.__dict__ for f in assessment.factors]
    raw_summary = {
        "group_breakdown": assessment.group_breakdown,
        "explanation": assessment.explanation,
        "recommended_action": assessment.recommended_action,
        "behavior": behavior_data,
        "attack_chain": attack_chain.model_dump(),
    }
    sources_dict = {"VirusTotal": vt_res}

    scan = Scan(
        id=generate_id("scan"),
        target=file_hash,
        target_type="hash",
        timestamp=datetime.utcnow(),
        risk_score=assessment.score,
        risk_level=assessment.level,
        confidence=assessment.confidence,
        detection_count=vt_res.get("data", {}).get("malicious", 0) if vt_res.get("data") else 0,
        total_engines=vt_res.get("data", {}).get("total", 0) if vt_res.get("data") else 0,
        factors_json=json.dumps(factors_dict),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources_dict),
        is_demo=is_demo,
        created_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return serialize_scan_response(scan)


@router.post("/file", response_model=ScanResponse)
async def analyze_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Stream-hash uploaded file without persisting to disk.
    Look up hash in threat database.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    total_size = 0

    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "FILE_TOO_LARGE", "message": "Uploaded file exceeds maximum allowed size of 32 MB."},
            )
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)

    file_sha256 = sha256.hexdigest()
    file_sha1 = sha1.hexdigest()
    file_md5 = md5.hexdigest()

    is_demo = not bool(VT_API_KEY)
    vt_res = await lookup_virustotal_hash(file_sha256)

    # In demo mode, if this file has no prior reputation, show friendly explanation
    if not vt_res.get("data") or vt_res.get("status") == "no_data":
        vt_res["data"] = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "message": "Unknown sample. No existing reputation found.",
        }

    norm = NormalizedEvidence(
        target=file_sha256,
        target_type="file",
        virustotal=vt_res.get("data"),
        file_metadata={
            "filename": file.filename,
            "size": total_size,
            "sha256": file_sha256,
            "sha1": file_sha1,
            "md5": file_md5,
        },
    )

    assessment = evaluate(norm, now=datetime.utcnow())
    attack_chain = build_attack_chain(
        target=file_sha256,
        target_type="file",
        evidence_data={"virustotal": vt_res.get("data")},
        risk_level=assessment.level,
    )

    factors_dict = [f.__dict__ for f in assessment.factors]
    raw_summary = {
        "group_breakdown": assessment.group_breakdown,
        "explanation": assessment.explanation,
        "recommended_action": assessment.recommended_action,
        "filename": file.filename,
        "file_size": total_size,
        "sha256": file_sha256,
        "sha1": file_sha1,
        "md5": file_md5,
        "attack_chain": attack_chain.model_dump(),
    }
    sources_dict = {"VirusTotal": vt_res}

    scan = Scan(
        id=generate_id("scan"),
        target=file_sha256,
        target_type="file",
        timestamp=datetime.utcnow(),
        risk_score=assessment.score,
        risk_level=assessment.level,
        confidence=assessment.confidence,
        detection_count=vt_res.get("data", {}).get("malicious", 0) if vt_res.get("data") else 0,
        total_engines=vt_res.get("data", {}).get("total", 0) if vt_res.get("data") else 0,
        factors_json=json.dumps(factors_dict),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources_dict),
        is_demo=is_demo,
        created_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return serialize_scan_response(scan)


@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email(
    file: UploadFile = File(...),
    hash_only: bool = False,
    db: Session = Depends(get_db),
):
    """
    Stream-hash and forensically analyze uploaded email (.eml or .msg).
    Strict Privacy Mode: Email file and attachments are processed purely in memory,
    never written to disk, never sent to third-party APIs, and never retained.
    Only analytical metadata, hashes, and authentication verdicts are persisted.
    """
    filename = file.filename or "sample.eml"
    fn_lower = filename.lower()

    # Validate file extension (.eml or .msg)
    if not (fn_lower.endswith(".eml") or fn_lower.endswith(".msg") or file.content_type == "message/rfc822"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_FILE_TYPE", "message": "Only .eml and .msg email files are supported."},
        )

    # 1. Stream-hash file into memory buffer (max 32MB)
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    buffer = bytearray()
    total_size = 0

    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "FILE_TOO_LARGE", "message": "Uploaded email exceeds maximum allowed size of 32 MB."},
            )
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)
        buffer.extend(chunk)

    raw_bytes = bytes(buffer)
    _, response = await process_email_forensics(raw_bytes, filename=filename, hash_only=hash_only, db=db)
    return response


