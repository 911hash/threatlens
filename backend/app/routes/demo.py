"""
Demo dataset management and seeding.
All simulated data is strictly labeled DEMO / SIMULATED.
Uses reserved .example / .test domains and simulated hashes.
Chronological scan IDs: _0 is the oldest, increasing with time.
"""

from datetime import datetime, timedelta
import json
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Scan, WatchlistItem, generate_id
from ..services.attack_chain import build_attack_chain

router = APIRouter(prefix="/api/demo", tags=["Demo"])

FEATURED_DEMO_URL = "http://service-cdn.example-phishing-login.com/auth"


def _create_simulated_scan(
    scan_id: str,
    target: str,
    target_type: str,
    timestamp: datetime,
    score: int,
    level: str,
    confidence: int,
    malicious_count: int,
    total_engines: int,
    factors: List[Dict[str, Any]],
    raw_summary: Dict[str, Any],
    sources: Dict[str, Any],
) -> Scan:
    # Ensure attack chain is populated
    if "attack_chain" not in raw_summary:
        chain = build_attack_chain(target, target_type, raw_summary, level)
        raw_summary["attack_chain"] = chain.model_dump()

    return Scan(
        id=scan_id,
        target=target,
        target_type=target_type,
        timestamp=timestamp,
        risk_score=score,
        risk_level=level,
        confidence=confidence,
        detection_count=malicious_count,
        total_engines=total_engines,
        factors_json=json.dumps(factors),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources),
        is_demo=True,
        created_at=timestamp,
    )


@router.get("")
def get_demo_info():
    return {
        "is_demo": True,
        "label": "[DEMO / SIMULATED DATASET]",
        "featured_target": FEATURED_DEMO_URL,
        "sample_targets": [
            {
                "target": FEATURED_DEMO_URL,
                "type": "url",
                "label": "Featured Threat Evolution (Deteriorating URL)",
                "description": "Demonstrates verdict drift over 5 days: initially benign, redirects modified, blacklisted.",
            },
            {
                "target": "https://safe-portal.example.com",
                "type": "url",
                "label": "Clean Benign URL",
                "description": "Safe domain with valid TLS cert and zero engine detections.",
            },
            {
                "target": "http://account-verification-alert.example-phishing.org/login",
                "type": "url",
                "label": "Newly Registered Phishing Domain",
                "description": "Young domain (<3 days old) imitating account verification portal.",
            },
            {
                "target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "type": "hash",
                "label": "Malicious Executable Hash",
                "description": "Simulated trojan dropper exhibiting PowerShell obfuscation and persistence.",
            },
            {
                "target": "http://remediated-host.example-clean.net/download",
                "type": "url",
                "label": "Remediated Threat (Improving URL)",
                "description": "Formerly compromised site cleaned up by webmaster, showing risk reduction.",
            },
        ],
    }


@router.post("/reset")
def reset_demo_data(db: Session = Depends(get_db)):
    """Cleanly reset and re-seed all demo data."""
    return seed_demo_data(reset=True, db=db)


@router.post("/seed")
def seed_demo_data(reset: bool = False, db: Session = Depends(get_db)):
    """
    Idempotent seeding of demo scans, watchlist, and evolution history.
    Scan IDs are strictly chronological: _0 is the oldest, increasing with time.
    If reset=True, cleanly wipes existing scans and re-seeds the pristine baseline.
    """
    now = datetime.utcnow()

    if reset:
        # Wipe all existing scans, alerts, and watchlist items to guarantee pristine state
        db.query(Alert).delete(synchronize_session=False)
        db.query(WatchlistItem).delete(synchronize_session=False)
        db.query(Scan).delete(synchronize_session=False)
        db.commit()
    else:
        # 1. Idempotency Check: if already seeded, return without changes
        existing_featured = db.query(Scan).filter(Scan.target == FEATURED_DEMO_URL).first()
        if existing_featured:
            latest = db.query(Scan).filter(Scan.target == FEATURED_DEMO_URL).order_by(Scan.timestamp.desc()).first()
            return {
                "status": "already_seeded",
                "message": "Demo dataset is already seeded.",
                "featured_target": FEATURED_DEMO_URL,
                "featured_scan_id": latest.id if latest else existing_featured.id,
            }

    # SEED TARGET 1: Safe URL (with valid 1-hop redirect chain)
    scan_safe = _create_simulated_scan(
        scan_id="demo_scan_safe_0",
        target="https://safe-portal.example.com",
        target_type="url",
        timestamp=now - timedelta(days=2),
        score=5,
        level="SAFE",
        confidence=88,
        malicious_count=0,
        total_engines=72,
        factors=[
            {
                "id": "mitigating_established_reputation",
                "group": "MITIGATING",
                "type": "mitigating",
                "severity": "info",
                "points": -15,
                "title": "Established Benign Reputation [DEMO]",
                "description": "Simulated authority records confirm clean operational history.",
                "source": "Demo Intelligence",
                "evidence_ref": {"clean": True},
            }
        ],
        raw_summary={
            "group_breakdown": {"AV_DETECTIONS": 0, "REPUTATION_LISTS": 0, "DOMAIN_INFRA": 0, "BEHAVIOR": 0, "MITIGATING": -15},
            "explanation": "ThreatLens evaluated this target as SAFE (5/100) across verified intelligence sources.",
            "recommended_action": "No significant malicious indicators were found in the available intelligence.",
            "redirects": {
                "initial_url": "https://safe-portal.example.com",
                "final_url": "https://safe-portal.example.com",
                "initial_domain": "safe-portal.example.com",
                "final_domain": "safe-portal.example.com",
                "hop_count": 0,
                "cross_domain": False,
                "suspicious": False,
                "hops": [
                    {"hop": 0, "url": "https://safe-portal.example.com", "domain": "safe-portal.example.com", "ip": "104.20.23.155", "status_code": 200}
                ],
            },
            "reputation_lists_flagged": [],
        },
        sources={"VirusTotal": {"status": "ok"}, "Google Safe Browsing": {"status": "ok"}},
    )
    db.add(scan_safe)

    # SEED TARGET 2: Young Phishing URL (with valid 1-hop redirect chain)
    scan_phish = _create_simulated_scan(
        scan_id="demo_scan_phish_0",
        target="http://account-verification-alert.example-phishing.org/login",
        target_type="url",
        timestamp=now - timedelta(hours=8),
        score=65,
        level="HIGH",
        confidence=75,
        malicious_count=0,
        total_engines=70,
        factors=[
            {
                "id": "infra_new_domain",
                "group": "DOMAIN_INFRA",
                "type": "indicator",
                "severity": "medium",
                "points": 10,
                "title": "Newly Registered Domain [DEMO]",
                "description": "Domain registered 2 days ago via privacy proxy registrar.",
                "source": "RDAP [DEMO]",
                "evidence_ref": {"domain_age_days": 2},
            },
            {
                "id": "rep_openphish",
                "group": "REPUTATION_LISTS",
                "type": "indicator",
                "severity": "high",
                "points": 30,
                "title": "OpenPhish Phishing Feed Match [DEMO]",
                "description": "Simulated listing in active credential phishing database.",
                "source": "OpenPhish [DEMO]",
                "evidence_ref": {"flagged": True},
            },
            {
                "id": "infra_suspicious_cert",
                "group": "DOMAIN_INFRA",
                "type": "indicator",
                "severity": "low",
                "points": 5,
                "title": "Suspicious TLS Certificate Pattern [DEMO]",
                "description": "Certificate SAN contains deceptive authentication keywords.",
                "source": "crt.sh [DEMO]",
                "evidence_ref": {"suspicious_sans": True},
            },
        ],
        raw_summary={
            "group_breakdown": {"AV_DETECTIONS": 0, "REPUTATION_LISTS": 30, "DOMAIN_INFRA": 15, "BEHAVIOR": 0, "MITIGATING": 0},
            "explanation": "ThreatLens scored this target at 65/100 (HIGH) based on newly registered domain and active phishing feeds.",
            "recommended_action": "Phishing threat detected: Do not enter credentials. Revoke active sessions if credentials were submitted.",
            "redirects": {
                "initial_url": "http://account-verification-alert.example-phishing.org/login",
                "final_url": "http://account-verification-alert.example-phishing.org/login",
                "initial_domain": "account-verification-alert.example-phishing.org",
                "final_domain": "account-verification-alert.example-phishing.org",
                "hop_count": 0,
                "cross_domain": False,
                "suspicious": False,
                "hops": [
                    {"hop": 0, "url": "http://account-verification-alert.example-phishing.org/login", "domain": "account-verification-alert.example-phishing.org", "ip": "104.20.23.156", "status_code": 200}
                ],
            },
            "reputation_lists_flagged": ["OpenPhish"],
        },
        sources={"OpenPhish": {"status": "ok"}, "RDAP": {"status": "ok"}},
    )
    db.add(scan_phish)

    # SEED TARGET 3: Malicious Hash with Behavior
    demo_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    scan_hash = _create_simulated_scan(
        scan_id="demo_scan_hash_0",
        target=demo_hash,
        target_type="hash",
        timestamp=now - timedelta(days=1),
        score=85,
        level="CRITICAL",
        confidence=92,
        malicious_count=42,
        total_engines=72,
        factors=[
            {
                "id": "av_detections_hit",
                "group": "AV_DETECTIONS",
                "type": "indicator",
                "severity": "critical",
                "points": 50,
                "title": "42 AV Engines Flagged Target [DEMO]",
                "description": "Simulated detection across 42 security vendor antivirus engines.",
                "source": "VirusTotal [DEMO]",
                "evidence_ref": {"malicious": 42},
            },
            {
                "id": "behavior_powershell",
                "group": "BEHAVIOR",
                "type": "indicator",
                "severity": "medium",
                "points": 10,
                "title": "PowerShell Execution Observed [DEMO]",
                "description": "Sandbox recorded base64 encoded PowerShell invocation.",
                "source": "Sandbox Behavior [DEMO]",
                "evidence_ref": {"powershell_command": "powershell.exe -enc SUVY..."},
            },
            {
                "id": "behavior_persistence",
                "group": "BEHAVIOR",
                "type": "indicator",
                "severity": "high",
                "points": 15,
                "title": "System Persistence Mechanism [DEMO]",
                "description": "Created Windows Registry Run key in HKCU.",
                "source": "Sandbox Behavior [DEMO]",
                "evidence_ref": {"persistence_type": "Registry RunKey"},
            },
        ],
        raw_summary={
            "group_breakdown": {"AV_DETECTIONS": 50, "REPUTATION_LISTS": 0, "DOMAIN_INFRA": 0, "BEHAVIOR": 25, "MITIGATING": 0},
            "explanation": "ThreatLens scored this target at 85/100 (CRITICAL) because multiple indicators point to malicious activity.",
            "recommended_action": "Do not open or execute this target. Block at perimeter firewalls and isolate any endpoints that accessed it.",
            "behavior": {
                "powershell_executed": True,
                "persistence_added": True,
                "suspicious_exec": True,
                "network_connection": {"destination": "c2-demo.evil-node.net", "port": 443},
            },
            "reputation_lists_flagged": [],
        },
        sources={"VirusTotal": {"status": "ok"}},
    )
    db.add(scan_hash)

    # SEED TARGET 4: Featured Deteriorating URL
    # Chronological: index 0 is oldest (4 days ago), index 4 is newest (today)
    hist_points = [
        # (index, days_ago, score, level, confidence, detections, factors, final_domain, hops_count, rep_lists)
        (
            0, 4, 18, "LOW", 60, 0,
            ["infra_new_domain"],
            "service-cdn.example-phishing-login.com", 0, [],
        ),
        (
            1, 3, 25, "LOW", 65, 1,
            ["infra_new_domain", "infra_suspicious_redirect"],
            "cdn-hop.example-gate.org", 1, [],
        ),
        (
            2, 2, 41, "MEDIUM", 72, 3,
            ["infra_new_domain", "infra_suspicious_redirect", "rep_openphish"],
            "auth-collect.phish-cdn.xyz", 2, ["OpenPhish"],
        ),
        (
            3, 1, 65, "HIGH", 85, 12,
            ["infra_new_domain", "infra_suspicious_redirect", "rep_openphish", "rep_google_safe_browsing"],
            "auth-collect.phish-cdn.xyz", 2, ["OpenPhish", "Safe Browsing"],
        ),
        (
            4, 0, 82, "CRITICAL", 94, 28,
            # Note: infra_new_domain is included consistently! (Domain is still <30 days old)
            ["infra_new_domain", "av_detections_hit", "rep_openphish", "rep_google_safe_browsing", "infra_suspicious_redirect", "infra_malicious_ip"],
            "malicious-delivery.phish-cdn.xyz", 3, ["OpenPhish", "Safe Browsing", "URLhaus"],
        ),
    ]

    last_featured_scan_id = "demo_scan_deteriorate_4"
    for idx, days_ago, sc, lvl, conf, det_c, factor_keys, f_dom, hops_c, rep_lists in hist_points:
        s_id = f"demo_scan_deteriorate_{idx}"

        # Build factors
        f_list = []
        if "infra_new_domain" in factor_keys:
            f_list.append({
                "id": "infra_new_domain",
                "group": "DOMAIN_INFRA",
                "type": "indicator",
                "severity": "medium",
                "points": 10,
                "title": "Newly Registered Domain [DEMO]",
                "description": "Domain registered recently; infrastructure age < 14 days.",
                "source": "RDAP [DEMO]",
                "evidence_ref": {"domain_age_days": 2 + (4 - days_ago)},
            })
        if "infra_suspicious_redirect" in factor_keys:
            f_list.append({
                "id": "infra_suspicious_redirect",
                "group": "DOMAIN_INFRA",
                "type": "indicator",
                "severity": "medium",
                "points": 10,
                "title": "Suspicious Redirect Chain [DEMO]",
                "description": f"URL diverts traffic across {hops_c} foreign domains before final destination.",
                "source": "Redirect Tracker [DEMO]",
                "evidence_ref": {"hops": hops_c},
            })
        if "rep_openphish" in factor_keys:
            f_list.append({
                "id": "rep_openphish",
                "group": "REPUTATION_LISTS",
                "type": "indicator",
                "severity": "high",
                "points": 30,
                "title": "OpenPhish Threat Listing [DEMO]",
                "description": "Target flagged on OpenPhish active credential phishing feed.",
                "source": "OpenPhish [DEMO]",
                "evidence_ref": {"flagged": True},
            })
        if "rep_google_safe_browsing" in factor_keys:
            f_list.append({
                "id": "rep_google_safe_browsing",
                "group": "REPUTATION_LISTS",
                "type": "indicator",
                "severity": "high",
                "points": 30,
                "title": "Google Safe Browsing Match [DEMO]",
                "description": "Listed in Safe Browsing blacklist for SOCIAL_ENGINEERING.",
                "source": "Google Safe Browsing [DEMO]",
                "evidence_ref": {"threat_types": ["SOCIAL_ENGINEERING"]},
            })
        if "av_detections_hit" in factor_keys:
            f_list.append({
                "id": "av_detections_hit",
                "group": "AV_DETECTIONS",
                "type": "indicator",
                "severity": "critical",
                "points": 50,
                "title": f"{det_c} AV Engines Flagged Target [DEMO]",
                "description": f"VirusTotal engines reached {det_c} detections.",
                "source": "VirusTotal [DEMO]",
                "evidence_ref": {"malicious": det_c},
            })
        if "infra_malicious_ip" in factor_keys:
            f_list.append({
                "id": "infra_malicious_ip",
                "group": "DOMAIN_INFRA",
                "type": "indicator",
                "severity": "high",
                "points": 20,
                "title": "Malicious Hosting IP [DEMO]",
                "description": "Resolved to known bulletproof hosting subnet.",
                "source": "IP Reputation [DEMO]",
                "evidence_ref": {"ip": "104.20.23.159"},
            })

        hops_data = [
            {"hop": 0, "url": FEATURED_DEMO_URL, "domain": "service-cdn.example-phishing-login.com", "ip": "104.20.23.154", "status_code": 302 if hops_c > 0 else 200}
        ]
        if hops_c >= 1:
            hops_data.append({"hop": 1, "url": f"http://{f_dom}/redirect", "domain": f_dom, "ip": "104.20.23.158", "status_code": 302 if hops_c > 1 else 200})
        if hops_c >= 2:
            hops_data.append({"hop": 2, "url": f"http://{f_dom}/auth", "domain": f_dom, "ip": "104.20.23.159", "status_code": 200})

        feat_scan = _create_simulated_scan(
            scan_id=s_id,
            target=FEATURED_DEMO_URL,
            target_type="url",
            timestamp=now - timedelta(days=days_ago, hours=2),
            score=sc,
            level=lvl,
            confidence=conf,
            malicious_count=det_c,
            total_engines=72,
            factors=f_list,
            raw_summary={
                "group_breakdown": {
                    "AV_DETECTIONS": 50 if det_c >= 16 else (30 if det_c >= 3 else 0),
                    "REPUTATION_LISTS": 35 if len(rep_lists) >= 2 else (30 if rep_lists else 0),
                    "DOMAIN_INFRA": 20 if "infra_malicious_ip" in factor_keys else 10,
                    "BEHAVIOR": 0,
                    "MITIGATING": 0,
                },
                "explanation": f"ThreatLens scored this target at {sc}/100 ({lvl}) based on deteriorating telemetry.",
                "recommended_action": "Do not open or execute this target. Block at perimeter firewalls." if sc >= 55 else "Exercise caution.",
                "redirects": {
                    "initial_url": FEATURED_DEMO_URL,
                    "final_url": f"http://{f_dom}/auth",
                    "initial_domain": "service-cdn.example-phishing-login.com",
                    "final_domain": f_dom,
                    "hop_count": hops_c,
                    "cross_domain": hops_c > 0,
                    "suspicious": hops_c > 0,
                    "hops": hops_data,
                },
                "reputation_lists_flagged": rep_lists,
            },
            sources={"VirusTotal": {"status": "ok"}, "OpenPhish": {"status": "ok"}},
        )
        db.add(feat_scan)

    # SEED TARGET 5: Improving URL (Chronological: _0 oldest, _1 newest)
    scan_imp_0 = _create_simulated_scan(
        scan_id="demo_scan_improve_0",
        target="http://remediated-host.example-clean.net/download",
        target_type="url",
        timestamp=now - timedelta(days=5),
        score=78,
        level="HIGH",
        confidence=80,
        malicious_count=18,
        total_engines=72,
        factors=[
            {
                "id": "av_detections_hit",
                "group": "AV_DETECTIONS",
                "type": "indicator",
                "severity": "high",
                "points": 50,
                "title": "18 AV Engines Flagged Target [DEMO]",
                "description": "Simulated malware hosting detections.",
                "source": "VirusTotal [DEMO]",
            }
        ],
        raw_summary={
            "group_breakdown": {"AV_DETECTIONS": 50, "REPUTATION_LISTS": 25, "DOMAIN_INFRA": 0, "BEHAVIOR": 0, "MITIGATING": 0},
            "explanation": "ThreatLens scored this target at 78/100 (HIGH).",
            "recommended_action": "Do not open or execute this target.",
            "redirects": {
                "initial_url": "http://remediated-host.example-clean.net/download",
                "final_url": "http://remediated-host.example-clean.net/download",
                "initial_domain": "remediated-host.example-clean.net",
                "final_domain": "remediated-host.example-clean.net",
                "hop_count": 0,
                "cross_domain": False,
                "suspicious": False,
                "hops": [
                    {"hop": 0, "url": "http://remediated-host.example-clean.net/download", "domain": "remediated-host.example-clean.net", "ip": "104.20.23.157", "status_code": 200}
                ],
            },
            "reputation_lists_flagged": ["URLhaus"],
        },
        sources={"VirusTotal": {"status": "ok"}},
    )
    scan_imp_1 = _create_simulated_scan(
        scan_id="demo_scan_improve_1",
        target="http://remediated-host.example-clean.net/download",
        target_type="url",
        timestamp=now - timedelta(hours=4),
        score=12,
        level="LOW",
        confidence=75,
        malicious_count=0,
        total_engines=72,
        factors=[
            {
                "id": "mitigating_established_reputation",
                "group": "MITIGATING",
                "type": "mitigating",
                "severity": "info",
                "points": -15,
                "title": "Remediated Clean Domain [DEMO]",
                "description": "Malicious payload removed; security vendors unflagged site.",
                "source": "ThreatLens Telemetry [DEMO]",
            }
        ],
        raw_summary={
            "group_breakdown": {"AV_DETECTIONS": 0, "REPUTATION_LISTS": 0, "DOMAIN_INFRA": 0, "BEHAVIOR": 0, "MITIGATING": -15},
            "explanation": "ThreatLens evaluated this target with a low risk rating of 12/100 (LOW).",
            "recommended_action": "No major threat indicators were found, but this is not a guarantee of safety.",
            "redirects": {
                "initial_url": "http://remediated-host.example-clean.net/download",
                "final_url": "http://remediated-host.example-clean.net/download",
                "initial_domain": "remediated-host.example-clean.net",
                "final_domain": "remediated-host.example-clean.net",
                "hop_count": 0,
                "cross_domain": False,
                "suspicious": False,
                "hops": [
                    {"hop": 0, "url": "http://remediated-host.example-clean.net/download", "domain": "remediated-host.example-clean.net", "ip": "104.20.23.157", "status_code": 200}
                ],
            },
            "reputation_lists_flagged": [],
        },
        sources={"VirusTotal": {"status": "ok"}},
    )
    db.add(scan_imp_0)
    db.add(scan_imp_1)

    # Add featured URL and safe URL to watchlist
    wl_item = WatchlistItem(
        id=generate_id("watch"),
        target=FEATURED_DEMO_URL,
        target_type="url",
        added_at=now - timedelta(days=4),
        last_scanned_at=now - timedelta(hours=2),
        last_level="CRITICAL",
        last_score=82,
        active=True,
    )
    db.add(wl_item)

    # Add initial alert for featured URL drift
    alert_item = Alert(
        id=generate_id("alert"),
        target=FEATURED_DEMO_URL,
        scan_id=last_featured_scan_id,
        previous_scan_id="demo_scan_deteriorate_3",
        kind="threat_escalation",
        message=f"{FEATURED_DEMO_URL} escalated from HIGH (65/100) to CRITICAL (82/100) with 28 AV detections.",
        created_at=now - timedelta(hours=2),
        seen=False,
    )
    db.add(alert_item)

    db.commit()

    return {
        "status": "seeded",
        "message": "Demo dataset seeded successfully.",
        "featured_target": FEATURED_DEMO_URL,
        "featured_scan_id": last_featured_scan_id,
    }
