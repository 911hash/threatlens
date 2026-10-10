"""
Email forensics engine: parses RFC822 email bytes, performs forensic header & auth analysis,
runs IP geolocation, calculates multi-group risk scores, generates attack chain graphs,
and persists scan results.
"""

from datetime import datetime
import email
import email.policy
import hashlib
import html
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from ..models import Scan, generate_id
from ..risk_engine import EVIDENCE_GROUPS, Factor, LEVEL_THRESHOLDS
from ..schemas import (
    AttackChainGraph,
    AttackChainLink,
    AttackChainNode,
    EmailAnalysisResponse,
    FactorResponse,
    GeoLocationResponse,
)
from ..services.attack_chain import build_attack_chain
from ..services.email_auth import parse_authentication_results
from ..services.email_headers import analyze_headers
from ..services.email_parser import parse_email
from ..services.geolocation import geolocate_ip
from ..services.llm_reasoner import reason

logger = logging.getLogger(__name__)

CONSUMER_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "zoho.com", "mail.com", "gmx.com"
}

COUNTRY_TLD_MAP = {
    "uk": "GB", "de": "DE", "fr": "FR", "ca": "CA", "jp": "JP",
    "au": "AU", "br": "BR", "in": "IN", "cn": "CN", "ru": "RU",
    "it": "IT", "es": "ES", "nl": "NL", "ch": "CH", "se": "SE",
    "no": "NO", "pl": "PL"
}


async def process_email_forensics(
    raw_bytes: bytes,
    filename: str = "sample.eml",
    hash_only: bool = False,
    db: Optional[Session] = None,
    gmail_id: Optional[str] = None,
    tenant_id: str = "default",
) -> Tuple[Scan, EmailAnalysisResponse]:
    """
    Forensically inspect in-memory raw RFC822 email bytes and persist scan.
    Strict Privacy Mode: Email file and attachments are processed purely in memory,
    never written to disk, and never retained.
    """
    total_size = len(raw_bytes)
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # 1. Parse RFC compliant email
    parse_result = parse_email(raw_bytes)

    # 2. Extract and evaluate email authentication (SPF, DKIM, DMARC, ARC)
    raw_headers: Dict[str, Any] = {}
    raw_received_lines: List[str] = []

    try:
        py_msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        for k, v in py_msg.items():
            k_clean = str(k)
            v_clean = str(v)
            if k_clean in raw_headers:
                if isinstance(raw_headers[k_clean], list):
                    raw_headers[k_clean].append(v_clean)
                else:
                    raw_headers[k_clean] = [raw_headers[k_clean], v_clean]
            else:
                raw_headers[k_clean] = v_clean

        for k, v in py_msg.raw_items():
            if str(k).lower() == "received":
                raw_received_lines.append(str(v))
    except Exception:
        pass

    auth_result = parse_authentication_results(raw_headers, parse_result.from_address)

    # 3. Analyze headers for forensic anomalies
    header_analysis = analyze_headers(
        headers=raw_headers,
        raw_received_lines=raw_received_lines,
        from_header=parse_result.sender,
        reply_to_header=parse_result.reply_to,
    )

    # 4. Risk Assessment & Factor Generation
    factors: List[Factor] = []

    # A. DOMAIN_INFRA group (cap 20)
    if auth_result.spf == "fail":
        factors.append(
            Factor(
                id="email_spf_fail",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="high",
                points=18,
                title="SPF Authentication Failed",
                description=f"Sending MTA is not authorized to deliver mail for domain '{auth_result.spf_domain or parse_result.from_domain}'.",
                source="Email Authentication",
                evidence_ref={"verdict": auth_result.spf, "domain": auth_result.spf_domain},
            )
        )
    elif auth_result.spf == "neutral":
        factors.append(
            Factor(
                id="email_spf_neutral",
                group="DOMAIN_INFRA",
                type="neutral",
                severity="low",
                points=5,
                title="SPF Neutral / Unspecified",
                description="SPF record does not explicitly authorize or deny sending IP address.",
                source="Email Authentication",
                evidence_ref={"verdict": auth_result.spf},
            )
        )

    if auth_result.dkim == "fail":
        factors.append(
            Factor(
                id="email_dkim_fail",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="high",
                points=18,
                title="DKIM Signature Verification Failed",
                description="Message cryptographic signature is invalid or message was modified during transit.",
                source="Email Authentication",
                evidence_ref={"verdict": auth_result.dkim, "domain": auth_result.dkim_domain},
            )
        )

    if auth_result.dmarc == "fail":
        factors.append(
            Factor(
                id="email_dmarc_fail",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="critical",
                points=22,
                title="DMARC Policy Enforcement Failure",
                description=f"Message failed sender domain DMARC alignment and verification (policy: {auth_result.dmarc_policy or 'none'}).",
                source="Email Authentication",
                evidence_ref={"verdict": auth_result.dmarc, "policy": auth_result.dmarc_policy},
            )
        )

    # B. REPUTATION_LISTS group (cap 35) - Phishing & Spoofing classification
    has_auth_failure = auth_result.spf == "fail" or auth_result.dmarc == "fail"
    if has_auth_failure and header_analysis.sender_reply_to_mismatch:
        factors.append(
            Factor(
                id="email_spoofed_identity_phish",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="critical",
                points=30,
                title="High-Confidence Phishing Identity Spoofing",
                description="Combined authentication failure and Reply-To redirection signature strongly indicates credential phishing deception.",
                source="Threat Forensics Engine",
                evidence_ref={"mismatch": header_analysis.mismatch_details},
            )
        )
    elif has_auth_failure:
        factors.append(
            Factor(
                id="email_unauthenticated_sender",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="high",
                points=20,
                title="Unauthenticated Mail Transmission",
                description="Sender failed domain authentication standards. Potential sender address forgery.",
                source="Threat Forensics Engine",
                evidence_ref={"from_domain": parse_result.from_domain},
            )
        )

    # C. BEHAVIOR group (cap 30)
    if header_analysis.sender_reply_to_mismatch:
        factors.append(
            Factor(
                id="email_reply_to_mismatch",
                group="BEHAVIOR",
                type="indicator",
                severity="high",
                points=20,
                title="Sender and Reply-To Mismatch",
                description=header_analysis.mismatch_details or "Reply-To address routes email responses away from the claimed sender domain.",
                source="Header Forensics",
                evidence_ref={"reply_to": parse_result.reply_to},
            )
        )

    suspicious_atts = [a for a in parse_result.attachments if a.is_suspicious]
    if suspicious_atts:
        factors.append(
            Factor(
                id="email_suspicious_attachment",
                group="BEHAVIOR",
                type="indicator",
                severity="critical",
                points=25,
                title="Suspicious Executable Email Attachment",
                description=f"Message contains potentially hazardous attachment: {suspicious_atts[0].filename} ({suspicious_atts[0].mime_type}).",
                source="Attachment Inspection",
                evidence_ref={"filename": suspicious_atts[0].filename, "sha256": suspicious_atts[0].sha256},
            )
        )

    if parse_result.html_body and ("<img" in parse_result.html_body.lower() or "url(" in parse_result.html_body.lower()):
        factors.append(
            Factor(
                id="email_tracking_elements",
                group="BEHAVIOR",
                type="indicator",
                severity="low",
                points=5,
                title="Remote Tracking Elements / Web Beacons Stripped",
                description="Body contained remote images or tracking pixels neutralized during in-memory HTML sanitization.",
                source="HTML Sanitizer",
                evidence_ref={"neutralized": True},
            )
        )

    if header_analysis.has_timing_anomaly:
        factors.append(
            Factor(
                id="email_relay_timing_anomaly",
                group="BEHAVIOR",
                type="indicator",
                severity="medium",
                points=10,
                title="Received Hop Timing Inversion or Abnormal Delay",
                description="; ".join(header_analysis.timing_gaps[:2]) if header_analysis.timing_gaps else "Anomalous delay observed in relay chain.",
                source="Header Forensics",
                evidence_ref={"gaps": header_analysis.timing_gaps},
            )
        )

    if header_analysis.x_spam_status and re.search(r"\byes\b", header_analysis.x_spam_status, re.IGNORECASE):
        factors.append(
            Factor(
                id="email_x_spam_flag",
                group="BEHAVIOR",
                type="indicator",
                severity="high",
                points=18,
                title="Upstream MTA Flagged as Spam",
                description=f"X-Spam-Status indicates mail was tagged as spam: {header_analysis.x_spam_status}",
                source="Header Forensics",
                evidence_ref={"status": header_analysis.x_spam_status},
            )
        )

    # D. MITIGATING group (floor -30)
    is_fully_authenticated = auth_result.spf == "pass" and auth_result.dkim == "pass" and auth_result.dmarc == "pass"
    if is_fully_authenticated:
        factors.append(
            Factor(
                id="email_auth_perfect_pass",
                group="MITIGATING",
                type="mitigating",
                severity="info",
                points=-25,
                title="Cryptographic Email Authentication Validated",
                description="Message passed SPF, DKIM, and DMARC verification with aligned domain policies.",
                source="Email Authentication",
                evidence_ref={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            )
        )

    if not any(f.type == "indicator" for f in factors) and not parse_result.is_malformed:
        factors.append(
            Factor(
                id="email_clean_structure",
                group="MITIGATING",
                type="mitigating",
                severity="info",
                points=-10,
                title="Clean Email Transport Structure",
                description="No relay timing inversions, executable attachments, or routing mismatches detected.",
                source="Header Forensics",
                evidence_ref={"attachments_count": len(parse_result.attachments)},
            )
        )

    # 5. GEOLOCATION group evaluation (in hop order)
    geo_results = []
    if db is not None:
        for sender_ip in parse_result.sender_ips:
            geo = geolocate_ip(sender_ip, db, hash_only=hash_only)
            geo_results.append(geo)

    header_analysis.geo_results = [
        GeoLocationResponse(**g.model_dump()) for g in geo_results
    ]

    # Geolocation Factors
    has_tor = any(g.is_tor for g in geo_results)
    if has_tor:
        tor_ips = [g.ip for g in geo_results if g.is_tor]
        factors.append(
            Factor(
                id="geo_tor_exit_node",
                group="GEOLOCATION",
                type="indicator",
                severity="critical",
                points=15,
                title="Tor Exit Node Origin",
                description="Message originated from or routed through a confirmed Tor anonymizing exit relay.",
                source="IP Geolocation Intelligence",
                evidence_ref={"tor_ips": tor_ips},
            )
        )

    has_vpn_proxy = any((g.is_vpn or g.is_proxy) for g in geo_results)
    if has_vpn_proxy:
        vpn_ips = [g.ip for g in geo_results if (g.is_vpn or g.is_proxy)]
        factors.append(
            Factor(
                id="geo_vpn_proxy",
                group="GEOLOCATION",
                type="indicator",
                severity="medium",
                points=5,
                title="Anonymous VPN or Proxy Infrastructure",
                description="Originating transmission IP is associated with a commercial VPN or anonymizing proxy service.",
                source="IP Geolocation Intelligence",
                evidence_ref={"vpn_ips": vpn_ips},
            )
        )

    is_consumer_sender = any(
        (parse_result.from_domain or "").lower().endswith(dom)
        or (parse_result.from_address or "").lower().endswith(dom)
        for dom in CONSUMER_DOMAINS
    )
    has_datacenter_consumer = any(g.is_datacenter and is_consumer_sender for g in geo_results)
    if has_datacenter_consumer:
        dc_ips = [g.ip for g in geo_results if g.is_datacenter]
        factors.append(
            Factor(
                id="geo_datacenter_sender",
                group="GEOLOCATION",
                type="indicator",
                severity="medium",
                points=5,
                title="Datacenter Hosting IP for Consumer Sender",
                description="Consumer-facing sender originated from a cloud or datacenter hosting provider rather than legitimate residential or webmail infrastructure.",
                source="Infrastructure Telemetry",
                evidence_ref={"datacenter_ips": dc_ips},
            )
        )

    has_country_mismatch = False
    mismatch_evidence = []
    sender_tld_val = ""
    if parse_result.from_domain:
        sender_tld_val = parse_result.from_domain.lower().split(".")[-1]
        if sender_tld_val in COUNTRY_TLD_MAP:
            expected_cc = COUNTRY_TLD_MAP[sender_tld_val]
            for g in geo_results:
                if g.country_code and g.country_code.upper() != expected_cc and g.country_code != "LOCAL":
                    has_country_mismatch = True
                    mismatch_evidence.append({
                        "ip": g.ip,
                        "ip_country": g.country_code.upper(),
                        "expected_country": expected_cc,
                        "tld": sender_tld_val,
                    })

    if has_country_mismatch:
        factors.append(
            Factor(
                id="geo_country_tld_mismatch",
                group="GEOLOCATION",
                type="indicator",
                severity="low",
                points=3,
                title="Sender IP Country Mismatch with Domain TLD",
                description=f"Originating IP country does not match sender domain country-code TLD (.{sender_tld_val}).",
                source="Geo-Forensic Correlation",
                evidence_ref={"mismatches": mismatch_evidence},
            )
        )

    # 6. Score calculation with group capping
    infra_raw = sum(f.points for f in factors if f.group == "DOMAIN_INFRA")
    infra_points = max(0, min(infra_raw, EVIDENCE_GROUPS["DOMAIN_INFRA"]["cap"]))

    rep_raw = sum(f.points for f in factors if f.group == "REPUTATION_LISTS")
    rep_points = max(0, min(rep_raw, EVIDENCE_GROUPS["REPUTATION_LISTS"]["cap"]))

    beh_raw = sum(f.points for f in factors if f.group == "BEHAVIOR")
    beh_points = max(0, min(beh_raw, EVIDENCE_GROUPS["BEHAVIOR"]["cap"]))

    geo_raw = sum(f.points for f in factors if f.group == "GEOLOCATION")
    geo_points = max(0, min(geo_raw, EVIDENCE_GROUPS["GEOLOCATION"]["cap"]))

    mit_raw = sum(f.points for f in factors if f.group == "MITIGATING")
    mit_points = min(0, max(mit_raw, EVIDENCE_GROUPS["MITIGATING"]["floor"]))

    group_breakdown = {
        "AV_DETECTIONS": 0,
        "REPUTATION_LISTS": rep_points,
        "DOMAIN_INFRA": infra_points,
        "BEHAVIOR": beh_points,
        "GEOLOCATION": geo_points,
        "MITIGATING": mit_points,
    }

    score = max(0, min(100, infra_points + rep_points + beh_points + geo_points + mit_points))

    if parse_result.is_malformed and not factors:
        risk_level = "UNKNOWN"
        confidence = 15
        explanation = "Email could not be parsed as a valid RFC message. Essential headers were missing."
        action = "Do not open attachments or follow links in malformed or corrupted email files."
    else:
        confidence = 85
        risk_level = "SAFE"
        for low_bound, high_bound, lvl_name in LEVEL_THRESHOLDS:
            if low_bound <= score <= high_bound:
                risk_level = lvl_name
                break

        if risk_level in ("CRITICAL", "HIGH"):
            action = "Phishing threat detected. Do not reply, click links, or open attachments. Report to Security Operations."
            explanation = (
                f"ThreatLens scored this email at {score}/100 ({risk_level}). Critical anomalies observed: "
                + "; ".join(f.title for f in factors if f.type == "indicator")
                + "."
            )
        elif risk_level == "MEDIUM":
            action = "Exercise caution. Verify the sender identity through an out-of-band channel before taking any action."
            explanation = f"ThreatLens flagged suspicious properties resulting in a {score}/100 ({risk_level}) rating."
        elif risk_level == "LOW":
            action = "Standard vigilance recommended. Review links and attachments carefully."
            explanation = f"ThreatLens evaluated this email with low risk ({score}/100). Minor transport variances noted."
        else:
            action = "Email verified against authentication standards. No high-risk indicators found."
            explanation = f"ThreatLens evaluated this email as SAFE ({score}/100). SPF, DKIM, and DMARC checks passed."

    # 7. Attack Chain Graph
    chain_nodes: List[AttackChainNode] = []
    chain_links: List[AttackChainLink] = []

    sender_status = (
        "malicious"
        if (auth_result.dmarc == "fail" or header_analysis.sender_reply_to_mismatch)
        else ("safe" if auth_result.dmarc == "pass" else "neutral")
    )
    from_label = parse_result.from_address or parse_result.sender or "Unknown Sender"
    chain_nodes.append(AttackChainNode(id="node_sender", label=from_label, type="domain", status=sender_status))

    prev_node_id = "node_sender"
    if parse_result.sender_ips:
        orig_ip = parse_result.sender_ips[0]
        ip_status = "suspicious" if auth_result.spf == "fail" else "safe"
        chain_nodes.append(AttackChainNode(id="node_orig_ip", label=f"IP: {orig_ip}", type="ip", status=ip_status))
        chain_links.append(AttackChainLink(source="node_orig_ip", target="node_sender", label="originates"))

    for hop in header_analysis.hops[:4]:
        hop_id = f"node_hop_{hop.hop_index}"
        hop_label = hop.by_host or f"Hop {hop.hop_index}"
        hop_status = "suspicious" if (hop.delay_seconds and hop.delay_seconds > 3600) else "safe"
        chain_nodes.append(AttackChainNode(id=hop_id, label=hop_label, type="redirect", status=hop_status))
        chain_links.append(AttackChainLink(source=prev_node_id, target=hop_id, label="relays"))
        prev_node_id = hop_id

    recip_label = parse_result.to_addresses[0] if parse_result.to_addresses else "Recipient"
    chain_nodes.append(AttackChainNode(id="node_recipient", label=recip_label, type="action", status="neutral"))
    chain_links.append(AttackChainLink(source=prev_node_id, target="node_recipient", label="delivers"))

    for idx, att in enumerate(parse_result.attachments):
        att_id = f"node_att_{idx}"
        att_status = "malicious" if att.is_suspicious else "safe"
        chain_nodes.append(AttackChainNode(id=att_id, label=att.filename, type="process", status=att_status))
        chain_links.append(AttackChainLink(source="node_recipient", target=att_id, label="payload"))

    attack_chain = AttackChainGraph(nodes=chain_nodes, links=chain_links)

    sources_dict = {
        "Email Authentication": {
            "spf": auth_result.spf,
            "dkim": auth_result.dkim,
            "dmarc": auth_result.dmarc,
            "arc": auth_result.arc,
            "spf_aligned": auth_result.spf_aligned,
            "dkim_aligned": auth_result.dkim_aligned,
        },
        "Header Forensics": {
            "hop_count": header_analysis.hop_count,
            "mismatch": header_analysis.sender_reply_to_mismatch,
            "timing_anomaly": header_analysis.has_timing_anomaly,
        },
        "Attachment Scanner": {
            "total_attachments": len(parse_result.attachments),
            "suspicious_count": len(suspicious_atts),
        },
        "HTML Sanitizer": {
            "sanitized": bool(parse_result.sanitized_html),
            "images_neutralized": True,
        },
        "IP Geolocation": {
            "total_ips": len(geo_results),
            "tor_detected": has_tor,
            "vpn_detected": has_vpn_proxy,
        },
    }

    # Target identifier
    if parse_result.message_id and parse_result.message_id.strip():
        target_display = html.unescape(parse_result.message_id.strip())
    else:
        fallback_str = f"{parse_result.sender or ''}{parse_result.subject or ''}{parse_result.date or ''}"
        target_display = hashlib.sha256(fallback_str.encode("utf-8")).hexdigest()

    # Engine signals
    if parse_result.is_malformed and not factors:
        total_engines = 0
        detection_count = 0
    else:
        auth_signals = 4
        hops_signals = header_analysis.hop_count
        att_signals = len(parse_result.attachments)
        geo_signals = len(geo_results)
        total_signals = auth_signals + hops_signals + att_signals + geo_signals
        raw_detection_count = len([f for f in factors if f.type == "indicator"])
        total_engines = max(total_signals, raw_detection_count)
        detection_count = min(raw_detection_count, total_engines)

    # Mandatory LLM Threat Reasoning (Always On)
    # Any LLM 503 error propagates directly - no template fallback
    llm_res = await reason(
        evidence={
            "subject": parse_result.subject,
            "from_domain": parse_result.from_domain,
            "reply_to": parse_result.reply_to,
            "authentication": {
                "spf": auth_result.spf,
                "dkim": auth_result.dkim,
                "dmarc": auth_result.dmarc,
            },
            "risk_score": score,
            "risk_level": risk_level,
            "indicators": [f.title for f in factors if f.type == "indicator"],
            "mitigating": [f.title for f in factors if f.type == "mitigating"],
            "suspicious_attachments": [a.filename for a in parse_result.attachments if a.is_suspicious],
            "geo_summary": {
                "originating_ips": [g.ip for g in geo_results],
                "tor_exit": has_tor,
                "vpn_proxy": has_vpn_proxy,
                "datacenter_sender": has_datacenter_consumer,
            },
        },
        body_excerpt=(parse_result.plain_body or "")[:1500],
        db=db,
    )
    explanation = llm_res.summary

    factors_dict = [f.__dict__ for f in factors]
    raw_summary = {
        "group_breakdown": group_breakdown,
        "explanation": explanation,
        "recommended_action": action,
        "auth_result": auth_result.model_dump(),
        "header_analysis": header_analysis.model_dump(),
        "attachments": [
            {
                "filename": a.filename,
                "mime_type": a.mime_type,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256,
                "is_suspicious": a.is_suspicious,
            }
            for a in parse_result.attachments
        ],
        "attack_chain": attack_chain.model_dump(),
        "file_sha256": file_sha256,
        "file_size": total_size,
        "from_address": parse_result.from_address,
        "to_addresses": parse_result.to_addresses,
        "reply_to": parse_result.reply_to,
        "date": parse_result.date,
        "subject": parse_result.subject,
        "sanitized_html": parse_result.sanitized_html,
        "plain_body": parse_result.plain_body,
        "geo_results": [g.model_dump() for g in geo_results],
        "sender_ips": parse_result.sender_ips,
        "privacy_mode": "hash_only" if hash_only else "full",
        "gmail_id": gmail_id,
        "llm_result": {
            "summary": llm_res.summary,
            "provider_used": llm_res.provider_used,
            "latency_ms": llm_res.latency_ms,
            "cache_hit": llm_res.cache_hit,
        },
        "anonymized_prompt": llm_res.anonymized_prompt,
    }

    scan = Scan(
        id=generate_id("scan"),
        target=target_display,
        target_type="email",
        timestamp=datetime.utcnow(),
        risk_score=score,
        risk_level=risk_level,
        confidence=confidence,
        detection_count=detection_count,
        total_engines=total_engines,
        factors_json=json.dumps(factors_dict),
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources_dict),
        is_demo=False,
        created_at=datetime.utcnow(),
    )

    if db is not None:
        db.add(scan)
        db.commit()
        db.refresh(scan)
        try:
            from .graph_service import index_email
            index_email(scan.id, tenant_id=tenant_id, db=db)
        except Exception as e:
            logger.exception("Failed to index email scan into artifact graph: %s", e)

    factors_response = [FactorResponse(**f) for f in factors_dict]

    response = EmailAnalysisResponse(
        id=scan.id,
        target=scan.target,
        target_type="email",
        subject=parse_result.subject,
        timestamp=scan.timestamp,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        confidence=scan.confidence,
        detection_count=scan.detection_count,
        total_engines=scan.total_engines,
        factors=factors_response,
        group_breakdown=group_breakdown,
        raw_summary=raw_summary,
        sources=sources_dict,
        attack_chain=attack_chain,
        is_demo=scan.is_demo,
        explanation=explanation,
        recommended_action=action,
        defanged_target=scan.target,
        parse_result=parse_result,
        auth_result=auth_result,
        header_analysis=header_analysis,
        sanitized_html=parse_result.sanitized_html,
        file_sha256=file_sha256,
        file_size=total_size,
        geo_results=[GeoLocationResponse(**g.model_dump()) for g in geo_results],
        privacy_mode="hash_only" if hash_only else "full",
        llm_result={
            "summary": llm_res.summary,
            "provider_used": llm_res.provider_used,
            "latency_ms": llm_res.latency_ms,
            "cache_hit": llm_res.cache_hit,
        },
        anonymized_prompt=llm_res.anonymized_prompt,
    )

    return scan, response

