"""
Pure explainable risk scoring engine for ThreatLens.
No network, no database, no system clock calls inside.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# Transparent scoring weights and caps
EVIDENCE_GROUPS = {
    "AV_DETECTIONS": {"cap": 50, "floor": 0},
    "REPUTATION_LISTS": {"cap": 35, "floor": 0},
    "DOMAIN_INFRA": {"cap": 20, "floor": 0},
    "BEHAVIOR": {"cap": 30, "floor": 0},
    "MITIGATING": {"cap": 0, "floor": -30},
}

LEVEL_THRESHOLDS = [
    (80, 100, "CRITICAL"),
    (55, 79, "HIGH"),
    (30, 54, "MEDIUM"),
    (10, 29, "LOW"),
    (0, 9, "SAFE"),
]


@dataclass
class Factor:
    id: str
    group: str  # AV_DETECTIONS, REPUTATION_LISTS, DOMAIN_INFRA, BEHAVIOR, MITIGATING
    type: str   # indicator, mitigating, neutral, conflict
    severity: str  # info, low, medium, high, critical
    points: int  # contribution before or after group capping
    title: str
    description: str
    source: str
    evidence_ref: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvidence:
    target: str
    target_type: str = "url"  # url, hash, file
    now: Optional[datetime] = None

    # Source data structures
    virustotal: Optional[Dict[str, Any]] = None
    safe_browsing: Optional[Dict[str, Any]] = None
    urlhaus: Optional[Dict[str, Any]] = None
    openphish: Optional[Dict[str, Any]] = None
    rdap: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    certificates: Optional[Dict[str, Any]] = None
    redirects: Optional[Dict[str, Any]] = None
    behavior: Optional[Dict[str, Any]] = None
    file_metadata: Optional[Dict[str, Any]] = None
    ip_reputation: Optional[Dict[str, Any]] = None
    known_good: Optional[Dict[str, Any]] = None


@dataclass
class RiskAssessment:
    score: int
    level: str  # SAFE | LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    confidence: int  # 0 - 100
    factors: List[Factor]
    group_breakdown: Dict[str, int]
    raw_evidence_summary: Dict[str, Any]
    explanation: str
    recommended_action: str


def evaluate(evidence: NormalizedEvidence, now: Optional[datetime] = None) -> RiskAssessment:
    """
    Evaluate threat evidence in a pure function.
    Deterministic, transparent, anti-double-counting.
    """
    ref_time = now or evidence.now or datetime(2026, 1, 1, 0, 0, 0)
    factors: List[Factor] = []
    has_any_source_data = False
    source_groups_present = set()

    # 1. AV_DETECTIONS group
    vt_malicious = 0
    vt_suspicious = 0
    vt_total = 0

    if evidence.virustotal and evidence.virustotal.get("status") not in ("no_data", "unavailable", "error"):
        vt_malicious = int(evidence.virustotal.get("malicious", 0))
        vt_suspicious = int(evidence.virustotal.get("suspicious", 0))
        vt_total = int(evidence.virustotal.get("total", 0))
        if vt_total > 0 or vt_malicious > 0 or vt_suspicious > 0 or evidence.virustotal.get("categories"):
            has_any_source_data = True
            source_groups_present.add("virustotal")

        if vt_malicious > 0 or vt_suspicious > 0:
            # VT malicious points
            mal_pts = 0
            if vt_malicious >= 16:
                mal_pts = 50
            elif vt_malicious >= 6:
                mal_pts = 40
            elif vt_malicious >= 3:
                mal_pts = 30
            elif vt_malicious >= 1:
                mal_pts = 20

            # VT suspicious points
            susp_pts = 0
            if vt_suspicious >= 6:
                susp_pts = 15
            elif vt_suspicious >= 3:
                susp_pts = 10
            elif vt_suspicious >= 1:
                susp_pts = 5

            av_points = min(mal_pts + susp_pts, EVIDENCE_GROUPS["AV_DETECTIONS"]["cap"])
            sev = "critical" if vt_malicious >= 10 else ("high" if vt_malicious >= 3 else "medium")
            
            factors.append(Factor(
                id="av_detections_hit",
                group="AV_DETECTIONS",
                type="indicator",
                severity=sev,
                points=av_points,
                title=f"{vt_malicious} AV Engines Flagged Target",
                description=(
                    f"VirusTotal detected {vt_malicious} malicious and {vt_suspicious} suspicious "
                    f"verdicts across {vt_total} security scanners."
                ),
                source="VirusTotal",
                evidence_ref={"malicious": vt_malicious, "suspicious": vt_suspicious, "total": vt_total}
            ))

    # 2. REPUTATION_LISTS group (cap +35)
    rep_factors: List[Factor] = []
    
    # Safe Browsing
    if evidence.safe_browsing and evidence.safe_browsing.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("safe_browsing")
        if evidence.safe_browsing.get("flagged"):
            threats = evidence.safe_browsing.get("threat_types", ["MALWARE"])
            threat_str = ", ".join(threats)
            rep_factors.append(Factor(
                id="rep_google_safe_browsing",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="high",
                points=30,
                title="Google Safe Browsing Match",
                description=f"Listed in Google Safe Browsing blacklist for threat types: {threat_str}.",
                source="Google Safe Browsing",
                evidence_ref={"threat_types": threats}
            ))

    # URLhaus
    if evidence.urlhaus and evidence.urlhaus.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("urlhaus")
        if evidence.urlhaus.get("flagged"):
            uh_status = evidence.urlhaus.get("threat", "Malware distribution")
            rep_factors.append(Factor(
                id="rep_abusech_urlhaus",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="high",
                points=30,
                title="Abuse.ch URLhaus Blacklist",
                description=f"Active threat listing confirmed on abuse.ch URLhaus: {uh_status}.",
                source="URLhaus",
                evidence_ref={"threat": uh_status}
            ))

    # OpenPhish
    if evidence.openphish and evidence.openphish.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("openphish")
        if evidence.openphish.get("flagged"):
            rep_factors.append(Factor(
                id="rep_openphish",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="high",
                points=30,
                title="OpenPhish Phishing Feed Match",
                description="URL identified in OpenPhish active phishing intelligence feed.",
                source="OpenPhish",
                evidence_ref={"flagged": True}
            ))

    # VT Categories / Known malicious
    if evidence.virustotal and evidence.virustotal.get("categories"):
        cats = [str(c).lower() for c in evidence.virustotal.get("categories", [])]
        if any("phishing" in c or "malicious" in c for c in cats):
            rep_factors.append(Factor(
                id="rep_vt_category",
                group="REPUTATION_LISTS",
                type="indicator",
                severity="medium",
                points=25,
                title="VirusTotal Threat Category",
                description=f"Categorized as malicious or phishing by intelligence vendors: {', '.join(cats[:3])}.",
                source="VirusTotal",
                evidence_ref={"categories": cats}
            ))

    # 3. DOMAIN_INFRA group (cap +20)
    infra_factors: List[Factor] = []

    # RDAP domain age
    if evidence.rdap and evidence.rdap.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("rdap")
        age_days = evidence.rdap.get("domain_age_days")
        is_new = evidence.rdap.get("is_newly_registered", False) or (age_days is not None and age_days < 30)
        registrar = evidence.rdap.get("registrar", "Unknown")
        if is_new:
            age_desc = f"{age_days} days old" if age_days is not None else "newly registered (< 30 days)"
            infra_factors.append(Factor(
                id="infra_new_domain",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="medium",
                points=10,
                title="Newly Registered Domain",
                description=f"Domain registered recently ({age_desc}) via registrar '{registrar}', a common tactic for disposable attack campaigns.",
                source="RDAP",
                evidence_ref={"domain_age_days": age_days, "registrar": registrar}
            ))

    # Redirect chain
    if evidence.redirects and evidence.redirects.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("redirects")
        hops = evidence.redirects.get("hop_count", 0)
        cross_dom = evidence.redirects.get("cross_domain", False)
        susp_redir = evidence.redirects.get("suspicious", False)
        if hops >= 2 or cross_dom or susp_redir:
            infra_factors.append(Factor(
                id="infra_suspicious_redirect",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="medium",
                points=10,
                title="Suspicious Redirect Chain",
                description=(
                    f"Analyzed {hops} redirect hops across external domains. "
                    "Chain obscures the final destination."
                ),
                source="Redirect Tracker",
                evidence_ref={"hops": hops, "cross_domain": cross_dom}
            ))

    # Malicious IP / ASN
    if evidence.ip_reputation and evidence.ip_reputation.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("ip_reputation")
        if evidence.ip_reputation.get("is_malicious"):
            ip_val = evidence.ip_reputation.get("ip", "Target IP")
            asn = evidence.ip_reputation.get("asn", "Unknown")
            infra_factors.append(Factor(
                id="infra_malicious_ip",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="high",
                points=20,
                title="Malicious Hosting Infrastructure",
                description=f"Hosting IP {ip_val} (ASN: {asn}) has documented malicious activity history.",
                source="IP Reputation",
                evidence_ref={"ip": ip_val, "asn": asn}
            ))

    # Certificates (crt.sh)
    if evidence.certificates and evidence.certificates.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("certificates")
        susp_sans = evidence.certificates.get("suspicious_sans", False)
        cert_age = evidence.certificates.get("age_days")
        if susp_sans or (cert_age is not None and cert_age < 3):
            infra_factors.append(Factor(
                id="infra_suspicious_cert",
                group="DOMAIN_INFRA",
                type="indicator",
                severity="low",
                points=5,
                title="Suspicious TLS Certificate Pattern",
                description="Certificate Transparency records show anomalous SAN patterns or brand typosquatting.",
                source="crt.sh",
                evidence_ref={"suspicious_sans": susp_sans, "age_days": cert_age}
            ))

    # DNS check
    if evidence.dns and evidence.dns.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("dns")

    # 4. BEHAVIOR group (cap +30)
    behavior_factors: List[Factor] = []
    if evidence.behavior and evidence.behavior.get("status") != "no_data":
        has_any_source_data = True
        source_groups_present.add("behavior")
        
        if evidence.behavior.get("powershell_executed"):
            behavior_factors.append(Factor(
                id="behavior_powershell",
                group="BEHAVIOR",
                type="indicator",
                severity="medium",
                points=10,
                title="PowerShell Execution Observed",
                description="Sandbox recorded execution of encoded or suspicious PowerShell command lines.",
                source="Sandbox Behavior",
                evidence_ref={"powershell_command": evidence.behavior.get("powershell_command", "powershell.exe -enc")}
            ))

        if evidence.behavior.get("persistence_added"):
            behavior_factors.append(Factor(
                id="behavior_persistence",
                group="BEHAVIOR",
                type="indicator",
                severity="high",
                points=15,
                title="System Persistence Mechanism",
                description="Process created auto-run registry keys, scheduled tasks, or startup hooks.",
                source="Sandbox Behavior",
                evidence_ref={"persistence_type": evidence.behavior.get("persistence_type", "RunKey")}
            ))

        if evidence.behavior.get("suspicious_exec"):
            behavior_factors.append(Factor(
                id="behavior_suspicious_exec",
                group="BEHAVIOR",
                type="indicator",
                severity="high",
                points=15,
                title="Suspicious Executable Activity",
                description="Dropped executables into AppData or injected into legitimate system binaries.",
                source="Sandbox Behavior",
                evidence_ref={"details": evidence.behavior.get("exec_details", "Dropped executable")}
            ))

    # 5. MITIGATING group (floor -30)
    # Mitigating cannot apply if AV_DETECTIONS >= 3 (flag conflict instead)
    mitigating_factors: List[Factor] = []
    mitigating_conflict_flag = False

    is_signed = False
    is_trusted_pub = False
    is_top_domain = False
    high_prevalence = False

    if evidence.file_metadata and evidence.file_metadata.get("status") not in ("no_data", "unavailable", "error"):
        is_signed = bool(evidence.file_metadata.get("is_signed") and evidence.file_metadata.get("signature_valid"))
        is_trusted_pub = bool(evidence.file_metadata.get("trusted_publisher"))
        high_prevalence = evidence.file_metadata.get("prevalence") == "high"
        if is_signed or is_trusted_pub or high_prevalence:
            has_any_source_data = True
            source_groups_present.add("file_metadata")

    if evidence.known_good and evidence.known_good.get("status") not in ("no_data", "unavailable", "error"):
        is_top_domain = bool(evidence.known_good.get("top_1m") or evidence.known_good.get("verified_vendor"))
        if is_top_domain:
            has_any_source_data = True
            source_groups_present.add("known_good")

    if is_signed or is_trusted_pub or is_top_domain or high_prevalence:
        if vt_malicious >= 3:
            mitigating_conflict_flag = True
            factors.append(Factor(
                id="conflict_signed_malicious",
                group="AV_DETECTIONS",
                type="conflict",
                severity="high",
                points=0,
                title="Signature Security Conflict",
                description=(
                    f"File or target presents a digital signature, but {vt_malicious} security engines "
                    "flagged it as malicious. Mitigating credits are withheld; signature may be stolen or compromised."
                ),
                source="ThreatLens Analysis",
                evidence_ref={"vt_malicious": vt_malicious, "is_signed": is_signed}
            ))
        else:
            if is_signed:
                mitigating_factors.append(Factor(
                    id="mitigating_valid_signature",
                    group="MITIGATING",
                    type="mitigating",
                    severity="info",
                    points=-15,
                    title="Valid Cryptographic Digital Signature",
                    description="Binary contains a verified cryptographic signature from an authenticated vendor certificate.",
                    source="File Authenticode",
                    evidence_ref={"signature_valid": True}
                ))

            if is_trusted_pub or is_top_domain:
                mitigating_factors.append(Factor(
                    id="mitigating_established_reputation",
                    group="MITIGATING",
                    type="mitigating",
                    severity="info",
                    points=-15,
                    title="Established Benign Reputation",
                    description="Target domain or publisher has long-standing legitimate presence in trusted authority databases.",
                    source="Reputation Intelligence",
                    evidence_ref={"trusted": True}
                ))

            if high_prevalence:
                mitigating_factors.append(Factor(
                    id="mitigating_high_prevalence",
                    group="MITIGATING",
                    type="mitigating",
                    severity="info",
                    points=-10,
                    title="High Global Prevalence",
                    description="Observed across hundreds of thousands of standard corporate endpoints without incident.",
                    source="Prevalence Telemetry",
                    evidence_ref={"prevalence": "high"}
                ))

    # Add factors from groups into main list
    factors.extend(rep_factors)
    factors.extend(infra_factors)
    factors.extend(behavior_factors)
    factors.extend(mitigating_factors)

    # 6. Apply group caps and compute score
    # AV_DETECTIONS group:
    av_raw = sum(f.points for f in factors if f.group == "AV_DETECTIONS" and f.type != "conflict")
    av_points = max(0, min(av_raw, EVIDENCE_GROUPS["AV_DETECTIONS"]["cap"]))

    # REPUTATION_LISTS group:
    # Multiple lists agreeing does not stack beyond cap (+35); take max or capped sum
    rep_raw = sum(f.points for f in factors if f.group == "REPUTATION_LISTS")
    rep_points = max(0, min(rep_raw, EVIDENCE_GROUPS["REPUTATION_LISTS"]["cap"]))

    # DOMAIN_INFRA group: cap +20
    infra_raw = sum(f.points for f in factors if f.group == "DOMAIN_INFRA")
    infra_points = max(0, min(infra_raw, EVIDENCE_GROUPS["DOMAIN_INFRA"]["cap"]))

    # BEHAVIOR group: cap +30
    beh_raw = sum(f.points for f in factors if f.group == "BEHAVIOR")
    beh_points = max(0, min(beh_raw, EVIDENCE_GROUPS["BEHAVIOR"]["cap"]))

    # MITIGATING group: floor -30
    mit_raw = sum(f.points for f in factors if f.group == "MITIGATING")
    mit_points = min(0, max(mit_raw, EVIDENCE_GROUPS["MITIGATING"]["floor"]))

    group_breakdown = {
        "AV_DETECTIONS": av_points,
        "REPUTATION_LISTS": rep_points,
        "DOMAIN_INFRA": infra_points,
        "BEHAVIOR": beh_points,
        "MITIGATING": mit_points,
    }

    raw_sum = av_points + rep_points + infra_points + beh_points + mit_points
    score = max(0, min(100, raw_sum))

    # 7. Confidence Calculation
    # Confidence represents evidence quality / depth, NOT danger level.
    # Factors:
    # - Number of distinct independent source groups providing telemetry
    # - Agreement among independent sources
    # - If no source data: confidence <= 10
    total_sources = len(source_groups_present)
    confidence = 0

    if not has_any_source_data or total_sources == 0:
        confidence = 0
        score = 0
        level = "UNKNOWN"
    elif evidence.target_type in ("file", "hash") and vt_total == 0 and not behavior_factors and not rep_factors:
        confidence = 0
        score = 0
        level = "UNKNOWN"
    else:
        # Source count base:
        # 1 source: 30 base
        # 2 sources: 50 base
        # 3 sources: 70 base
        # 4+ sources: 85 base
        if total_sources == 1:
            base_conf = 30
        elif total_sources == 2:
            base_conf = 50
        elif total_sources == 3:
            base_conf = 70
        else:
            base_conf = 85

        # Multi-source agreement bonus:
        # e.g. VT detects threat + reputation list agrees => +10 confidence
        flagged_rep_count = len(rep_factors)
        has_av_hit = vt_malicious > 0
        
        bonus = 0
        if has_av_hit and flagged_rep_count >= 1:
            bonus += 10
        if flagged_rep_count >= 2:
            bonus += 5
        if vt_malicious >= 10:
            bonus += 5
        if is_signed and vt_total > 50 and vt_malicious == 0:
            bonus += 15  # Clean signed file checked against 50+ engines

        confidence = max(10, min(100, base_conf + bonus))

        # Level determination
        if confidence <= 10:
            level = "UNKNOWN"
        else:
            level = "UNKNOWN"
            for low_bound, high_bound, lvl_name in LEVEL_THRESHOLDS:
                if low_bound <= score <= high_bound:
                    level = lvl_name
                    break

            # Rule: Never output SAFE with confidence below 40; downgrade to LOW or UNKNOWN
            if level == "SAFE":
                if confidence < 40:
                    level = "LOW"
                elif evidence.target_type in ("file", "hash") and (confidence < 60 or vt_total < 40):
                    level = "LOW"

    # Actionable recommendation
    if level == "CRITICAL" or level == "HIGH":
        action = "Do not open or execute this target. Block at perimeter firewalls and isolate any endpoints that accessed it."
        if any("phish" in f.id or "openphish" in f.id for f in factors):
            action = "Phishing threat detected: Do not enter credentials. Revoke active sessions if credentials were submitted."
    elif level == "MEDIUM":
        action = "Exercise caution. Further manual inspection or sandboxing is recommended before interaction."
    elif level == "LOW":
        action = "No major threat indicators were found, but this is not a guarantee of safety. Exercise standard vigilance."
    elif level == "SAFE":
        action = "No significant malicious indicators were found in the available intelligence."
    else:
        action = "Treat this as unverified. Do not execute until independently verified. No reputation data was found. This does NOT mean the target is safe."

    # Explanations
    explanation = _generate_plain_english_explanation(score, level, confidence, factors, group_breakdown)

    return RiskAssessment(
        score=score,
        level=level,
        confidence=confidence,
        factors=factors,
        group_breakdown=group_breakdown,
        raw_evidence_summary={
            "total_sources_evaluated": total_sources,
            "sources": list(source_groups_present),
            "vt_malicious": vt_malicious,
            "vt_total": vt_total,
        },
        explanation=explanation,
        recommended_action=action,
    )


def _generate_plain_english_explanation(
    score: int,
    level: str,
    confidence: int,
    factors: List[Factor],
    breakdown: Dict[str, int],
) -> str:
    """Deterministic plain-English breakdown keyed on factors."""
    if level == "UNKNOWN":
        return (
            "ThreatLens was unable to collect sufficient security telemetry from connected intelligence "
            "providers. The target has no prior reputation history. Lack of detection is not proof of safety."
        )

    parts = []
    if level in ("CRITICAL", "HIGH"):
        parts.append(
            f"ThreatLens scored this target at {score}/100 ({level}) because multiple indicators point to malicious activity."
        )
    elif level == "MEDIUM":
        parts.append(
            f"ThreatLens identified suspicious properties resulting in a {score}/100 ({level}) rating."
        )
    elif level == "LOW":
        parts.append(
            f"ThreatLens evaluated this target with a low risk rating of {score}/100 ({level}). Minor anomalies were observed."
        )
    else:
        parts.append(
            f"ThreatLens evaluated this target as {level} ({score}/100) across verified intelligence sources."
        )

    # Highlight specific key factors
    indicator_titles = [f.title for f in factors if f.type == "indicator"]
    if indicator_titles:
        parts.append(f"Key indicators found: {'; '.join(indicator_titles[:3])}.")

    mitigating_titles = [f.title for f in factors if f.type == "mitigating"]
    if mitigating_titles:
        parts.append(f"Protective factors noted: {'; '.join(mitigating_titles)}.")

    conflict_factors = [f for f in factors if f.type == "conflict"]
    if conflict_factors:
        parts.append(f"Caution: {conflict_factors[0].description}")

    return " ".join(parts)
