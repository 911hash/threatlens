"""
Email Authentication Forensics Service.

Parses RFC 8601 Authentication-Results headers and associated security fields
(Received-SPF, DKIM-Signature, ARC-Authentication-Results) to validate:
- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication, Reporting, and Conformance)
- ARC (Authenticated Received Chain)

Key behaviors:
- Missing headers produce 'none', NEVER 'fail'.
- Extracts domain alignment info (SPF domain vs From domain, DKIM d= vs From domain).
- Extracts DMARC policies (reject / quarantine / none).
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from ..schemas import EmailAuthResult


def _extract_domain(email_or_domain: Optional[str]) -> Optional[str]:
    """Extract clean domain name from email address or domain string."""
    if not email_or_domain:
        return None
    val = email_or_domain.strip().lower()
    if "@" in val:
        val = val.split("@")[-1]
    # Strip brackets, quotes, or trailing punctuation
    val = re.sub(r"[<>\"\';\(\)]", "", val).strip()
    # Strip leading @
    if val.startswith("@"):
        val = val[1:]
    return val if "." in val else (val or None)


def _check_domain_alignment(domain_a: Optional[str], domain_b: Optional[str]) -> Optional[bool]:
    """
    Check if two domains align (exact match or subdomain match under relaxed DMARC alignment).
    """
    if not domain_a or not domain_b:
        return None
    d1 = domain_a.lower().strip()
    d2 = domain_b.lower().strip()
    if d1 == d2:
        return True
    if d1.endswith("." + d2) or d2.endswith("." + d1):
        return True
    return False


def _normalize_auth_verdict(raw_val: Optional[str]) -> str:
    """Normalize raw authentication verdict to pass, fail, neutral, or none."""
    if not raw_val:
        return "none"
    v = raw_val.lower().strip()
    if v == "pass":
        return "pass"
    if v in ("fail", "softfail", "hardfail", "permerror", "temperror"):
        return "fail"
    if v in ("neutral", "policy"):
        return "neutral"
    if v == "none":
        return "none"
    return "none"


def parse_authentication_results(
    headers: Dict[str, Any],
    from_address: Optional[str] = None,
) -> EmailAuthResult:
    """
    Parse email headers for authentication results.
    Handles multiple headers, casing variations, and missing records.
    """
    # Collect all header candidates
    auth_headers: List[str] = []
    received_spf_headers: List[str] = []
    dkim_signatures: List[str] = []
    arc_headers: List[str] = []

    for key, val in headers.items():
        k_lower = key.lower()
        vals = val if isinstance(val, list) else [val]
        for v in vals:
            if not isinstance(v, str):
                continue
            if k_lower == "authentication-results":
                auth_headers.append(v)
            elif k_lower == "received-spf":
                received_spf_headers.append(v)
            elif k_lower == "dkim-signature":
                dkim_signatures.append(v)
            elif "arc-authentication-results" in k_lower:
                arc_headers.append(v)

    combined_auth = " ; ".join(auth_headers)
    combined_arc = " ; ".join(arc_headers)
    from_domain = _extract_domain(from_address)

    # 1. SPF Evaluation
    spf_verdict = "none"
    spf_domain = None

    # Search Authentication-Results for spf=
    spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z0-9_\-]+)", combined_auth, re.IGNORECASE)
    if spf_match:
        spf_verdict = _normalize_auth_verdict(spf_match.group(1))

    # Fallback to Received-SPF if not found in Authentication-Results
    if spf_verdict == "none" and received_spf_headers:
        for rspf in received_spf_headers:
            rspf_lower = rspf.lower().strip()
            if rspf_lower.startswith("pass"):
                spf_verdict = "pass"
                break
            elif rspf_lower.startswith("fail") or rspf_lower.startswith("softfail"):
                spf_verdict = "fail"
                break
            elif rspf_lower.startswith("neutral"):
                spf_verdict = "neutral"
                break

    # Extract SPF domain
    spf_dom_match = re.search(r"smtp\.mailfrom\s*=\s*([^\s;()]+)", combined_auth, re.IGNORECASE)
    if not spf_dom_match:
        spf_dom_match = re.search(r"envelope-from\s*=\s*([^\s;()]+)", combined_auth, re.IGNORECASE)
    if not spf_dom_match and received_spf_headers:
        spf_dom_match = re.search(r"domain of\s+([^\s;()]+)", " ".join(received_spf_headers), re.IGNORECASE)

    if spf_dom_match:
        spf_domain = _extract_domain(spf_dom_match.group(1))

    # 2. DKIM Evaluation
    dkim_verdict = "none"
    dkim_domain = None

    dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z0-9_\-]+)", combined_auth, re.IGNORECASE)
    if dkim_match:
        dkim_verdict = _normalize_auth_verdict(dkim_match.group(1))

    # Extract DKIM domain
    dkim_dom_match = re.search(r"header\.[id]\s*=\s*@?([^\s;()]+)", combined_auth, re.IGNORECASE)
    if not dkim_dom_match and dkim_signatures:
        for dsig in dkim_signatures:
            d_match = re.search(r"\bd\s*=\s*([^;\s]+)", dsig, re.IGNORECASE)
            if d_match:
                dkim_domain = _extract_domain(d_match.group(1))
                break
    elif dkim_dom_match:
        dkim_domain = _extract_domain(dkim_dom_match.group(1))

    # 3. DMARC Evaluation
    dmarc_verdict = "none"
    dmarc_policy = None

    dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z0-9_\-]+)", combined_auth, re.IGNORECASE)
    if dmarc_match:
        dmarc_verdict = _normalize_auth_verdict(dmarc_match.group(1))

    policy_match = re.search(r"\b(?:p|action|policy)\s*=\s*([a-zA-Z0-9_\-]+)", combined_auth, re.IGNORECASE)
    if policy_match:
        dmarc_policy = policy_match.group(1).lower()

    # 4. ARC Evaluation
    arc_verdict = "none"
    arc_text = combined_auth + " ; " + combined_arc
    arc_match = re.search(r"\barc\s*=\s*([a-zA-Z0-9_\-]+)", arc_text, re.IGNORECASE)
    if arc_match:
        arc_verdict = _normalize_auth_verdict(arc_match.group(1))

    # 5. Domain Alignment Analysis
    spf_aligned = None
    if spf_domain and from_domain:
        spf_aligned = _check_domain_alignment(spf_domain, from_domain)

    dkim_aligned = None
    if dkim_domain and from_domain:
        dkim_aligned = _check_domain_alignment(dkim_domain, from_domain)

    # Detailed debug context
    details = {
        "raw_authentication_results": auth_headers[:3],
        "spf_raw": spf_match.group(0) if spf_match else None,
        "dkim_raw": dkim_match.group(0) if dkim_match else None,
        "dmarc_raw": dmarc_match.group(0) if dmarc_match else None,
        "arc_raw": arc_match.group(0) if arc_match else None,
        "from_domain": from_domain,
        "spf_domain": spf_domain,
        "dkim_domain": dkim_domain,
        "spf_alignment_pass": spf_aligned,
        "dkim_alignment_pass": dkim_aligned,
        "dmarc_policy": dmarc_policy,
    }

    return EmailAuthResult(
        spf=spf_verdict,
        dkim=dkim_verdict,
        dmarc=dmarc_verdict,
        arc=arc_verdict,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        from_domain=from_domain,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        dmarc_policy=dmarc_policy,
        details=details,
    )
