"""
Email Header Forensics and Anomaly Detection Service.

Performs deep structural inspection of email headers:
- Received chain analysis: hop counts, transit delays, timing gaps, reverse relay ordering.
- Sender vs. Reply-To mismatch detection (prominent phishing / spoofing indicator).
- Extraction and sanitization of diagnostic X-headers (X-Spam-Status, X-Mailer, X-Originating-IP).
- Security hardening: Escapes ALL header keys and values using HTML entity encoding to
  prevent header injection and stored XSS vectors.
"""

import email.utils
import html
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..schemas import EmailHeaderAnalysis, EmailHeaderHop


def escape_header_val(val: Any) -> Any:
    """Recursively escape strings for safe HTML rendering."""
    if isinstance(val, str):
        return html.escape(val, quote=True)
    elif isinstance(val, list):
        return [escape_header_val(x) for x in val]
    elif isinstance(val, dict):
        return {escape_header_val(k): escape_header_val(v) for k, v in val.items()}
    return val


def escape_headers_dict(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Return a dictionary where all keys and string values are HTML escaped."""
    escaped: Dict[str, Any] = {}
    for k, v in headers.items():
        escaped_k = html.escape(str(k), quote=True)
        escaped[escaped_k] = escape_header_val(v)
    return escaped


def _extract_email_address(raw_addr: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract pure address (e.g. user@domain.com) and domain (domain.com) from a raw header string.
    """
    if not raw_addr:
        return None, None

    # Use email.utils.parseaddr
    _, addr = email.utils.parseaddr(raw_addr)
    addr = addr.strip().lower()
    if not addr and "@" in raw_addr:
        # Fallback regex
        m = re.search(r"[\w\.-]+@[\w\.-]+", raw_addr)
        if m:
            addr = m.group(0).lower()

    if "@" in addr:
        domain = addr.split("@")[-1].strip()
        return addr, domain
    return (addr or None), None


def _extract_ip_from_text(text: str) -> Optional[str]:
    """Find first IPv4 or IPv6 address in string."""
    # Look for [x.x.x.x] or (x.x.x.x) or standalone
    ipv4_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    if ipv4_match:
        ip = ipv4_match.group(0)
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass

    ipv6_match = re.search(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", text)
    if ipv6_match:
        ip = ipv6_match.group(0)
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass

    return None


def extract_sender_ips(
    raw_received_lines: List[str],
    headers: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Extract sender IPs ordered by hop (closest relay first) and deduplicated.
    - X-Originating-IP represents the client author and is ordered first (hop 0 / origin).
    - Received headers are ordered bottom-to-top (RFC 5322 reverse order), so Hop 1 is the first relay closest to sender.
    """
    ordered_ips: List[str] = []

    # 1. X-Originating-IP takes precedence as the direct client author
    if headers:
        for k, v in headers.items():
            if str(k).lower().strip() == "x-originating-ip":
                val = v[0] if isinstance(v, list) else str(v)
                ip = _extract_ip_from_text(str(val))
                if ip and ip not in ordered_ips:
                    ordered_ips.append(ip)

    # 2. Iterate Received headers in reverse (Hop 1 is closest relay to sender)
    for line in reversed(raw_received_lines):
        ip = _extract_ip_from_text(line)
        if ip and ip not in ordered_ips:
            ordered_ips.append(ip)

    return ordered_ips


def analyze_headers(
    headers: Dict[str, Any],
    raw_received_lines: List[str],
    from_header: Optional[str] = None,
    reply_to_header: Optional[str] = None,
) -> EmailHeaderAnalysis:
    """
    Perform forensic analysis on email headers and Received hop chain.
    """
    anomalies: List[str] = []
    timing_gaps: List[str] = []
    unexpected_relays: List[str] = []
    hops: List[EmailHeaderHop] = []

    # 1. Sender / Reply-To Mismatch Detection
    from_addr, from_domain = _extract_email_address(from_header)
    reply_addr, reply_domain = _extract_email_address(reply_to_header)

    sender_reply_to_mismatch = False
    mismatch_details = None

    if reply_addr and from_addr:
        # Normalize comparison
        if from_domain and reply_domain:
            f_dom = from_domain.lower()
            r_dom = reply_domain.lower()
            # Mismatch if domains are different and not subdomains of one another
            if f_dom != r_dom and not (f_dom.endswith("." + r_dom) or r_dom.endswith("." + f_dom)):
                sender_reply_to_mismatch = True
                mismatch_details = (
                    f"Sender domain '{from_domain}' differs from Reply-To destination '{reply_domain}'."
                )
                anomalies.append(
                    f"Sender/Reply-To domain mismatch: Replies directed to '{reply_addr}' instead of sender domain."
                )
        elif reply_addr != from_addr:
            sender_reply_to_mismatch = True
            mismatch_details = f"Reply-To address '{reply_addr}' differs from From address '{from_addr}'."
            anomalies.append(mismatch_details)

    # 2. X-Header Extraction
    x_spam_status = None
    x_mailer = None
    x_originating_ip = None

    for k, v in headers.items():
        k_lower = k.lower().strip()
        val_str = v[0] if isinstance(v, list) else str(v)
        if k_lower == "x-spam-status":
            x_spam_status = escape_header_val(val_str)
            if re.search(r"\byes\b", val_str, re.IGNORECASE):
                anomalies.append(f"Header indicates spam flag: X-Spam-Status = {escape_header_val(val_str)}")
        elif k_lower == "x-mailer":
            x_mailer = escape_header_val(val_str)
        elif k_lower == "x-originating-ip":
            # Extract IP from [ip] or string
            ip_found = _extract_ip_from_text(val_str)
            x_originating_ip = escape_header_val(ip_found or val_str)

    # 3. Received Chain Processing
    # RFC 5322: Received headers are prepended by each MTA.
    # The bottom-most Received header is the first hop (closest to sender).
    # The top-most Received header is the final hop (recipient's inbound gateway).
    hop_count = len(raw_received_lines)

    if hop_count == 0:
        anomalies.append("Missing Received headers: No mail transmission path recorded.")
    elif hop_count > 10:
        anomalies.append(f"Excessive hop count ({hop_count} relays): Possible routing loop or proxying.")

    parsed_hops: List[Dict[str, Any]] = []

    for idx, line in enumerate(reversed(raw_received_lines)):
        hop_num = idx + 1
        # Extract from / by
        from_m = re.search(r"\bfrom\s+([^\s;]+(?:\s+\([^)]*\))?)", line, re.IGNORECASE)
        by_m = re.search(r"\bby\s+([^\s;]+)", line, re.IGNORECASE)
        ip = _extract_ip_from_text(line)

        # Extract timestamp: usually after the last semicolon
        timestamp_dt = None
        timestamp_str = None
        if ";" in line:
            date_candidate = line.rsplit(";", 1)[-1].strip()
            try:
                timestamp_dt = email.utils.parsedate_to_datetime(date_candidate)
                timestamp_str = timestamp_dt.isoformat()
            except Exception:
                timestamp_str = date_candidate

        from_host = from_m.group(1).strip() if from_m else None
        by_host = by_m.group(1).strip() if by_m else None

        # Check for unexpected relays
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                # If an intermediate hop claims to be a public delivery MTA from a private IP
                if ip_obj.is_private and hop_num > 1 and hop_num < hop_count:
                    unexpected_relays.append(f"Internal private IP {ip} in intermediate relay hop {hop_num}.")
            except ValueError:
                pass

        parsed_hops.append({
            "hop_num": hop_num,
            "from_host": escape_header_val(from_host),
            "by_host": escape_header_val(by_host),
            "ip": ip,
            "timestamp_dt": timestamp_dt,
            "timestamp_str": escape_header_val(timestamp_str),
        })

    # 4. Timing Gap & Anomaly Inspection
    has_timing_anomaly = False

    for i in range(len(parsed_hops)):
        cur = parsed_hops[i]
        delay_seconds = None

        if i > 0:
            prev = parsed_hops[i - 1]
            if cur["timestamp_dt"] and prev["timestamp_dt"]:
                # Ensure timezone awareness compatibility
                dt_cur = cur["timestamp_dt"]
                dt_prev = prev["timestamp_dt"]
                if dt_cur.tzinfo is None:
                    dt_cur = dt_cur.replace(tzinfo=timezone.utc)
                if dt_prev.tzinfo is None:
                    dt_prev = dt_prev.replace(tzinfo=timezone.utc)

                diff = (dt_cur - dt_prev).total_seconds()
                delay_seconds = int(diff)

                # Anomaly: Negative delay > 60s (clock inversion)
                if diff < -60:
                    gap_msg = (
                        f"Clock skew anomaly: Hop {cur['hop_num']} timestamp is {abs(int(diff))}s "
                        f"earlier than Hop {prev['hop_num']}."
                    )
                    timing_gaps.append(gap_msg)
                    anomalies.append(gap_msg)
                    has_timing_anomaly = True
                # Anomaly: Hop delay > 3600s (1 hour)
                elif diff > 3600:
                    gap_msg = (
                        f"Unusually long delay of {int(diff // 60)} minutes between Hop {prev['hop_num']} "
                        f"and Hop {cur['hop_num']}."
                    )
                    timing_gaps.append(gap_msg)
                    anomalies.append(gap_msg)
                    has_timing_anomaly = True

        hops.append(
            EmailHeaderHop(
                hop_index=cur["hop_num"],
                from_host=cur["from_host"],
                by_host=cur["by_host"],
                ip=cur["ip"],
                timestamp=cur["timestamp_str"],
                delay_seconds=delay_seconds,
            )
        )

    return EmailHeaderAnalysis(
        hop_count=hop_count,
        hops=hops,
        timing_gaps=timing_gaps,
        unexpected_relays=unexpected_relays,
        has_timing_anomaly=has_timing_anomaly,
        sender_reply_to_mismatch=sender_reply_to_mismatch,
        mismatch_details=escape_header_val(mismatch_details) if mismatch_details else None,
        x_spam_status=x_spam_status,
        x_mailer=x_mailer,
        x_originating_ip=x_originating_ip,
        sender_ips=extract_sender_ips(raw_received_lines, headers),
        anomalies=anomalies,
    )
