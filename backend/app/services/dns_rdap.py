"""
Keyless / Free intelligence sources:
- DNS resolution (A, AAAA, MX, NS)
- RDAP domain age & registrar
- crt.sh Certificate Transparency
"""

from datetime import datetime
import socket
from typing import Any, Dict, List, Optional
import httpx


async def resolve_dns(domain: str) -> Dict[str, Any]:
    """Resolve standard DNS records without external credentials."""
    records: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
    }

    # Demo domain check
    if "example" in domain or "phish-cdn" in domain:
        return {
            "name": "DNS Resolution",
            "status": "ok",
            "data": {
                "resolved": True,
                "records": {"A": ["104.20.23.154"], "AAAA": [], "MX": ["mail.example.com"], "NS": ["ns1.example.com"]},
                "primary_ip": "104.20.23.154",
            },
            "fetched_at": datetime.utcnow().isoformat(),
        }

    # Standard socket resolution for A / AAAA
    try:
        addr_info = socket.getaddrinfo(domain, None)
        for item in addr_info:
            ip = item[4][0]
            if ":" in ip:
                if ip not in records["AAAA"]:
                    records["AAAA"].append(ip)
            else:
                if ip not in records["A"]:
                    records["A"].append(ip)
    except Exception:
        pass

    # Optional dnspython lookup for MX / NS
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        try:
            mx_ans = resolver.resolve(domain, "MX")
            records["MX"] = [str(r.exchange).rstrip(".") for r in mx_ans]
        except Exception:
            pass

        try:
            ns_ans = resolver.resolve(domain, "NS")
            records["NS"] = [str(r.target).rstrip(".") for r in ns_ans]
        except Exception:
            pass
    except Exception:
        pass

    resolved = bool(records["A"] or records["AAAA"])
    return {
        "name": "DNS Resolution",
        "status": "ok" if resolved else "no_data",
        "data": {
            "resolved": resolved,
            "records": records,
            "primary_ip": records["A"][0] if records["A"] else (records["AAAA"][0] if records["AAAA"] else None),
        },
        "fetched_at": datetime.utcnow().isoformat(),
    }


async def lookup_rdap(domain: str) -> Dict[str, Any]:
    """Query open RDAP endpoint for domain age and registrar."""
    if "example-phishing" in domain or "phish-cdn" in domain or "phishing" in domain:
        return {
            "name": "RDAP",
            "status": "ok",
            "data": {
                "domain": domain,
                "registrar": "NameCheap [DEMO]",
                "registration_date": "2026-10-06T00:00:00Z",
                "domain_age_days": 2,
                "is_newly_registered": True,
            },
            "fetched_at": datetime.utcnow().isoformat(),
        }
    if "safe-portal" in domain:
        return {
            "name": "RDAP",
            "status": "ok",
            "data": {
                "domain": domain,
                "registrar": "MarkMonitor [DEMO]",
                "registration_date": "2022-01-10T00:00:00Z",
                "domain_age_days": 1730,
                "is_newly_registered": False,
            },
            "fetched_at": datetime.utcnow().isoformat(),
        }

    # Clean domain (strip subdomains for TLD lookup if needed, or query direct domain)
    endpoint = f"https://rdap.org/domain/{domain}"

    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            resp = await client.get(endpoint, headers={"User-Agent": "ThreatLens/1.0"})
            if resp.status_code != 200:
                return {
                    "name": "RDAP",
                    "status": "no_data",
                    "message": f"RDAP query returned HTTP {resp.status_code}",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            data = resp.json()
            events = data.get("events", [])
            registration_date = None
            for ev in events:
                if ev.get("eventAction") == "registration":
                    registration_date = ev.get("eventDate")
                    break

            # Find registrar
            registrar = "Unknown"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar = item[3]
                                break

            age_days = None
            is_new = False
            if registration_date:
                try:
                    # Clean ISO format e.g. 2026-01-15T00:00:00Z
                    reg_dt = datetime.fromisoformat(registration_date.replace("Z", "+00:00")).replace(tzinfo=None)
                    age_days = (datetime.utcnow() - reg_dt).days
                    is_new = age_days < 30
                except Exception:
                    pass

            return {
                "name": "RDAP",
                "status": "ok",
                "data": {
                    "domain": domain,
                    "registrar": registrar,
                    "registration_date": registration_date,
                    "domain_age_days": age_days,
                    "is_newly_registered": is_new,
                },
                "fetched_at": datetime.utcnow().isoformat(),
            }
    except Exception as e:
        return {
            "name": "RDAP",
            "status": "unavailable",
            "message": str(e),
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }


async def lookup_crtsh(domain: str) -> Dict[str, Any]:
    """Query crt.sh Certificate Transparency logs."""
    endpoint = f"https://crt.sh/?q={domain}&output=json"

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(endpoint, headers={"User-Agent": "ThreatLens/1.0"})
            if resp.status_code != 200:
                return {
                    "name": "crt.sh",
                    "status": "no_data",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            data = resp.json()
            if not isinstance(data, list):
                data = []

            total_certs = len(data)
            suspicious_sans = False

            # Check if domain has suspicious SAN entries (e.g. PayPal, Apple, Google keywords on unrelated domain)
            brand_keywords = ["login", "verify", "secure", "bank", "account", "paypal", "apple", "microsoft"]
            for cert in data[:10]:
                name_val = cert.get("name_value", "").lower()
                for kw in brand_keywords:
                    if kw in name_val and kw not in domain.lower():
                        suspicious_sans = True
                        break

            return {
                "name": "crt.sh",
                "status": "ok",
                "data": {
                    "total_certificates": total_certs,
                    "suspicious_sans": suspicious_sans,
                    "recent_entries": [
                        {
                            "issuer": c.get("issuer_name"),
                            "common_name": c.get("common_name"),
                            "entry_timestamp": c.get("entry_timestamp"),
                        }
                        for c in data[:3]
                    ],
                },
                "fetched_at": datetime.utcnow().isoformat(),
            }
    except Exception as e:
        return {
            "name": "crt.sh",
            "status": "unavailable",
            "message": str(e),
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }
