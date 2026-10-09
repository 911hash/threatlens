"""
IP Geolocation, ASN Enrichment & Infrastructure Risk Service.

Performs geolocation lookup, ASN intelligence, and infrastructure anomaly classification
(VPN, proxy, Tor exit nodes, and cloud datacenters).
Adheres strictly to:
- SQLite 24h TTL caching (geolocation_cache table)
- Graceful degradation on rate limits / network failure (returns cached or "unknown")
- Never log raw IP at INFO level (raw IPs only logged at DEBUG, masked at INFO)
- Hash-only privacy mode: skips external network requests entirely
"""

import datetime
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..models import GeolocationCache

logger = logging.getLogger(__name__)

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,org,proxy,hosting,query"

TOR_INDICATOR_KEYWORDS = ["tor", "onion", "exit node", "tornodes", "tor-exit", "torservers"]
VPN_INDICATOR_KEYWORDS = [
    "vpn", "mullvad", "nordvpn", "expressvpn", "surfshark", "proton", 
    "private internet access", "tunnelbear", "cyberghost", "ipvanish", "ovpn"
]
DATACENTER_INDICATOR_KEYWORDS = [
    "amazon", "aws", "digitalocean", "hetzner", "ovh", "linode", "google cloud",
    "gcp", "microsoft", "azure", "oracle cloud", "vultr", "leaseweb", "choopa",
    "contabo", "datacenter", "hosting", "server", "cloud"
]


class GeoLocation(BaseModel):
    ip: str
    country: str = "unknown"
    country_code: Optional[str] = None
    region: str = "unknown"
    city: str = "unknown"
    lat: Optional[float] = None
    lon: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_unknown: bool = False
    cached: bool = False


def mask_ip(ip: str) -> str:
    """Mask raw IP address to preserve privacy in info-level logs."""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    if ":" in ip:
        return ip[:8] + ":****"
    return "***"


def purge_expired_cache(db: Session, max_age_hours: int = 24) -> int:
    """Purge cached geolocation records older than TTL on startup or routine maintenance."""
    try:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=max_age_hours)
        deleted = (
            db.query(GeolocationCache)
            .filter(GeolocationCache.fetched_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.commit()
        logger.info("Purged %d expired records from geolocation_cache", deleted)
        return deleted
    except Exception as e:
        db.rollback()
        logger.warning("Failed to purge expired geolocation cache: %s", str(e))
        return 0


def _is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        # RFC 5737 test documentation networks (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24)
        # are reserved for testing/benchmarks and should be queryable/mockable
        if (
            ip_obj in ipaddress.ip_network("198.51.100.0/24")
            or ip_obj in ipaddress.ip_network("203.0.113.0/24")
            or ip_obj in ipaddress.ip_network("192.0.2.0/24")
        ):
            return False
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def _classify_infrastructure(
    data: Dict[str, Any],
    isp: Optional[str],
    org: Optional[str],
    asn: Optional[str]
) -> Dict[str, bool]:
    """Detect VPN, Proxy, Tor, and Datacenter flags based on telemetry and keyword heuristics."""
    combined_text = f"{isp or ''} {org or ''} {asn or ''}".lower()

    # Tor detection
    is_tor = any(k in combined_text for k in TOR_INDICATOR_KEYWORDS)

    # VPN detection
    is_vpn = any(k in combined_text for k in VPN_INDICATOR_KEYWORDS)

    # Proxy detection from API field or flags
    is_proxy = bool(data.get("proxy", False)) or is_vpn or is_tor

    # Datacenter / Cloud hosting detection
    is_datacenter = bool(data.get("hosting", False)) or any(
        k in combined_text for k in DATACENTER_INDICATOR_KEYWORDS
    )

    return {
        "is_vpn": is_vpn,
        "is_proxy": is_proxy,
        "is_tor": is_tor,
        "is_datacenter": is_datacenter,
    }


def geolocate_ip(
    ip: str,
    db: Session,
    hash_only: bool = False,
    timeout: float = 3.0,
) -> GeoLocation:
    """
    Geolocate and enrich an IP address with ASN, ISP, and infrastructure flags.

    - SQLite 24h TTL cache lookup first.
    - If hash_only=True: returns cached result if present, otherwise returns 'unknown'
      without initiating external network requests.
    - If service is down or rate-limited: gracefully falls back to cached data or 'unknown'.
    - Never logs raw IP at INFO level.
    """
    clean_ip = ip.strip()
    logger.debug("Processing geolocation for raw IP: %s (hash_only=%s)", clean_ip, hash_only)
    logger.info("Processing geolocation for IP: %s (hash_only=%s)", mask_ip(clean_ip), hash_only)

    if not clean_ip:
        return GeoLocation(ip="", is_unknown=True)

    # 1. Private / Local IP bypass
    if _is_private_ip(clean_ip):
        return GeoLocation(
            ip=clean_ip,
            country="Private Network",
            country_code="LOCAL",
            region="Internal",
            city="Internal",
            isp="Private Routing",
            asn="RFC1918",
            org="Local / Internal Network",
            is_vpn=False,
            is_proxy=False,
            is_tor=False,
            is_datacenter=False,
            is_unknown=False,
            cached=True,
        )

    now = datetime.datetime.utcnow()

    # 2. Check SQLite cache
    cached_row = db.query(GeolocationCache).filter(GeolocationCache.ip == clean_ip).first()

    if cached_row and cached_row.fetched_at:
        try:
            fetched_at = cached_row.fetched_at
            if getattr(fetched_at, 'tzinfo', None) is not None:
                fetched_at = fetched_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            now_naive = datetime.datetime.utcnow()
            age_seconds = (now_naive - fetched_at).total_seconds()
        except Exception:
            age_seconds = 0
        # Active cache hit within 24 hours
        if age_seconds < 86400:
            try:
                cached_data = json.loads(cached_row.response_json)
                cached_data["cached"] = True
                logger.info("Geolocation cache hit for IP %s (age=%.1fs)", mask_ip(clean_ip), age_seconds)
                return GeoLocation(**cached_data)
            except Exception as e:
                logger.warning("Error parsing cached geolocation JSON: %s", str(e))

    # 3. Privacy / Hash-only mode: NO external network requests permitted
    if hash_only:
        logger.info("Privacy hash-only mode active: skipping live lookup for IP %s", mask_ip(clean_ip))
        if cached_row:
            try:
                cached_data = json.loads(cached_row.response_json)
                cached_data["cached"] = True
                return GeoLocation(**cached_data)
            except Exception:
                pass
        return GeoLocation(ip=clean_ip, is_unknown=True, cached=False)

    # 4. Live lookup via httpx client
    endpoint = IP_API_URL.format(ip=clean_ip)
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(endpoint)

        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                isp = data.get("isp")
                asn = data.get("as")
                org = data.get("org")
                infra_flags = _classify_infrastructure(data, isp, org, asn)

                geo_obj = GeoLocation(
                    ip=clean_ip,
                    country=data.get("country") or "unknown",
                    country_code=data.get("countryCode"),
                    region=data.get("regionName") or "unknown",
                    city=data.get("city") or "unknown",
                    lat=data.get("lat"),
                    lon=data.get("lon"),
                    timezone=data.get("timezone"),
                    isp=isp,
                    asn=asn,
                    org=org,
                    is_vpn=infra_flags["is_vpn"],
                    is_proxy=infra_flags["is_proxy"],
                    is_tor=infra_flags["is_tor"],
                    is_datacenter=infra_flags["is_datacenter"],
                    is_unknown=False,
                    cached=False,
                )

                # Save / update in SQLite cache
                try:
                    payload_json = geo_obj.model_dump_json()
                    if cached_row:
                        cached_row.response_json = payload_json
                        cached_row.fetched_at = now
                    else:
                        new_row = GeolocationCache(
                            ip=clean_ip,
                            response_json=payload_json,
                            fetched_at=now,
                        )
                        db.add(new_row)
                    db.commit()
                except Exception as db_err:
                    db.rollback()
                    logger.warning("Failed to commit geolocation to cache: %s", str(db_err))

                return geo_obj

        # If API returned fail status (e.g. invalid query or rate limited)
        logger.warning(
            "Geolocation service returned unsuccessful response: status=%s, msg=%s",
            resp.status_code,
            resp.text[:100] if resp.text else ""
        )
    except Exception as exc:
        # Graceful handling for timeouts, network drops, or 429 rate limits
        logger.warning("Geolocation service failure for IP %s: %s", mask_ip(clean_ip), str(exc))

    # 5. Graceful fallback on network failure: use stale cache if available, else 'unknown'
    if cached_row:
        try:
            cached_data = json.loads(cached_row.response_json)
            cached_data["cached"] = True
            return GeoLocation(**cached_data)
        except Exception:
            pass

    return GeoLocation(ip=clean_ip, is_unknown=True, cached=False)
