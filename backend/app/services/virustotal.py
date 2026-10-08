"""
VirusTotal API v3 integration with token-bucket rate limiting and 10-minute caching.
Strict privacy adherence: No default submission or file uploads.
"""

import base64
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import httpx

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALLOW_VT_URL_SUBMISSION = os.getenv("ALLOW_VT_URL_SUBMISSION", "false").lower() == "true"
ALLOW_FILE_UPLOAD_TO_VT = os.getenv("ALLOW_FILE_UPLOAD_TO_VT", "false").lower() == "true"

# Cache structure: target -> {data, timestamp}
_VT_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = timedelta(minutes=10)

# Token bucket rate limiter: 4 requests per 60 seconds
_RATE_LIMIT_TOKENS = 4
_RATE_LIMIT_WINDOW = 60.0
_LAST_TOKENS_REFRESH = time.monotonic()
_AVAILABLE_TOKENS = float(_RATE_LIMIT_TOKENS)


def _consume_token() -> bool:
    global _LAST_TOKENS_REFRESH, _AVAILABLE_TOKENS
    now = time.monotonic()
    elapsed = now - _LAST_TOKENS_REFRESH
    _LAST_TOKENS_REFRESH = now
    _AVAILABLE_TOKENS = min(float(_RATE_LIMIT_TOKENS), _AVAILABLE_TOKENS + elapsed * (_RATE_LIMIT_TOKENS / _RATE_LIMIT_WINDOW))

    if _AVAILABLE_TOKENS >= 1.0:
        _AVAILABLE_TOKENS -= 1.0
        return True
    return False


def get_cached_vt_result(target: str) -> Optional[Dict[str, Any]]:
    cached = _VT_CACHE.get(target)
    if cached:
        if datetime.utcnow() - cached["timestamp"] < CACHE_TTL:
            return cached["data"]
    return None


def store_cached_vt_result(target: str, data: Dict[str, Any]):
    _VT_CACHE[target] = {
        "timestamp": datetime.utcnow(),
        "data": data,
    }


def url_to_vt_id(url: str) -> str:
    """Encode URL to VirusTotal v3 URL identifier (base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def lookup_virustotal_url(url: str) -> Dict[str, Any]:
    """
    Lookup URL analysis in VirusTotal.
    Returns normalized SourceResult.
    """
    cached = get_cached_vt_result(url)
    if cached:
        return {
            "name": "VirusTotal",
            "status": "ok",
            "data": cached,
            "cached": True,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {
            "name": "VirusTotal",
            "status": "unavailable",
            "message": "VirusTotal API key not configured.",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    if not _consume_token():
        # Check if we have stale cache to return
        stale = _VT_CACHE.get(url)
        return {
            "name": "VirusTotal",
            "status": "rate_limited",
            "message": "Rate limited. Showing last known result.",
            "data": stale["data"] if stale else None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    url_id = url_to_vt_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {"x-apikey": api_key, "User-Agent": "ThreatLens/1.0"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(endpoint, headers=headers)
            if resp.status_code == 404:
                # Target not yet scanned in VT
                return {
                    "name": "VirusTotal",
                    "status": "no_data",
                    "message": "Target not found in VirusTotal database.",
                    "data": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0},
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            elif resp.status_code == 429:
                stale = _VT_CACHE.get(url)
                return {
                    "name": "VirusTotal",
                    "status": "rate_limited",
                    "message": "Rate limited by VirusTotal API. Showing last known result.",
                    "data": stale["data"] if stale else None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            elif resp.status_code != 200:
                return {
                    "name": "VirusTotal",
                    "status": "error",
                    "message": f"VirusTotal returned HTTP {resp.status_code}",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            body = resp.json()
            attributes = body.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            # Extract categories
            categories = list(attributes.get("categories", {}).values())

            parsed_data = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,
                "reputation": attributes.get("reputation", 0),
                "categories": categories,
                "first_submission_date": attributes.get("first_submission_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "vendors_sample": [
                    {"engine": k, "category": v.get("category"), "result": v.get("result")}
                    for k, v in list(results.items())[:10]
                ],
            }
            store_cached_vt_result(url, parsed_data)

            return {
                "name": "VirusTotal",
                "status": "ok",
                "data": parsed_data,
                "cached": False,
                "fetched_at": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        return {
            "name": "VirusTotal",
            "status": "error",
            "message": f"Connection error: {str(e)}",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }


async def lookup_virustotal_hash(file_hash: str) -> Dict[str, Any]:
    """
    Lookup hash analysis in VirusTotal (MD5, SHA-1, SHA-256).
    """
    cached = get_cached_vt_result(file_hash)
    if cached:
        return {
            "name": "VirusTotal",
            "status": "ok",
            "data": cached,
            "cached": True,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {
            "name": "VirusTotal",
            "status": "unavailable",
            "message": "VirusTotal API key not configured.",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    if not _consume_token():
        stale = _VT_CACHE.get(file_hash)
        return {
            "name": "VirusTotal",
            "status": "rate_limited",
            "message": "Rate limited. Showing last known result.",
            "data": stale["data"] if stale else None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key, "User-Agent": "ThreatLens/1.0"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(endpoint, headers=headers)
            if resp.status_code == 404:
                return {
                    "name": "VirusTotal",
                    "status": "no_data",
                    "message": "File hash not found in VirusTotal database.",
                    "data": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0},
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            elif resp.status_code == 429:
                stale = _VT_CACHE.get(file_hash)
                return {
                    "name": "VirusTotal",
                    "status": "rate_limited",
                    "message": "Rate limited by VirusTotal API.",
                    "data": stale["data"] if stale else None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            elif resp.status_code != 200:
                return {
                    "name": "VirusTotal",
                    "status": "error",
                    "message": f"VirusTotal returned HTTP {resp.status_code}",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            body = resp.json()
            attributes = body.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            sig_info = attributes.get("signature_info", {})

            parsed_data = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,
                "reputation": attributes.get("reputation", 0),
                "meaningful_name": attributes.get("meaningful_name"),
                "type_description": attributes.get("type_description"),
                "size": attributes.get("size"),
                "is_signed": bool(sig_info),
                "signature_verified": sig_info.get("verified", False),
                "publisher": sig_info.get("product") or sig_info.get("copyright"),
            }
            store_cached_vt_result(file_hash, parsed_data)

            return {
                "name": "VirusTotal",
                "status": "ok",
                "data": parsed_data,
                "cached": False,
                "fetched_at": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        return {
            "name": "VirusTotal",
            "status": "error",
            "message": f"Connection error: {str(e)}",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }
