"""
Threat intelligence feed integrations:
- OpenPhish community feed (locally cached, periodic refresh)
- Abuse.ch URLhaus API (keyed / free auth key)
"""

from datetime import datetime, timedelta
import os
from typing import Any, Dict, Optional, Set
import httpx

ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")

# OpenPhish cache
_OPENPHISH_CACHE: Set[str] = set()
_OPENPHISH_LAST_FETCH: Optional[datetime] = None
OPENPHISH_CACHE_TTL = timedelta(hours=4)


async def _refresh_openphish_feed_if_needed():
    global _OPENPHISH_CACHE, _OPENPHISH_LAST_FETCH
    now = datetime.utcnow()
    if _OPENPHISH_LAST_FETCH and (now - _OPENPHISH_LAST_FETCH < OPENPHISH_CACHE_TTL):
        return

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get("https://openphish.com/feed.txt", headers={"User-Agent": "ThreatLens/1.0"})
            if resp.status_code == 200:
                urls = {line.strip().lower() for line in resp.text.splitlines() if line.strip()}
                _OPENPHISH_CACHE = urls
                _OPENPHISH_LAST_FETCH = now
    except Exception:
        # Keep stale cache if available
        pass


async def lookup_openphish(url: str) -> Dict[str, Any]:
    """Check OpenPhish community feed."""
    await _refresh_openphish_feed_if_needed()
    normalized = url.strip().lower()
    flagged = normalized in _OPENPHISH_CACHE

    return {
        "name": "OpenPhish",
        "status": "ok",
        "data": {
            "flagged": flagged,
            "feed_size": len(_OPENPHISH_CACHE),
            "last_refreshed": _OPENPHISH_LAST_FETCH.isoformat() if _OPENPHISH_LAST_FETCH else None,
        },
        "fetched_at": datetime.utcnow().isoformat(),
    }


async def lookup_urlhaus(url: str) -> Dict[str, Any]:
    """Query abuse.ch URLhaus API."""
    auth_key = os.getenv("ABUSECH_AUTH_KEY", "")
    if not auth_key:
        return {
            "name": "URLhaus",
            "status": "unavailable",
            "message": "abuse.ch Auth-Key not configured.",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key": auth_key, "User-Agent": "ThreatLens/1.0"}
    data = {"url": url}

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(endpoint, data=data, headers=headers)
            if resp.status_code != 200:
                return {
                    "name": "URLhaus",
                    "status": "error",
                    "message": f"URLhaus returned HTTP {resp.status_code}",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            result = resp.json()
            query_status = result.get("query_status")

            if query_status == "ok":
                return {
                    "name": "URLhaus",
                    "status": "ok",
                    "data": {
                        "flagged": True,
                        "threat": result.get("threat", "Malware"),
                        "url_status": result.get("url_status"),
                        "tags": result.get("tags", []),
                    },
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            elif query_status == "no_results":
                return {
                    "name": "URLhaus",
                    "status": "ok",
                    "data": {
                        "flagged": False,
                        "threat": None,
                        "url_status": "clean",
                    },
                    "fetched_at": datetime.utcnow().isoformat(),
                }
            else:
                return {
                    "name": "URLhaus",
                    "status": "error",
                    "message": f"URLhaus status: {query_status}",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }
    except Exception as e:
        return {
            "name": "URLhaus",
            "status": "error",
            "message": str(e),
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }
