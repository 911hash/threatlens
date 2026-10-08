"""
Google Safe Browsing v4 client.
Graceful degradation when API key is missing.
"""

import os
from datetime import datetime
from typing import Any, Dict
import httpx


async def lookup_safe_browsing(url: str) -> Dict[str, Any]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return {
            "name": "Google Safe Browsing",
            "status": "unavailable",
            "message": "Google Safe Browsing API key not configured.",
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "threatlens",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code != 200:
                return {
                    "name": "Google Safe Browsing",
                    "status": "error",
                    "message": f"HTTP {resp.status_code} from Safe Browsing API",
                    "data": None,
                    "fetched_at": datetime.utcnow().isoformat(),
                }

            data = resp.json()
            matches = data.get("matches", [])
            flagged = len(matches) > 0
            threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})

            return {
                "name": "Google Safe Browsing",
                "status": "ok",
                "data": {
                    "flagged": flagged,
                    "threat_types": threat_types,
                    "matches_count": len(matches),
                },
                "fetched_at": datetime.utcnow().isoformat(),
            }
    except Exception as e:
        return {
            "name": "Google Safe Browsing",
            "status": "error",
            "message": str(e),
            "data": None,
            "fetched_at": datetime.utcnow().isoformat(),
        }
