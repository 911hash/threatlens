"""
End-to-end verification of cache hits during email analysis.
Calls the email analysis route twice and monitors external HTTP requests to demonstrate
that the 2nd load makes 0 external lookups and returns cached=True.
"""

import sys
import os
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Add backend directory to sys.path
sys.path.insert(0, "/home/ankitdey/Documents/hackathon/threatlens/backend")

from app.main import app
from app.database import SessionLocal
from app.models import GeolocationCache

def run():
    client = TestClient(app)
    db = SessionLocal()

    test_ip = "185.220.101.99"
    # Clean cache for this test IP
    db.query(GeolocationCache).filter(GeolocationCache.ip == test_ip).delete()
    db.commit()

    raw_eml = f"""Received: from relay.torproject.org ([{test_ip}]) by mx.google.com with ESMTP id 12345; Fri, 09 Oct 2026 10:00:00 +0000
From: test@spoofed-service.com
To: victim@company.com
Subject: Test Geolocation Cache Hit
Date: Fri, 09 Oct 2026 10:00:00 +0000

This is a test email for geolocation caching verification.
"""

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Berlin",
        "city": "Berlin",
        "lat": 52.52,
        "lon": 13.405,
        "timezone": "Europe/Berlin",
        "isp": "Tor Exit Relay Service",
        "as": "AS208323",
        "org": "Tor Project Node",
        "proxy": True,
        "hosting": True,
    }

    print(">>> 1. First Email Analysis (Cache Miss -> Outbound Lookup) <<<")
    with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
        response1 = client.post(
            "/api/analyze/email",
            files={"file": ("test.eml", raw_eml.encode("utf-8"), "message/rfc822")},
            data={"hash_only": "false"}
        )
        assert response1.status_code == 200, f"Error {response1.text}"
        data1 = response1.json()
        calls_after_1 = mock_get.call_count
        print(f"Status: {response1.status_code}")
        print(f"External Geolocation HTTP Calls made: {calls_after_1}")
        geo1 = data1.get("geo_results", [])
        print(f"Geo results returned: {len(geo1)}")
        if geo1:
            print(f"First run cached flag: {geo1[0].get('cached')}")

        print("\n>>> 2. Second Email Analysis (Cache Hit -> Zero Outbound Lookups) <<<")
        response2 = client.post(
            "/api/analyze/email",
            files={"file": ("test.eml", raw_eml.encode("utf-8"), "message/rfc822")},
            data={"hash_only": "false"}
        )
        assert response2.status_code == 200, f"Error {response2.text}"
        data2 = response2.json()
        calls_after_2 = mock_get.call_count
        print(f"Status: {response2.status_code}")
        print(f"External Geolocation HTTP Calls made on 2nd load: {calls_after_2 - calls_after_1} (Total calls: {calls_after_2})")
        geo2 = data2.get("geo_results", [])
        print(f"Geo results returned: {len(geo2)}")
        if geo2:
            print(f"Second run cached flag: {geo2[0].get('cached')}")

        assert calls_after_1 == 1, f"Expected 1 call on first load, got {calls_after_1}"
        assert calls_after_2 == 1, f"Expected 0 additional calls on second load, got {calls_after_2}"
        assert geo2[0].get("cached") is True, "Expected cached=True on second load"

        print("\n>>> SUCCESS: Zero external geolocation calls made on second load! Cache-hit verified. <<<")

    db.close()

if __name__ == "__main__":
    run()
