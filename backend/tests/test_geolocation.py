"""
Tests for Phase 8: Geolocation, ASN Enrichment & Infrastructure Risk.

Covers:
1. Datacenter IP fixture (+5 factor)
2. Tor IP fixture (+15 factor)
3. Cache hit: second call makes zero network requests (httpx call_count == 1)
4. Service failure returns "unknown", report still renders without error
5. Hash-only mode: no live lookup fired (httpx call_count == 0)
6. AV_DETECTIONS >= 3 rule: geolocation cannot push score past next level threshold
"""

import io
import json
from unittest.mock import MagicMock, patch
import pytest
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models import GeolocationCache
from app.services.geolocation import geolocate_ip, purge_expired_cache
from app.risk_engine import NormalizedEvidence, evaluate


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def mock_llm_reasoning():
    from unittest.mock import AsyncMock
    from app.services.llm_reasoner import LLMResult

    mock_res = LLMResult(
        summary="ThreatLens AI analysis: Evaluated transport and geolocation infrastructure.",
        provider_used="groq",
        latency_ms=30,
        cache_hit=False,
        raw_response="ThreatLens AI analysis: Evaluated transport and geolocation infrastructure.",
        anonymized_prompt="Anonymized prompt evidence",
    )
    with patch("app.services.email_forensics.reason", new=AsyncMock(return_value=mock_res)):
        yield


def test_cache_hit_makes_zero_network_requests(db_session):
    """Test: second call to geolocate_ip for the same IP makes zero network requests."""
    test_ip = "198.51.100.42"
    # Ensure clean state for test IP
    db_session.query(GeolocationCache).filter(GeolocationCache.ip == test_ip).delete()
    db_session.commit()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Netherlands",
        "countryCode": "NL",
        "regionName": "North Holland",
        "city": "Amsterdam",
        "lat": 52.37,
        "lon": 4.89,
        "timezone": "Europe/Amsterdam",
        "isp": "Example Host B.V.",
        "as": "AS12345 Example Host",
        "org": "Example Org",
        "proxy": False,
        "hosting": False,
    }

    with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
        # First call: cache miss, fires network lookup
        res1 = geolocate_ip(test_ip, db_session, hash_only=False)
        assert res1.country == "Netherlands"
        assert res1.cached is False
        assert mock_get.call_count == 1

        # Second call: cache hit, zero network requests
        res2 = geolocate_ip(test_ip, db_session, hash_only=False)
        assert res2.country == "Netherlands"
        assert res2.cached is True
        assert mock_get.call_count == 1  # Still 1, no second call!


def test_hash_only_mode_no_network_request(db_session):
    """Test: in hash-only mode, no live lookup is fired for un-cached IPs."""
    test_ip = "198.51.100.99"
    # Ensure clean state for test IP
    db_session.query(GeolocationCache).filter(GeolocationCache.ip == test_ip).delete()
    db_session.commit()

    with patch("httpx.Client.get") as mock_get:
        res = geolocate_ip(test_ip, db_session, hash_only=True)
        assert mock_get.call_count == 0
        assert res.is_unknown is True
        assert res.cached is False


def test_service_failure_returns_unknown_gracefully(client, db_session):
    """Test: when geolocation service fails or times out, returns 'unknown' and report still renders."""
    test_ip = "198.51.100.77"
    db_session.query(GeolocationCache).filter(GeolocationCache.ip == test_ip).delete()
    db_session.commit()

    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused")):
        res = geolocate_ip(test_ip, db_session, hash_only=False)
        assert res.is_unknown is True
        assert res.country == "unknown"

        # Verify that upload endpoint still succeeds (200 OK) even when geolocation fails
        eml_content = (
            b"From: test@example.test\r\n"
            b"To: recipient@example.test\r\n"
            b"Subject: Test Network Drop\r\n"
            b"Message-ID: <drop-test@example.test>\r\n"
            b"Received: from relay.example.test ([198.51.100.77]) by mx.example.test; Fri, 09 Oct 2026 12:00:00 +0000\r\n\r\n"
            b"Test body.\r\n"
        )
        files = {"file": ("test_drop.eml", io.BytesIO(eml_content), "message/rfc822")}
        resp = client.post("/api/analyze/email", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["geo_results"]) >= 1
        assert data["geo_results"][0]["is_unknown"] is True


def test_tor_ip_fixture_awards_15_points(client):
    """Test: Tor exit node IP awards +15 points in GEOLOCATION group."""
    tor_ip = "185.220.101.5"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Saxony",
        "city": "Dresden",
        "lat": 51.05,
        "lon": 13.73,
        "timezone": "Europe/Berlin",
        "isp": "Tor Exit Relay Network",
        "as": "AS60729 Tor Nodes",
        "org": "The Tor Project Relay",
        "proxy": True,
        "hosting": False,
    }

    eml_content = (
        f"From: user@example.test\r\n"
        f"Subject: Important Notification\r\n"
        f"Message-ID: <tor-msg-123@example.test>\r\n"
        f"Received: from tor-relay.test ([{tor_ip}]) by mx.mail-receiver.example.org; Fri, 09 Oct 2026 10:00:00 +0000\r\n\r\n"
        f"Hello from Tor network.\r\n"
    ).encode("utf-8")

    with patch("httpx.Client.get", return_value=mock_resp):
        files = {"file": ("tor.eml", io.BytesIO(eml_content), "message/rfc822")}
        resp = client.post("/api/analyze/email", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["group_breakdown"]["GEOLOCATION"] == 15
        assert any(f["id"] == "geo_tor_exit_node" and f["points"] == 15 for f in data["factors"])


def test_datacenter_consumer_sender_awards_5_points(client):
    """Test: Datacenter IP for consumer-facing sender (e.g. @gmail.com) awards +5 points."""
    dc_ip = "54.240.196.1"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "city": "Ashburn",
        "lat": 39.04,
        "lon": -77.48,
        "timezone": "America/New_York",
        "isp": "Amazon.com, Inc.",
        "as": "AS16509 Amazon.com, Inc.",
        "org": "AWS EC2 Datacenter",
        "proxy": False,
        "hosting": True,
    }

    eml_content = (
        f"From: spoofeduser@gmail.com\r\n"
        f"Subject: Action Required\r\n"
        f"Message-ID: <dc-consumer-456@gmail.com>\r\n"
        f"Received: from ec2.amazonaws.com ([{dc_ip}]) by mx.mail-receiver.example.org; Fri, 09 Oct 2026 10:00:00 +0000\r\n\r\n"
        f"Suspicious email claiming to be from Gmail but sent directly from AWS EC2.\r\n"
    ).encode("utf-8")

    with patch("httpx.Client.get", return_value=mock_resp):
        files = {"file": ("datacenter.eml", io.BytesIO(eml_content), "message/rfc822")}
        resp = client.post("/api/analyze/email", files=files)
        assert resp.status_code == 200
        data = resp.json()

        assert data["group_breakdown"]["GEOLOCATION"] >= 5
        assert any(f["id"] == "geo_datacenter_sender" and f["points"] == 5 for f in data["factors"])


def test_av_detections_ge_3_rule_caps_geolocation():
    """
    Test Rule: if AV_DETECTIONS >= 3, geolocation alone must NOT push score
    past the next level threshold.
    """
    # 1. Base evidence with 3 AV detections:
    # 3 VT malicious detections yields 30 AV_DETECTIONS points
    # Add reputation points to place base score right at 54 (top of MEDIUM tier: 30-54)
    # Next threshold is HIGH (55..79)
    evidence = NormalizedEvidence(
        target="http://malicious.example.test",
        target_type="url",
        virustotal={"status": "complete", "malicious": 3, "total": 70},  # AV_DETECTIONS >= 3 (30 pts)
        urlhaus={"status": "malicious", "threat": "malware_download"},    # REPUTATION_LISTS (20 pts)
        safe_browsing={"status": "suspicious"},                           # REPUTATION_LISTS (10 pts -> cap 35, total rep 30? No: urlhaus 20 + safe_browsing 10 = 24 or 30)
    )

    # Evaluate without geolocation first
    base_res = evaluate(evidence)
    assert base_res.raw_evidence_summary["vt_malicious"] >= 3
    # Check current tier
    base_score = base_res.score

    # Now add Tor exit node (+15 geolocation points)
    evidence_with_geo = NormalizedEvidence(
        target="http://malicious.example.test",
        target_type="url",
        virustotal={"status": "complete", "malicious": 3, "total": 70},
        urlhaus={"status": "malicious", "threat": "malware_download"},
        safe_browsing={"status": "suspicious"},
        geolocation={"is_tor": True, "ip": "185.220.101.5"},
    )
    res_with_geo = evaluate(evidence_with_geo)

    assert res_with_geo.group_breakdown["GEOLOCATION"] == 15

    # If base_score was in MEDIUM (e.g. 50 or 54), it must NOT exceed 54 solely from geolocation
    if 30 <= base_score <= 54:
        assert res_with_geo.score <= 54, f"Geolocation pushed score {res_with_geo.score} past MEDIUM ceiling 54!"
        assert res_with_geo.level == "MEDIUM"
    elif 55 <= base_score <= 79:
        assert res_with_geo.score <= 79, f"Geolocation pushed score {res_with_geo.score} past HIGH ceiling 79!"
        assert res_with_geo.level == "HIGH"
