"""
Integration tests for FastAPI endpoints.
Tests health, demo seed, URL analysis with SSRF handling, hash analysis, history, and watchlist.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "configured_sources" in data
    assert "demo_mode" in data
    assert isinstance(data["configured_sources"], dict)


def test_demo_seed_and_info(client):
    # Test GET /api/demo
    demo_info = client.get("/api/demo")
    assert demo_info.status_code == 200
    assert "featured_target" in demo_info.json()

    # Test POST /api/demo/seed
    seed_resp = client.post("/api/demo/seed")
    assert seed_resp.status_code == 200
    data = seed_resp.json()
    assert data["status"] in ("seeded", "already_seeded")
    assert "featured_target" in data


def test_ssrf_rejection_endpoints(client):
    targets = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",
        "http://10.0.0.1",
        "http://192.168.1.1",
    ]

    for target in targets:
        resp = client.post("/api/analyze/url", json={"url": target})
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data
        assert "private or internal network and can't be analyzed" in data["error"]["message"]


def test_invalid_hash_rejection(client):
    resp = client.post("/api/analyze/hash", json={"hash": "invalid-not-hex"})
    assert resp.status_code == 400
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_HASH"


def test_watchlist_flow(client):
    # Add item
    add_resp = client.post(
        "/api/watchlist",
        json={"target": "http://monitored-site.example.com", "target_type": "url"},
    )
    assert add_resp.status_code == 201
    item_id = add_resp.json()["id"]

    # List items
    list_resp = client.get("/api/watchlist")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(i["id"] == item_id for i in items)

    # Delete item
    del_resp = client.delete(f"/api/watchlist/{item_id}")
    assert del_resp.status_code == 200


def test_get_scans_and_history(client):
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    scans = scans_resp.json()
    assert isinstance(scans, list)


def test_demo_reset_and_clean_scores(client):
    """Confirm reset and re-seed produces exact scores: 18, 25, 41, 65, 82."""
    featured_url = "http://service-cdn.example-phishing-login.com/auth"
    # Seed with reset=True
    reset_resp = client.post("/api/demo/seed?reset=true")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "seeded"

    # Query history
    from urllib.parse import quote
    hist_resp = client.get(f"/api/history/{quote(featured_url, safe='')}")
    assert hist_resp.status_code == 200
    data = hist_resp.json()
    scans = data["scans"]
    assert len(scans) == 5

    # Ascending scores
    scores_asc = sorted([s["risk_score"] for s in scans])
    assert scores_asc == [18, 25, 41, 65, 82]


def test_unknown_hash_and_file_yields_unknown_confidence_le_10(client):
    """Confirm hash or file with no source data yields UNKNOWN (confidence <= 10), never SAFE."""
    # 1. Unknown hash
    unknown_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    resp = client.post("/api/analyze/hash", json={"hash": unknown_hash})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "UNKNOWN"
    assert data["confidence"] <= 10
    assert data["risk_score"] == 0
    assert data["risk_level"] != "SAFE"

    # 2. Unknown file upload
    import io
    file_content = b"This is an unindexed sample file with zero threat intelligence records."
    resp_file = client.post(
        "/api/analyze/file",
        files={"file": ("unseen_sample.txt", io.BytesIO(file_content), "text/plain")},
    )
    assert resp_file.status_code == 200
    data_file = resp_file.json()
    assert data_file["risk_level"] == "UNKNOWN"
    assert data_file["confidence"] <= 10
    assert data_file["risk_score"] == 0
    assert data_file["risk_level"] != "SAFE"


def test_featured_url_rescan_always_produces_nonzero_diff_even_at_cap(client):
    """Confirm re-scanning featured demo URL always produces a nonzero diff vs the latest scan."""
    featured_url = "http://service-cdn.example-phishing-login.com/auth"
    # Clean reset first
    client.post("/api/demo/seed?reset=true")

    # Get latest scan ID
    from urllib.parse import quote
    hist_resp = client.get(f"/api/history/{quote(featured_url, safe='')}")
    latest_id = hist_resp.json()["scans"][0]["id"]

    # Re-scan 6 times: 82 -> 85 -> 88 -> 91 -> 92 -> 92 (capped) -> 92 (capped)
    for i in range(6):
        rescan_resp = client.post("/api/analyze/url", json={"url": featured_url})
        assert rescan_resp.status_code == 200
        new_scan = rescan_resp.json()
        new_id = new_scan["id"]

        # Score must be <= 92 and never 100
        assert new_scan["risk_score"] <= 92
        assert new_scan["risk_score"] != 100

        # Compare vs previous scan
        cmp_resp = client.get(f"/api/compare/{latest_id}/{new_id}")
        assert cmp_resp.status_code == 200
        diff = cmp_resp.json()

        # Must be nonzero diff!
        assert diff["summary"] != "Threat profile unchanged", f"Failed on iteration {i}: diff was zero"
        has_nonzero_metric = (
            diff["score_delta"] != 0
            or diff["detection_delta"] != 0
            or len(diff["factors_added"]) > 0
            or len(diff["factors_removed"]) > 0
            or len(diff["factors_changed"]) > 0
            or diff["redirect_chain_change"]["hop_count_delta"] != 0
            or len(diff["reputation_changes"]["newly_flagged"]) > 0
            or len(diff["reputation_changes"]["unflagged"]) > 0
        )
        assert has_nonzero_metric, f"Iteration {i} had all zero metrics"

        # Advance latest_id
        latest_id = new_id

