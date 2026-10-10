"""
Tests for multi-user session isolation.

Verifies:
1. test_session_isolation_gmail:
   Session A connects Gmail, session B calls /api/auth/status and gets connected: false.
2. test_session_isolation_scans:
   Session A runs/has a scan, session B queries /api/scans and gets empty list.
3. test_session_isolation_graph:
   Session A ingests an entity into artifact graph, session B queries /api/graph/recent and gets empty graph.
4. test_missing_cookie_creates_new_session:
   Request with no cookie gets a Set-Cookie: tl_session=... header in response.
"""

from datetime import datetime
import uuid
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import GmailAccount, GraphNode, Scan, generate_id
from app.services import graph_service


@pytest.fixture
def client():
    # Fresh TestClient without stored cookies
    return TestClient(app)


def test_session_isolation_gmail(client):
    """Session A connects Gmail; Session B sees connected: false."""
    session_a = f"sess_gmail_a_{uuid.uuid4().hex[:8]}"
    session_b = f"sess_gmail_b_{uuid.uuid4().hex[:8]}"

    db = SessionLocal()
    try:
        # Create an active Gmail account for Session A
        acc = GmailAccount(
            id=generate_id("gacc"),
            user_session_id=session_a,
            email_address="alice.session@example.test",
            encrypted_refresh_token="mock_enc_refresh_token_a",
            scopes="https://www.googleapis.com/auth/gmail.readonly",
            connected_at=datetime.utcnow(),
            is_active=True,
        )
        db.add(acc)
        db.commit()
    finally:
        db.close()

    # Session B queries Gmail status
    resp_b = client.get("/api/auth/gmail/status", headers={"X-Session-ID": session_b})
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["connected"] is False
    assert data_b["email"] is None

    # Session A queries Gmail status
    resp_a = client.get("/api/auth/gmail/status", headers={"X-Session-ID": session_a})
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["connected"] is True
    assert data_a["email"] == "alice.session@example.test"


def test_session_isolation_scans(client):
    """Session A creates a scan; Session B sees empty scan list."""
    session_a = f"sess_scans_a_{uuid.uuid4().hex[:8]}"
    session_b = f"sess_scans_b_{uuid.uuid4().hex[:8]}"

    db = SessionLocal()
    try:
        scan_a = Scan(
            id=generate_id("scan"),
            user_session_id=session_a,
            target="https://isolated-session-target.test",
            target_type="url",
            timestamp=datetime.utcnow(),
            risk_score=75,
            risk_level="HIGH",
            confidence=85,
            detection_count=12,
            total_engines=70,
            factors_json="[]",
            raw_summary_json="{}",
            sources_json="{}",
            is_demo=False,
        )
        db.add(scan_a)
        db.commit()
    finally:
        db.close()

    # Session B queries scans
    resp_b = client.get("/api/scans", headers={"X-Session-ID": session_b})
    assert resp_b.status_code == 200
    scans_b = resp_b.json()
    # Confirm none of the scans belong to session_a target
    assert not any(s["target"] == "https://isolated-session-target.test" for s in scans_b)

    # Session A queries scans
    resp_a = client.get("/api/scans", headers={"X-Session-ID": session_a})
    assert resp_a.status_code == 200
    scans_a = resp_a.json()
    assert any(s["target"] == "https://isolated-session-target.test" for s in scans_a)


def test_session_isolation_graph(client):
    """Session A has graph nodes; Session B queries graph/recent and gets empty/isolated graph."""
    session_a = f"sess_graph_a_{uuid.uuid4().hex[:8]}"
    session_b = f"sess_graph_b_{uuid.uuid4().hex[:8]}"

    db = SessionLocal()
    try:
        graph_service._upsert_node(
            tenant_id="default",
            node_type="domain",
            value=f"isolated-{session_a}.test",
            display_value=f"isolated-{session_a}.test",
            db=db,
            user_session_id=session_a,
        )
        db.commit()
    finally:
        db.close()

    # Session B queries recent graph nodes
    resp_b = client.get("/api/graph/recent", headers={"X-Session-ID": session_b})
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert not any(n["value"] == f"isolated-{session_a}.test" for n in data_b.get("nodes", []))

    # Session A queries recent graph nodes
    resp_a = client.get("/api/graph/recent", headers={"X-Session-ID": session_a})
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert any(n["value"] == f"isolated-{session_a}.test" for n in data_a.get("nodes", []))


def test_missing_cookie_creates_new_session():
    """Request with no cookie gets a Set-Cookie: tl_session=... header in response."""
    test_client = TestClient(app, cookies=None)
    resp = test_client.get("/api/health")
    assert resp.status_code == 200

    # Ensure Set-Cookie header contains tl_session
    set_cookie = resp.headers.get("set-cookie", "")
    assert "tl_session=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
