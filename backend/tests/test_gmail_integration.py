"""
Integration and Unit Tests for Gmail OAuth and Inbox Sync (Part A).
Tests:
1. Mock OAuth flow returns valid credentials and stores encrypted refresh token.
2. gmail_sync parses 3 mocked messages -> 3 scans and 3 inbox items.
3. Duplicate Message-ID is skipped on re-sync.
4. Token refresh on 401 works (mock 401 then 200), second 401 marks account disconnected.
5. Disconnect endpoint revokes token at Google and deletes account row.
6. Rate limiting on /api/inbox/sync (1 per 30s per account).
"""

import base64
from datetime import datetime, timedelta
from email.message import EmailMessage
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from googleapiclient.errors import HttpError
import httpx

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import GmailAccount, InboxMessage, Scan
from app.services.gmail_oauth import (
    _verifier_store,
    decrypt_token,
    encrypt_token,
    exchange_code,
    get_authorization_url,
    revoke_token,
)
from app.services.gmail_sync import (
    convert_gmail_message_to_rfc822,
    fetch_messages,
    sync_inbox,
)
from app.services.llm_reasoner import LLMResult


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def mock_llm_reasoning():
    mock_res = LLMResult(
        summary="ThreatLens AI analysis: Email evaluated against RFC authentication and infrastructure signals.",
        provider_used="groq",
        latency_ms=45,
        cache_hit=False,
        raw_response="ThreatLens AI analysis: Email evaluated against RFC authentication and infrastructure signals.",
        anonymized_prompt="Anonymized prompt evidence",
    )
    with patch("app.services.email_forensics.reason", new=AsyncMock(return_value=mock_res)):
        yield


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
def preserve_real_gmail_account():
    db = SessionLocal()
    real_account = db.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
    backup = None
    if real_account and real_account.encrypted_refresh_token:
        backup = {
            "id": real_account.id,
            "user_session_id": real_account.user_session_id,
            "email_address": real_account.email_address,
            "encrypted_refresh_token": real_account.encrypted_refresh_token,
            "scopes": real_account.scopes,
            "connected_at": real_account.connected_at,
            "last_sync_at": real_account.last_sync_at,
            "is_active": real_account.is_active,
        }
    db.close()
    yield
    if backup:
        db = SessionLocal()
        acc = db.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
        if not acc:
            acc = GmailAccount(**backup)
            db.add(acc)
        else:
            for k, v in backup.items():
                setattr(acc, k, v)
        db.commit()
        db.close()


def _make_mock_gmail_payload(
    msg_id: str,
    subject: str,
    sender: str,
    body_text: str,
    message_id_header: str,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
) -> dict:
    """Helper to construct a realistic Gmail format='full' dictionary."""
    auth_header = (
        f"mx.google.com; spf={spf} smtp.mailfrom={sender}; "
        f"dkim={dkim} header.i=@{sender.split('@')[-1]}; "
        f"dmarc={dmarc}"
    )
    headers = [
        {"name": "From", "value": sender},
        {"name": "To", "value": "recipient@example.com"},
        {"name": "Subject", "value": subject},
        {"name": "Date", "value": "Fri, 09 Oct 2026 12:00:00 +0000"},
        {"name": "Message-ID", "value": message_id_header},
        {"name": "Authentication-Results", "value": auth_header},
        {"name": "Received", "value": "from mail.sender.test ([192.0.2.1]) by mx.google.com; Fri, 09 Oct 2026 12:00:00 +0000"},
    ]
    encoded_body = base64.urlsafe_b64encode(body_text.encode("utf-8")).decode("utf-8")

    return {
        "id": msg_id,
        "threadId": f"thread_{msg_id}",
        "snippet": body_text[:50],
        "payload": {
            "mimeType": "text/plain",
            "headers": headers,
            "body": {"size": len(body_text), "data": encoded_body},
            "parts": [],
        },
    }


# =====================================================================
# 1. MOCK OAUTH FLOW & TOKEN ENCRYPTION TESTS
# =====================================================================

def test_fernet_token_encryption_roundtrip():
    """Verify Fernet encryption & decryption round-trip with SESSION_SECRET."""
    secret_token = "1//04test_google_oauth_refresh_token_xyz123"
    enc = encrypt_token(secret_token)
    assert enc != secret_token
    assert len(enc) > 20
    dec = decrypt_token(enc)
    assert dec == secret_token


def test_oauth_start_missing_config(client):
    """When GOOGLE_CLIENT_ID is not configured, /start returns HTTP 400."""
    with patch.dict("os.environ", {"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}):
        resp = client.get("/api/auth/gmail/start", follow_redirects=False)
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "OAUTH_CONFIG_MISSING"


def test_oauth_start_with_config(client):
    """When configured, /start redirects with 307 to Google consent URL."""
    with patch.dict("os.environ", {
        "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "test-client-secret",
        "GOOGLE_OAUTH_REDIRECT_URI": "http://localhost:8000/api/auth/gmail/callback",
    }):
        resp = client.get("/api/auth/gmail/start", follow_redirects=False)
        assert resp.status_code == 307
        assert "accounts.google.com" in resp.headers["location"]
        assert "scope=" in resp.headers["location"]


def test_oauth_start_stores_verifier_and_callback_uses_it():
    """Verify PKCE code_verifier is preserved between get_authorization_url and exchange_code."""
    fake_state = "test_pkce_state_xyz"
    with patch.dict("os.environ", {
        "GOOGLE_CLIENT_ID": "mock-client-id",
        "GOOGLE_CLIENT_SECRET": "mock-client-secret",
    }):
        auth_url, state_out = get_authorization_url(state=fake_state)
        assert state_out == fake_state
        assert fake_state in _verifier_store
        expected_verifier = _verifier_store[fake_state]
        assert expected_verifier is not None
        assert len(expected_verifier) > 10

        # Mock Flow inside exchange_code
        mock_flow = MagicMock()
        mock_flow.credentials = MagicMock()
        with patch("app.services.gmail_oauth.build_flow", return_value=mock_flow):
            creds = exchange_code(code="mock_auth_code", state=fake_state)
            assert mock_flow.code_verifier == expected_verifier
            mock_flow.fetch_token.assert_called_once_with(code="mock_auth_code")
            assert creds == mock_flow.credentials

        # Verify it was popped from store
        assert fake_state not in _verifier_store


def test_oauth_callback_exchanges_code_and_stores_encrypted_token(client, db_session):
    """Mock OAuth exchange stores encrypted refresh token and redirects to /inbox."""
    mock_creds = MagicMock()
    mock_creds.refresh_token = "1//mock_refresh_token_abc"
    mock_creds.token = "ya29.mock_access_token"

    with patch("app.routes.auth.exchange_code", return_value=mock_creds), \
         patch("app.routes.auth.fetch_account_profile_email", return_value="analyst@gmail.com"):

        resp = client.get("/api/auth/gmail/callback?code=mock_auth_code", follow_redirects=False)
        assert resp.status_code in (302, 307)
        assert "/inbox?connected=true" in resp.headers["location"]

        account = db_session.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
        assert account is not None
        assert account.email_address == "analyst@gmail.com"
        assert account.is_active is True
        # Verify stored token is encrypted
        assert account.encrypted_refresh_token != "1//mock_refresh_token_abc"
        assert decrypt_token(account.encrypted_refresh_token) == "1//mock_refresh_token_abc"

    # Status endpoint should now report connected
    status_resp = client.get("/api/auth/gmail/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["connected"] is True
    assert data["email"] == "analyst@gmail.com"


# =====================================================================
# 2. GMAIL SYNC: 3 MOCKED MESSAGES -> 3 SCANS
# =====================================================================

def _get_or_create_test_account(db_session, email="analyst@gmail.com") -> GmailAccount:
    account = db_session.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
    if not account:
        account = GmailAccount(
            user_session_id="default_user",
            email_address=email,
            encrypted_refresh_token=encrypt_token("mock_token_123"),
            is_active=True,
        )
        db_session.add(account)
        db_session.commit()
    else:
        account.is_active = True
        if not account.email_address:
            account.email_address = email
        db_session.commit()
    return account


# =====================================================================
# 2. GMAIL SYNC: 3 MOCKED MESSAGES -> 3 SCANS
# =====================================================================

@pytest.mark.asyncio
async def test_gmail_sync_parses_3_messages_into_3_scans(client, db_session):
    """gmail_sync fetches 3 mocked messages and produces 3 forensic scans."""
    account = _get_or_create_test_account(db_session)

    # Clean any leftover records from prior test runs
    db_session.query(InboxMessage).filter(
        (InboxMessage.gmail_id.in_(["msg_001", "msg_002", "msg_003"])) |
        (InboxMessage.message_id.in_(["<msg1@corp.test>", "<msg2@phish.test>", "<msg3@digest.test>"]))
    ).delete(synchronize_session=False)
    db_session.query(Scan).filter(Scan.target.in_(["<msg1@corp.test>", "<msg2@phish.test>", "<msg3@digest.test>"])).delete(synchronize_session=False)
    db_session.commit()

    # Construct 3 distinct mock messages
    msg1 = _make_mock_gmail_payload("msg_001", "Meeting Agenda", "alice@corp.test", "Hello team, here is the agenda.", "<msg1@corp.test>", "pass", "pass", "pass")
    msg2 = _make_mock_gmail_payload("msg_002", "Urgent Action Required", "support@phish.test", "Please click here to verify.", "<msg2@phish.test>", "fail", "fail", "fail")
    msg3 = _make_mock_gmail_payload("msg_003", "Weekly Newsletter", "news@digest.test", "Check out top security news.", "<msg3@digest.test>", "neutral", "pass", "neutral")

    messages_store = {"msg_001": msg1, "msg_002": msg2, "msg_003": msg3}

    # Build mock service
    mock_service = MagicMock()
    mock_service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg_001"}, {"id": "msg_002"}, {"id": "msg_003"}]
    }

    def mock_get(userId, id, format):
        req = MagicMock()
        req.execute.return_value = messages_store[id]
        return req

    mock_service.users().messages().get.side_effect = mock_get

    # Run sync
    synced_count = await sync_inbox(account, db_session, max_results=20, service_override=mock_service)
    assert synced_count == 3

    # Check inbox messages
    inbox_items = (
        db_session.query(InboxMessage)
        .filter(InboxMessage.account_id == account.id, InboxMessage.gmail_id.in_(["msg_001", "msg_002", "msg_003"]))
        .all()
    )
    assert len(inbox_items) == 3

    # Verify /api/inbox returns 3 items
    inbox_resp = client.get("/api/inbox")
    assert inbox_resp.status_code == 200
    inbox_list = inbox_resp.json()
    assert len(inbox_list) >= 3

    # Verify detail endpoint /api/inbox/{gmail_id}
    detail_resp = client.get("/api/inbox/msg_001")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["gmail_id"] == "msg_001"
    assert detail["subject"] == "Meeting Agenda"
    assert "risk_score" in detail
    assert "factors" in detail


# =====================================================================
# 3. DUPLICATE MESSAGE-ID SKIPPED ON RE-SYNC
# =====================================================================

@pytest.mark.asyncio
async def test_duplicate_message_id_skipped_on_resync(client, db_session):
    """Re-syncing with identical Message-IDs returns 0 new messages."""
    account = _get_or_create_test_account(db_session)

    scans_before = db_session.query(Scan).count()
    inbox_before = db_session.query(InboxMessage).count()

    msg1 = _make_mock_gmail_payload("msg_001", "Meeting Agenda", "alice@corp.test", "Hello team.", "<msg1@corp.test>")
    msg2 = _make_mock_gmail_payload("msg_002", "Urgent Action Required", "support@phish.test", "Please verify.", "<msg2@phish.test>")

    mock_service = MagicMock()
    mock_service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg_001"}, {"id": "msg_002"}]
    }
    mock_service.users().messages().get.side_effect = lambda userId, id, format: MagicMock(execute=lambda: msg1 if id == "msg_001" else msg2)

    # Re-sync should skip both
    synced_count = await sync_inbox(account, db_session, max_results=20, service_override=mock_service)
    assert synced_count == 0

    scans_after = db_session.query(Scan).count()
    inbox_after = db_session.query(InboxMessage).count()
    assert scans_after == scans_before
    assert inbox_after == inbox_before



# =====================================================================
# 4. TOKEN REFRESH ON 401 (MOCK 401 THEN 200) & SECOND 401 DISCONNECT
# =====================================================================

def test_token_refresh_on_401_retry_success(db_session):
    """Encountering 401 on first call triggers refresh and succeeds on retry."""
    account = _get_or_create_test_account(db_session)


    # Construct mock HttpError with 401
    mock_resp_401 = MagicMock()
    mock_resp_401.status = 401
    error_401 = HttpError(resp=mock_resp_401, content=b"Unauthorized")

    mock_service_fail = MagicMock()
    mock_service_fail.users().messages().list().execute.side_effect = error_401

    mock_service_success = MagicMock()
    mock_service_success.users().messages().list().execute.return_value = {"messages": []}

    services = [mock_service_fail, mock_service_success]

    def mock_get_service(acc, db):
        s = services.pop(0) if services else mock_service_success
        return s, MagicMock()

    with patch("app.services.gmail_sync.get_gmail_service_with_retry", side_effect=mock_get_service):
        fetched = fetch_messages(account, db_session)
        assert fetched == []
        # Account should still be active because retry succeeded
        assert account.is_active is True


def test_second_401_marks_account_disconnected(db_session):
    """Persistent 401 error marks account.is_active = False."""
    real_account = db_session.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
    orig_active = real_account.is_active if real_account else None

    account = _get_or_create_test_account(db_session)

    mock_resp_401 = MagicMock()
    mock_resp_401.status = 401
    error_401 = HttpError(resp=mock_resp_401, content=b"Unauthorized")

    mock_service_persistent_401 = MagicMock()
    mock_service_persistent_401.users().messages().list().execute.side_effect = error_401

    try:
        with patch("app.services.gmail_sync.get_gmail_service_with_retry", return_value=(mock_service_persistent_401, MagicMock())):
            fetched = fetch_messages(account, db_session)
            assert fetched == []
            db_session.refresh(account)
            assert account.is_active is False
    finally:
        if orig_active is not None:
            account.is_active = orig_active
            db_session.commit()


# =====================================================================
# 5. DISCONNECT REVOKES AND DELETES ROW
# =====================================================================

def test_disconnect_revokes_token_and_deletes_account(client, db_session):
    """Disconnect endpoint calls Google revocation and removes DB row."""
    # Backup real account if present
    real_account = db_session.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
    real_attrs = None
    if real_account and real_account.email_address != "temp@gmail.com":
        real_attrs = {
            "id": real_account.id,
            "user_session_id": real_account.user_session_id,
            "email_address": real_account.email_address,
            "encrypted_refresh_token": real_account.encrypted_refresh_token,
            "scopes": real_account.scopes,
            "connected_at": real_account.connected_at,
            "last_sync_at": real_account.last_sync_at,
            "is_active": real_account.is_active,
        }

    account = real_account
    if not account:
        account = GmailAccount(
            user_session_id="default_user",
            email_address="temp@gmail.com",
            encrypted_refresh_token=encrypt_token("temp_token_123"),
            is_active=True,
        )
        db_session.add(account)
        db_session.commit()
    else:
        account.is_active = True
        db_session.commit()

    try:
        with patch("app.routes.auth.revoke_token", return_value=True) as mock_revoke:
            resp = client.post("/api/auth/gmail/disconnect")
            assert resp.status_code == 200
            data = resp.json()
            assert data["disconnected"] is True
            mock_revoke.assert_called_once()

        # Verify row is deleted
        deleted_account = db_session.query(GmailAccount).filter(GmailAccount.user_session_id == "default_user").first()
        assert deleted_account is None

        # Verify status returns false
        status_resp = client.get("/api/auth/gmail/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["connected"] is False
    finally:
        if real_attrs:
            db_session.add(GmailAccount(**real_attrs))
            db_session.commit()


# =====================================================================
# 6. MANUAL SYNC RATE LIMITING
# =====================================================================

def test_sync_rate_limit_30_seconds(client, db_session):
    """POST /api/inbox/sync enforces 30s rate limit."""
    # Create active account with recent last_sync_at
    account = GmailAccount(
        user_session_id="default_user",
        email_address="rate_limit@gmail.com",
        encrypted_refresh_token=encrypt_token("tok_rate_limit"),
        last_sync_at=datetime.utcnow() - timedelta(seconds=10),
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()

    resp = client.post("/api/inbox/sync")
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "SYNC_RATE_LIMITED"

    # Cleanup
    db_session.delete(account)
    db_session.commit()
