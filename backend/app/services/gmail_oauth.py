"""
Gmail OAuth service: flow creation, code exchange, token refresh, token encryption & revocation.
Only requests readonly scope: https://www.googleapis.com/auth/gmail.readonly.
"""

import base64
import hashlib
import logging
import os
import threading
import time
from typing import Optional, Tuple
from cryptography.fernet import Fernet
import httpx
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
DEFAULT_REDIRECT_URI = "http://localhost:8000/api/auth/gmail/callback"
GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

_verifier_store: dict[str, str] = {}   # keyed by state
_verifier_timestamps: dict[str, float] = {}  # keyed by state -> creation timestamp
_verifier_store_lock = threading.Lock()
_VERIFIER_TTL_SECONDS = 600.0  # 10 minutes


def store_verifier(state: str, verifier: str) -> None:
    now = time.time()
    with _verifier_store_lock:
        # Evict entries older than 10 minutes
        stale_states = [s for s, ts in _verifier_timestamps.items() if now - ts > _VERIFIER_TTL_SECONDS]
        for s in stale_states:
            _verifier_store.pop(s, None)
            _verifier_timestamps.pop(s, None)
        _verifier_store[state] = verifier
        _verifier_timestamps[state] = now


def pop_verifier(state: str) -> Optional[str]:
    now = time.time()
    with _verifier_store_lock:
        # Evict stale entries
        stale_states = [s for s, ts in _verifier_timestamps.items() if now - ts > _VERIFIER_TTL_SECONDS]
        for s in stale_states:
            _verifier_store.pop(s, None)
            _verifier_timestamps.pop(s, None)
        ts = _verifier_timestamps.pop(state, None)
        verifier = _verifier_store.pop(state, None)
        if ts is None or verifier is None:
            return None
        if now - ts > _VERIFIER_TTL_SECONDS:
            return None
        return verifier


def _get_fernet() -> Fernet:
    secret = os.getenv("SESSION_SECRET", "threatlens-default-secret-key-32b!")
    # Derive deterministic 32-byte key
    key_bytes = hashlib.sha256(secret.encode("utf-8")).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_token(token: str) -> str:
    """Encrypt a token with SESSION_SECRET using Fernet symmetric encryption."""
    if not token:
        return ""
    f = _get_fernet()
    return f.encrypt(token.encode("utf-8")).decode("utf-8")


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a Fernet-encrypted token with SESSION_SECRET."""
    if not encrypted_token:
        return ""
    f = _get_fernet()
    return f.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")


def build_flow(state: Optional[str] = None, autogenerate_code_verifier: bool = False) -> Flow:
    """
    Build Google OAuth2 Flow configured strictly for read-only Gmail access.
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    redirect_uri = os.getenv("GOOGLE_OAUTH_REDIRECT_URI", DEFAULT_REDIRECT_URI)

    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=[GMAIL_READONLY_SCOPE],
        state=state,
        autogenerate_code_verifier=autogenerate_code_verifier,
    )
    flow.redirect_uri = redirect_uri
    return flow


def get_authorization_url(state: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate Google OAuth consent URL requiring offline access (refresh_token).
    """
    flow = build_flow(state=state, autogenerate_code_verifier=True)
    authorization_url, state_out = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    if flow.code_verifier and state_out:
        store_verifier(state_out, flow.code_verifier)
    return authorization_url, state_out


def exchange_code(code: str, state: Optional[str] = None) -> Credentials:
    """
    Exchange authorization code for access and refresh tokens.
    """
    if not state:
        raise ValueError("OAuth state expired or unknown. Restart the flow.")

    verifier = pop_verifier(state)
    if not verifier:
        raise ValueError("OAuth state expired or unknown. Restart the flow.")

    flow = build_flow(state=state)
    flow.code_verifier = verifier
    flow.fetch_token(code=code)
    return flow.credentials


def refresh_if_needed(credentials: Credentials) -> Credentials:
    """
    Refresh credentials if expired or nearing expiry.
    """
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    return credentials


def build_credentials_from_refresh_token(refresh_token: str) -> Credentials:
    """
    Reconstruct Google Credentials instance from decrypted refresh token.
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")

    return Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=[GMAIL_READONLY_SCOPE],
    )


def fetch_account_profile_email(credentials: Credentials) -> Optional[str]:
    """
    Fetch connected user's primary email address using the Gmail API profile endpoint.
    """
    try:
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")
    except Exception as e:
        logger.warning("Failed to fetch Gmail profile email: %s", e)
        return None


def revoke_token(token: str) -> bool:
    """
    Revoke access or refresh token at Google's revocation endpoint.
    """
    if not token:
        return False
    try:
        resp = httpx.post(
            GOOGLE_REVOKE_ENDPOINT,
            params={"token": token},
            headers={"content-type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning("Error revoking token with Google: %s", e)
        return False
