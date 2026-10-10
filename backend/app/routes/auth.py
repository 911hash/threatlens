"""
Authentication routes for Gmail OAuth2 integration.
Handles consent start, callback token exchange, status check, and revocation/disconnect.
Per-browser multi-user session isolation via session cookies.
"""

from datetime import datetime
import logging
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import GmailAccount, generate_id
from ..session import get_or_create_session_id
from ..services.gmail_oauth import (
    decrypt_token,
    encrypt_token,
    exchange_code,
    fetch_account_profile_email,
    get_authorization_url,
    get_state_session,
    revoke_token,
    store_state_session,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth/gmail", tags=["Gmail Auth"])
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")


@router.get("/start")
def start_gmail_oauth(request: Request, response: Response):
    """
    Start OAuth flow by redirecting user to Google's consent screen.
    Requires Google Client ID & Secret configured in environment.
    Stores session_id associated with OAuth state.
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "OAUTH_CONFIG_MISSING",
                "message": "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.",
            },
        )

    session_id = get_or_create_session_id(request, response)

    try:
        auth_url, state_out = get_authorization_url()
        store_state_session(state_out, session_id)
        redirect_resp = RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        get_or_create_session_id(request, redirect_resp)
        return redirect_resp
    except Exception as e:
        logger.exception("Failed to build authorization URL: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "OAUTH_INIT_ERROR", "message": f"Failed to initialize OAuth flow: {str(e)}"},
        )


@router.get("/callback")
def gmail_oauth_callback(
    request: Request,
    response: Response,
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Exchange authorization code for credentials, store encrypted refresh token in DB,
    and redirect user back to frontend /inbox.
    """
    if error:
        logger.warning("Google OAuth error callback: %s", error)
        return RedirectResponse(url=f"{FRONTEND_ORIGIN}/inbox?error={error}")

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "MISSING_CODE", "message": "Authorization code is missing from callback."},
        )

    try:
        credentials = exchange_code(code, state=state)
    except Exception as e:
        logger.exception("Token exchange failed: %s", e)
        return RedirectResponse(url=f"{FRONTEND_ORIGIN}/inbox?error=token_exchange_failed")

    session_id = (get_state_session(state) if state else None) or get_or_create_session_id(request, response)

    refresh_token_val = credentials.refresh_token
    if not refresh_token_val:
        # Check if an existing account already has a refresh token for this session
        existing = (
            db.query(GmailAccount)
            .filter(GmailAccount.user_session_id == session_id, GmailAccount.is_active == True)
            .first()
        )
        if existing and existing.encrypted_refresh_token:
            refresh_token_val = decrypt_token(existing.encrypted_refresh_token)
        else:
            logger.warning("No refresh token returned by Google OAuth. User may need to re-authorize.")
            refresh_token_val = credentials.token or "no_refresh_token"

    user_email = fetch_account_profile_email(credentials) or "user@gmail.com"
    encrypted_rt = encrypt_token(refresh_token_val)

    # Upsert account for this browser session
    account = db.query(GmailAccount).filter(GmailAccount.user_session_id == session_id).first()
    if account:
        account.email_address = user_email
        account.encrypted_refresh_token = encrypted_rt
        account.is_active = True
        account.connected_at = datetime.utcnow()
    else:
        account = GmailAccount(
            id=generate_id("gacc"),
            user_session_id=session_id,
            email_address=user_email,
            encrypted_refresh_token=encrypted_rt,
            scopes="https://www.googleapis.com/auth/gmail.readonly",
            connected_at=datetime.utcnow(),
            is_active=True,
        )
        db.add(account)

    db.commit()
    redirect_resp = RedirectResponse(url=f"{FRONTEND_ORIGIN}/inbox?connected=true")
    get_or_create_session_id(request, redirect_resp)
    return redirect_resp


@router.get("/status")
def gmail_oauth_status(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Return connection status of Gmail account for current browser session.
    """
    session_id = get_or_create_session_id(request, response)
    account = (
        db.query(GmailAccount)
        .filter(GmailAccount.user_session_id == session_id, GmailAccount.is_active == True)
        .first()
    )
    if not account:
        return {"connected": False, "email": None}

    return {
        "connected": True,
        "email": account.email_address,
        "connected_at": account.connected_at.isoformat() if account.connected_at else None,
        "last_sync_at": account.last_sync_at.isoformat() if account.last_sync_at else None,
    }


@router.post("/disconnect")
def gmail_oauth_disconnect(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Revoke OAuth tokens at Google and delete account row for current browser session.
    """
    session_id = get_or_create_session_id(request, response)
    account = (
        db.query(GmailAccount)
        .filter(GmailAccount.user_session_id == session_id, GmailAccount.is_active == True)
        .first()
    )
    if not account:
        return {"connected": False, "disconnected": False, "message": "No active account found."}

    # Attempt Google revocation
    try:
        token_to_revoke = decrypt_token(account.encrypted_refresh_token)
        revoke_token(token_to_revoke)
    except Exception as e:
        logger.warning("Error during token revocation: %s", e)

    # Delete row from DB
    db.delete(account)
    db.commit()

    return {"connected": False, "disconnected": True, "message": "Gmail account disconnected successfully."}
