import logging
import os
from typing import Optional
import uuid
from fastapi import Request, Response

logger = logging.getLogger(__name__)

COOKIE_NAME = "tl_session"
SESSION_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days in seconds


def is_request_secure(request: Optional[Request] = None) -> bool:
    """
    Check if the request is secure (HTTPS or force secure via env).
    Evaluates request.url.scheme, X-Forwarded-Proto header (reverse proxies),
    and FORCE_SECURE_COOKIES environment variable.
    """
    if os.getenv("FORCE_SECURE_COOKIES") == "1":
        return True
    if request is not None:
        scheme = getattr(getattr(request, "url", None), "scheme", "http")
        headers = getattr(request, "headers", None)
        forwarded_proto = headers.get("x-forwarded-proto") if headers else None
        return scheme == "https" or forwarded_proto == "https"
    return False


def set_session_cookie(
    response: Response,
    session_id: str,
    request: Optional[Request] = None,
) -> None:
    """
    Set the tl_session cookie on response.
    When secure (HTTPS or FORCE_SECURE_COOKIES=1):
      SameSite=None, Secure=True, HttpOnly=True, Path=/, Max-Age=2592000
    When local dev over plain HTTP:
      SameSite=lax, Secure=False, HttpOnly=True, Path=/, Max-Age=2592000
    """
    secure = is_request_secure(request)
    samesite = "None" if secure else "lax"

    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path="/",
    )


def extract_session_id_from_state(state: Optional[str]) -> Optional[str]:
    """
    Extract session_id from OAuth state parameter formatted as f"{session_id}:{random_nonce}".
    Fallback to returning None if state is absent or does not contain separator.
    """
    if not state or not isinstance(state, str):
        return None
    cleaned = state.strip()
    if ":" in cleaned:
        sid = cleaned.split(":", 1)[0].strip()
        if sid:
            return sid
    return None


def get_or_create_session_id(request: Request, response: Optional[Response] = None) -> str:
    """
    Get or create a per-browser session ID.
    Priority:
    1. X-Session-ID header (dev/testing override)
    2. request.cookies['tl_session']
    3. request.state.session_id (if set by middleware)
    4. Generate fresh UUID4, set tl_session cookie on response if provided.
    """
    # 1. Header override for testing / dev
    header_val = request.headers.get("X-Session-ID")
    if header_val and header_val.strip():
        session_id = header_val.strip()
        request.state.session_id = session_id
        return session_id

    # 2. Existing cookie
    cookie_val = request.cookies.get(COOKIE_NAME)
    if cookie_val and cookie_val.strip():
        session_id = cookie_val.strip()
        request.state.session_id = session_id
        if response is not None:
            set_session_cookie(response, session_id, request)
        return session_id

    # 3. Check request state (e.g. set by session middleware)
    state_val = getattr(request.state, "session_id", None)
    if state_val and state_val.strip():
        if response is not None:
            set_session_cookie(response, state_val.strip(), request)
        return state_val.strip()

    # 4. Generate new session ID
    session_id = str(uuid.uuid4())
    request.state.session_id = session_id

    # Set cookie on response if provided
    if response is not None:
        set_session_cookie(response, session_id, request)

    return session_id

