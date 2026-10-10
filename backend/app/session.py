"""
Session management for multi-user session isolation.
Generates and inspects per-browser session IDs stored in HTTP-only cookies.
Supports X-Session-ID header for test and dev overrides.
"""

from typing import Optional
import uuid
from fastapi import Request, Response

COOKIE_NAME = "tl_session"
SESSION_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days in seconds


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
        return session_id

    # 3. Check request state (e.g. set by session middleware)
    state_val = getattr(request.state, "session_id", None)
    if state_val and state_val.strip():
        return state_val.strip()

    # 4. Generate new session ID
    session_id = str(uuid.uuid4())
    request.state.session_id = session_id

    # Set cookie on response if provided
    if response is not None:
        response.set_cookie(
            key=COOKIE_NAME,
            value=session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            path="/",
        )

    return session_id
