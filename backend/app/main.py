"""
Main FastAPI Application for ThreatLens.
Explainable threat intelligence layer.
"""

from pathlib import Path
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(REPO_ROOT / ".env", override=True)

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import os
from typing import Any, Dict
import uuid
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .database import Base, SessionLocal, engine, run_migrations
from .models import Alert, Scan, WatchlistItem, generate_id
import logging
from .routes import analyze, auth, demo, forensics, history, inbox, watchlist
from .schemas import HealthConfigResponse, HealthResponse
from .session import COOKIE_NAME, SESSION_COOKIE_MAX_AGE, get_or_create_session_id, set_session_cookie
from .services.gmail_worker import shutdown_gmail_polling_worker, start_gmail_polling_worker
from apscheduler.schedulers.background import BackgroundScheduler
from .services.url_analysis import refang_target, trace_url_redirects, validate_url_syntax
from .services.virustotal import VT_API_KEY, lookup_virustotal_hash, lookup_virustotal_url
from .risk_engine import NormalizedEvidence, evaluate

logger = logging.getLogger(__name__)

# Create tables and run auto-migrations
Base.metadata.create_all(bind=engine)
run_migrations()

frontend_origin_env = os.getenv("FRONTEND_ORIGIN")
if not frontend_origin_env or not frontend_origin_env.strip():
    logger.warning("FRONTEND_ORIGIN is not set. Defaulting to ['http://localhost:5173'].")
    allow_origins_list = ["http://localhost:5173"]
else:
    origins = [org.strip() for org in frontend_origin_env.split(",") if org.strip()]
    allow_origins_list = origins if origins else ["http://localhost:5173"]


WATCHLIST_INTERVAL_MINUTES = int(os.getenv("WATCHLIST_INTERVAL_MINUTES", "15"))

# Background Watchlist Task
_background_task_handle = None


async def _run_watchlist_rescan_loop():
    """Periodic background rescan of active watchlist items."""
    while True:
        try:
            await asyncio.sleep(WATCHLIST_INTERVAL_MINUTES * 60)
            db = SessionLocal()
            try:
                items = db.query(WatchlistItem).filter(WatchlistItem.active == True).all()
                for item in items:
                    try:
                        # Stagger slightly to respect rate limits
                        await asyncio.sleep(2)
                        await watchlist.perform_watchlist_rescan(item, db)
                    except Exception:
                        db.rollback()
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _background_task_handle
    # Purge expired geolocation cache entries on startup (24h TTL)
    try:
        startup_db = SessionLocal()
        from .services.geolocation import purge_expired_cache
        purge_expired_cache(startup_db, max_age_hours=24)
        startup_db.close()
    except Exception:
        pass

    # Retention purge job: runs on startup, then every 24 hours via APScheduler
    retention_scheduler = BackgroundScheduler()
    try:
        from .services.retention import purge_expired
        purge_expired()
        retention_scheduler.add_job(purge_expired, "interval", hours=24)
        retention_scheduler.start()
    except Exception:
        pass

    _background_task_handle = asyncio.create_task(_run_watchlist_rescan_loop())
    start_gmail_polling_worker()
    yield
    shutdown_gmail_polling_worker()
    try:
        retention_scheduler.shutdown(wait=False)
    except Exception:
        pass
    if _background_task_handle:
        _background_task_handle.cancel()


app = FastAPI(
    title="ThreatLens API",
    description="Explainable threat intelligence layer for security decisions.",
    version="1.0.0",
    lifespan=lifespan,
)

# Session cookie middleware (auto-attaches tl_session cookie to incoming/outgoing traffic)
@app.middleware("http")
async def session_cookie_middleware(request: Request, call_next):
    header_val = request.headers.get("X-Session-ID")
    cookie_val = request.cookies.get(COOKIE_NAME)
    had_cookie = bool(cookie_val)
    session_id = header_val or cookie_val or str(uuid.uuid4())
    request.state.session_id = session_id

    response = await call_next(request)

    # Attach/refresh tl_session cookie on outgoing response unless dev header override
    if not header_val:
        set_session_cookie(response, session_id, request)
    return response


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(analyze.router)
app.include_router(auth.router)
app.include_router(inbox.router)
app.include_router(history.router)
app.include_router(watchlist.router)
app.include_router(demo.router)
app.include_router(forensics.router)


# Global Error Format Handler: {error: {code, message}}
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail},
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "HTTP_ERROR", "message": str(exc.detail)}},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    first_err = exc.errors()[0] if exc.errors() else {}
    msg = first_err.get("msg", "Invalid request parameters.")
    field = ".".join(str(loc) for loc in first_err.get("loc", []))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": {"code": "VALIDATION_ERROR", "message": f"{field}: {msg}"}},
    )


@app.get("/api/health", response_model=HealthResponse)
def health_check():
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    sb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    abuse_key = os.getenv("ABUSECH_AUTH_KEY", "")

    configured_sources = {
        "virustotal": bool(vt_key),
        "google_safe_browsing": bool(sb_key),
        "urlhaus": bool(abuse_key),
        "openphish": True,  # Keyless / public feed
        "rdap": True,       # Keyless open protocol
        "dns": True,        # Keyless standard socket
        "crtsh": True,      # Keyless open CT log
    }

    demo_mode = not bool(vt_key)

    return HealthResponse(
        status="ok",
        configured_sources=configured_sources,
        demo_mode=demo_mode,
        timestamp=datetime.utcnow().isoformat(),
    )


@app.get("/api/health/config", response_model=HealthConfigResponse)
def health_config():
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    sb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    abuse_key = os.getenv("ABUSECH_AUTH_KEY", "")

    sources = {
        "virustotal": {"configured": bool(vt_key), "type": "keyed"},
        "google_safe_browsing": {"configured": bool(sb_key), "type": "keyed"},
        "urlhaus": {"configured": bool(abuse_key), "type": "keyed"},
        "openphish": {"configured": True, "type": "keyless"},
        "rdap": {"configured": True, "type": "keyless"},
        "dns": {"configured": True, "type": "keyless"},
        "crtsh": {"configured": True, "type": "keyless"},
    }

    groq_configured = bool(os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY"))
    cf_configured = bool(os.getenv("CLOUDFLARE_ACCOUNT_ID") and os.getenv("CLOUDFLARE_API_TOKEN"))
    mistral_configured = bool(os.getenv("MISTRAL_API_KEY"))

    llm = {
        "primary": {"provider": "groq", "configured": groq_configured},
        "fallback_1": {"provider": "cloudflare", "configured": cf_configured},
        "fallback_2": {"provider": "mistral", "configured": mistral_configured},
    }

    demo_mode = not bool(vt_key)

    return HealthConfigResponse(
        sources=sources,
        llm=llm,
        demo_mode=demo_mode,
    )
