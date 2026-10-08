"""
Main FastAPI Application for ThreatLens.
Explainable threat intelligence layer.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import os
from typing import Any, Dict
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()

from .database import Base, SessionLocal, engine
from .models import Alert, Scan, WatchlistItem, generate_id
from .routes import analyze, demo, history, watchlist
from .schemas import HealthResponse
from .services.url_analysis import refang_target, trace_url_redirects, validate_url_syntax
from .services.virustotal import VT_API_KEY, lookup_virustotal_hash, lookup_virustotal_url
from .risk_engine import NormalizedEvidence, evaluate

# Create tables
Base.metadata.create_all(bind=engine)

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
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
    _background_task_handle = asyncio.create_task(_run_watchlist_rescan_loop())
    yield
    if _background_task_handle:
        _background_task_handle.cancel()


app = FastAPI(
    title="ThreatLens API",
    description="Explainable threat intelligence layer for security decisions.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(analyze.router)
app.include_router(history.router)
app.include_router(watchlist.router)
app.include_router(demo.router)


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
