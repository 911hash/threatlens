"""
Background Gmail inbox polling worker using APScheduler.
Polls connected active Gmail accounts every 60s.
Skips if last_sync_at was less than 30s ago.
Logs only message counts, NEVER email addresses.
Pauses on rate-limit errors and retries in 60s.
"""

import asyncio
from datetime import datetime, timedelta
import logging
from typing import Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from ..database import SessionLocal
from ..models import GmailAccount
from ..services.gmail_sync import sync_inbox

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()
_rate_limited_until: Optional[datetime] = None


async def poll_gmail_inboxes_job():
    """
    Execute periodic background sync across active Gmail accounts.
    Runs every 60 seconds.
    """
    global _rate_limited_until

    now = datetime.utcnow()
    if _rate_limited_until and now < _rate_limited_until:
        logger.info("Gmail inbox sync queue paused due to rate limiting; will resume shortly.")
        return

    db = SessionLocal()
    try:
        active_accounts = db.query(GmailAccount).filter(GmailAccount.is_active == True).all()
        for account in active_accounts:
            if account.last_sync_at:
                elapsed = (now - account.last_sync_at).total_seconds()
                if elapsed < 30:
                    continue  # Skip if synced less than 30s ago

            try:
                synced_count = await sync_inbox(account, db, max_results=25)
                # PRIVACY RULE: Log only counts, never email addresses
                logger.info("Gmail periodic sync completed: %d new message(s) ingested", synced_count)
            except Exception as e:
                err_str = str(e).lower()
                if "429" in err_str or "rate limit" in err_str or "resource_exhausted" in err_str:
                    logger.warning("Rate limit encountered during sync. Pausing queue for 60 seconds.")
                    _rate_limited_until = datetime.utcnow() + timedelta(seconds=60)
                    break
                else:
                    logger.warning("Periodic sync failed for account ID %s: %s", account.id, type(e).__name__)
    except Exception as e:
        logger.warning("Error running poll_gmail_inboxes_job: %s", e)
    finally:
        db.close()


def start_gmail_polling_worker():
    """Start APScheduler background job if not already running."""
    if not scheduler.running:
        scheduler.add_job(
            poll_gmail_inboxes_job,
            "interval",
            seconds=60,
            id="gmail_inbox_poller",
            replace_existing=True,
        )
        scheduler.start()
        logger.info("Gmail inbox polling worker started (APScheduler, 60s interval).")


def shutdown_gmail_polling_worker():
    """Shutdown APScheduler background worker cleanly."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Gmail inbox polling worker stopped.")
