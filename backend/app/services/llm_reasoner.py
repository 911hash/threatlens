"""
LLM Reasoning Service for Email Forensics.
Orchestrates primary and fallback LLM providers (Groq -> Cloudflare Workers AI -> Mistral),
enforces PII anonymization before all outbound calls,
maintains a 168h TTL SQLite cache, handles 429 rate-limiting with 4s backoff,
and raises HTTP 503 if all providers fail.
"""

import asyncio
from datetime import datetime, timedelta
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import LLMCache
from ..services.llm_providers import (
    CloudflareAIProvider,
    GroqProvider,
    MistralProvider,
    LLMProvider,
    LLMProviderError,
    get_provider_by_name,
)
from ..services.pii_anonymizer import anonymize

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security analyst. Explain why this email is or isn't suspicious in 2-4 sentences of plain English. "
    "Do not invent facts. Only reference the evidence provided. If evidence is thin, say so."
)


class LLMResult(BaseModel):
    summary: str
    provider_used: str
    latency_ms: int
    cache_hit: bool
    raw_response: str
    anonymized_prompt: str


def _get_provider_chain() -> List[LLMProvider]:
    """
    Build prioritized list of providers:
    Primary from LLM_PROVIDER, followed by LLM_FALLBACK_PROVIDERS in order.
    Skips any provider whose required credentials are missing.
    """
    primary_name = os.getenv("LLM_PROVIDER", "groq").strip().lower()
    fallback_names = [
        f.strip().lower()
        for f in os.getenv("LLM_FALLBACK_PROVIDERS", "cloudflare,mistral").split(",")
        if f.strip()
    ]

    chain_names = [primary_name] + [f for f in fallback_names if f != primary_name]
    chain: List[LLMProvider] = []

    for name in chain_names:
        provider = get_provider_by_name(name)
        if provider:
            if name in ("cloudflare", "cloudflare_ai", "cloudflare-ai"):
                if getattr(provider, "account_id", None) and getattr(provider, "api_token", None):
                    chain.append(provider)
                else:
                    logger.debug("Skipping Cloudflare provider: credentials not set")
            else:
                api_key = getattr(provider, "api_key", None)
                if api_key:
                    chain.append(provider)
                else:
                    logger.debug("Skipping LLM provider %s: API key not set", name)

    return chain


def _compute_cache_key(system_prompt: str, user_prompt: str) -> str:
    """Compute sha256 hash of system and user prompts."""
    combined = f"{system_prompt}\n{user_prompt}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


async def reason(
    evidence: Dict[str, Any],
    body_excerpt: str = "",
    db: Optional[Session] = None,
    provider_override: Optional[List[LLMProvider]] = None,
) -> LLMResult:
    """
    Generate plain-English threat reasoning using LLM provider chain.
    1. Anonymizes evidence and body text (PII scrubbing).
    2. Checks SQLite llm_cache.
    3. Tries primary provider, falls back on failure, retries on 429 with 4s sleep.
    4. Raises HTTPException(503, 'AI reasoning unavailable') if all fail.
    """
    # 1. Anonymize evidence & body text
    evidence_json = json.dumps(evidence, default=str)
    anonymized_evidence_str, _ = anonymize(evidence_json)
    anonymized_body, _ = anonymize(body_excerpt or "")

    user_prompt = f"Evidence:\n{anonymized_evidence_str}\n\n---\n\nEmail Body Excerpt:\n{anonymized_body}"
    cache_key = _compute_cache_key(SYSTEM_PROMPT, user_prompt)

    # 2. Check SQLite cache
    owns_db = False
    if db is None:
        db = SessionLocal()
        owns_db = True

    try:
        cached = db.query(LLMCache).filter(LLMCache.key == cache_key).first()
        if cached:
            # Check 168-hour TTL
            age = (datetime.utcnow() - cached.created_at).total_seconds()
            ttl_seconds = cached.ttl_hours * 3600
            if age < ttl_seconds:
                try:
                    data = json.loads(cached.response_json)
                    return LLMResult(
                        summary=data.get("summary", ""),
                        provider_used=data.get("provider_used", "cached"),
                        latency_ms=data.get("latency_ms", 0),
                        cache_hit=True,
                        raw_response=data.get("raw_response", ""),
                        anonymized_prompt=user_prompt,
                    )
                except Exception:
                    pass

        # 3. Provider Chain execution
        providers = provider_override if provider_override is not None else _get_provider_chain()
        if not providers:
            # No provider configured with valid API keys
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "AI_UNAVAILABLE", "message": "AI reasoning unavailable: no LLM providers configured."},
            )

        last_error = None
        for provider in providers:
            start_time = time.perf_counter()
            try:
                # First attempt
                logger.info("Attempting LLM reasoning via provider: %s", provider.name)
                response_text = await provider.call(SYSTEM_PROMPT, user_prompt)
                latency_ms = int((time.perf_counter() - start_time) * 1000)

                # Persist to cache
                clean_summary = response_text.strip()
                cache_payload = {
                    "summary": clean_summary,
                    "provider_used": provider.name,
                    "latency_ms": latency_ms,
                    "raw_response": response_text,
                }
                new_cache = LLMCache(
                    key=cache_key,
                    response_json=json.dumps(cache_payload),
                    created_at=datetime.utcnow(),
                    ttl_hours=168,
                )
                db.merge(new_cache)
                db.commit()

                return LLMResult(
                    summary=clean_summary,
                    provider_used=provider.name,
                    latency_ms=latency_ms,
                    cache_hit=False,
                    raw_response=response_text,
                    anonymized_prompt=user_prompt,
                )

            except LLMProviderError as e:
                last_error = e
                if e.is_rate_limit:
                    logger.warning("Provider %s hit rate limit (429). Retrying in 4s...", provider.name)
                    await asyncio.sleep(4)
                    try:
                        response_text = await provider.call(SYSTEM_PROMPT, user_prompt)
                        latency_ms = int((time.perf_counter() - start_time) * 1000)

                        clean_summary = response_text.strip()
                        cache_payload = {
                            "summary": clean_summary,
                            "provider_used": provider.name,
                            "latency_ms": latency_ms,
                            "raw_response": response_text,
                        }
                        new_cache = LLMCache(
                            key=cache_key,
                            response_json=json.dumps(cache_payload),
                            created_at=datetime.utcnow(),
                            ttl_hours=168,
                        )
                        db.merge(new_cache)
                        db.commit()

                        return LLMResult(
                            summary=clean_summary,
                            provider_used=provider.name,
                            latency_ms=latency_ms,
                            cache_hit=False,
                            raw_response=response_text,
                            anonymized_prompt=user_prompt,
                        )
                    except Exception as retry_err:
                        logger.warning("Provider %s retry failed (%s). Moving to next provider in chain.", provider.name, retry_err)
                else:
                    logger.warning("Provider %s failed (%s). Moving to next provider in chain.", provider.name, e)

        # 4. If all fail, raise 503
        logger.error("All LLM providers failed. Last error: %s", last_error)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AI_UNAVAILABLE", "message": "AI reasoning unavailable"},
        )
    finally:
        if owns_db:
            db.close()
