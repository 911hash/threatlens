"""
Comprehensive tests for Provider-Agnostic LLM Reasoning (Phase 9 Part B & Phase 9.1).
Tests:
1. PII Anonymizer strips all emails, phones, and URLs from phishing fixture (zero @ and zero http survive).
2. Primary provider (Groq) succeeds -> response cached, provider_used='groq'.
3. Groq 429 rate limit triggers fallback to Cloudflare Workers AI -> provider_used='cloudflare'.
4. Groq and Cloudflare fail -> Mistral succeeds -> provider_used='mistral'.
5. All providers fail -> raises HTTPException(503, 'AI reasoning unavailable').
6. Mistral rate limiting sleeps 1.1s minimum gap between back-to-back calls.
7. /api/analyze/email endpoint propagates 503 when AI reasoning fails (no template fallback).
"""

import asyncio
from datetime import datetime
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import LLMCache
from app.services.llm_providers import (
    CloudflareAIProvider,
    GroqProvider,
    LLMProviderError,
    MistralProvider,
)
import app.services.llm_providers as llm_providers_module
from app.services.llm_reasoner import LLMResult, reason
from app.services.pii_anonymizer import anonymize


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
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
def clean_llm_cache(db_session):
    db_session.query(LLMCache).delete()
    db_session.commit()
    yield
    db_session.query(LLMCache).delete()
    db_session.commit()


PHISHING_BODY_FIXTURE = """
Dear valued customer,

We detected unauthorized activity on your account. Please confirm your identity immediately:
Contact support at security-team@fake-corp-update.test or verification-alert@phish-domain.co.uk.
Direct verification hotline: +1 (555) 234-5678 or 555-876-5432.
Click the secure portal below:
https://secure-login.fake-corp-update.test/auth?token=998877&redirect=http://portal.account.test/login
Urgent: Do not ignore this email.
"""


# =====================================================================
# 1. PII ANONYMIZER INVARIANT TESTS
# =====================================================================

def test_pii_anonymizer_strips_all_pii_zero_leakage():
    """Anonymizer replaces emails, phones, and URLs, leaving zero '@' and zero 'http'."""
    anonymized_text, mapping = anonymize(PHISHING_BODY_FIXTURE)

    # Invariant 1: Zero '@' symbols survive
    assert "@" not in anonymized_text, f"Leaked '@' found: {anonymized_text}"

    # Invariant 2: Zero 'http' (case-insensitive) survive
    assert "http" not in anonymized_text.lower(), f"Leaked 'http' found: {anonymized_text}"

    # Invariant 3: Structured replacement tokens present
    assert "[EMAIL_1]" in anonymized_text
    assert "[EMAIL_2]" in anonymized_text
    assert "[PHONE_1]" in anonymized_text
    assert "[URL_1]" in anonymized_text

    # Invariant 4: Mapping exists and contains original PII
    assert "security-team@fake-corp-update.test" in mapping
    assert mapping["security-team@fake-corp-update.test"] == "[EMAIL_1]"
    assert any("555" in k for k in mapping)
    assert any("http" in k for k in mapping)


# =====================================================================
# 2. PRIMARY PROVIDER (GROQ) SUCCESS & CACHE PERSISTENCE
# =====================================================================

@pytest.mark.asyncio
async def test_groq_primary_success_and_cached(db_session):
    """When Groq succeeds, returns provider_used='groq', cache_hit=False, and persists to llm_cache."""
    mock_groq = MagicMock(spec=GroqProvider)
    mock_groq.name = "groq"
    mock_groq.call = AsyncMock(return_value="Email displays legitimate SPF and DKIM authentication signatures.")

    evidence = {"from_domain": "legit.test", "auth": {"spf": "pass"}}
    body = "Quarterly investor presentation."

    result = await reason(
        evidence=evidence,
        body_excerpt=body,
        db=db_session,
        provider_override=[mock_groq],
    )

    assert result.provider_used == "groq"
    assert "legitimate SPF and DKIM" in result.summary
    assert result.cache_hit is False
    assert "[URL_" not in result.summary
    mock_groq.call.assert_awaited_once()

    # Second call with identical input MUST hit cache and make ZERO additional calls
    result_cache_hit = await reason(
        evidence=evidence,
        body_excerpt=body,
        db=db_session,
        provider_override=[mock_groq],
    )
    assert result_cache_hit.cache_hit is True
    assert result_cache_hit.provider_used == "groq"
    assert result_cache_hit.summary == result.summary
    # Still only called once
    mock_groq.call.assert_awaited_once()


# =====================================================================
# 3. RATE LIMIT 429 FALLBACK: GROQ 429 -> CLOUDFLARE 200
# =====================================================================

@pytest.mark.asyncio
async def test_groq_429_falls_back_to_cloudflare(db_session):
    """Groq returning 429 falls back to Cloudflare Workers AI, returning provider_used='cloudflare'."""
    mock_groq = MagicMock(spec=GroqProvider)
    mock_groq.name = "groq"
    mock_groq.call = AsyncMock(side_effect=LLMProviderError("Rate limit exceeded", status_code=429, is_rate_limit=True))

    mock_cloudflare = MagicMock(spec=CloudflareAIProvider)
    mock_cloudflare.name = "cloudflare"
    mock_cloudflare.call = AsyncMock(return_value="Suspicious credential harvesting links detected by Cloudflare Workers AI.")

    evidence = {"unique_id": "test_cloudflare_fallback", "domain": "phish-corp.test"}

    with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        result = await reason(
            evidence=evidence,
            body_excerpt="Click here immediately: https://phish-corp.test/login",
            db=db_session,
            provider_override=[mock_groq, mock_cloudflare],
        )

        assert result.provider_used == "cloudflare"
        assert "Cloudflare" in result.summary
        assert mock_groq.call.await_count == 2  # Initial attempt + 1 retry after 429
        mock_sleep.assert_awaited_once_with(4)
        mock_cloudflare.call.assert_awaited_once()


# =====================================================================
# 4. MULTI-PROVIDER FALLBACK CHAIN: GROQ + CLOUDFLARE -> MISTRAL
# =====================================================================

@pytest.mark.asyncio
async def test_cloudflare_429_falls_back_to_mistral(db_session):
    """When Groq and Cloudflare fail, fallback chain reaches Mistral successfully."""
    mock_groq = MagicMock(spec=GroqProvider)
    mock_groq.name = "groq"
    mock_groq.call = AsyncMock(side_effect=LLMProviderError("Groq 429", status_code=429, is_rate_limit=True))

    mock_cloudflare = MagicMock(spec=CloudflareAIProvider)
    mock_cloudflare.name = "cloudflare"
    mock_cloudflare.call = AsyncMock(side_effect=LLMProviderError("Cloudflare 429", status_code=429, is_rate_limit=True))

    mock_mistral = MagicMock(spec=MistralProvider)
    mock_mistral.name = "mistral"
    mock_mistral.call = AsyncMock(return_value="Mistral analysis: Tor exit relay detected with spoofed From header.")

    evidence = {"unique_id": "test_mistral_fallback", "sender_ip": "198.51.100.1"}

    with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        result = await reason(
            evidence=evidence,
            body_excerpt="Urgent invoice attached.",
            db=db_session,
            provider_override=[mock_groq, mock_cloudflare, mock_mistral],
        )

        assert result.provider_used == "mistral"
        assert "Mistral analysis" in result.summary
        assert mock_groq.call.await_count == 2
        assert mock_cloudflare.call.await_count == 2
        assert mock_sleep.await_count == 2
        mock_mistral.call.assert_awaited_once()


# =====================================================================
# 5. ALL THREE PROVIDERS FAIL -> HTTP 503 ERROR
# =====================================================================

@pytest.mark.asyncio
async def test_all_three_fail_raises_503(db_session):
    """When Groq 500 -> Cloudflare 500 -> Mistral 500, raises HTTPException 503."""
    mock_groq = MagicMock(spec=GroqProvider)
    mock_groq.name = "groq"
    mock_groq.call = AsyncMock(side_effect=LLMProviderError("Groq 500", status_code=500))

    mock_cloudflare = MagicMock(spec=CloudflareAIProvider)
    mock_cloudflare.name = "cloudflare"
    mock_cloudflare.call = AsyncMock(side_effect=LLMProviderError("Cloudflare 500", status_code=500))

    mock_mistral = MagicMock(spec=MistralProvider)
    mock_mistral.name = "mistral"
    mock_mistral.call = AsyncMock(side_effect=LLMProviderError("Mistral 500", status_code=500))

    evidence = {"unique_id": "test_all_three_fail_case"}

    with pytest.raises(HTTPException) as exc_info:
        await reason(
            evidence=evidence,
            body_excerpt="Test message",
            db=db_session,
            provider_override=[mock_groq, mock_cloudflare, mock_mistral],
        )

    assert exc_info.value.status_code == 503
    assert "AI reasoning unavailable" in str(exc_info.value.detail)


# =====================================================================
# 6. MISTRAL RATE LIMIT THROTTLING: 1.1s SLEEP ENFORCEMENT
# =====================================================================

@pytest.mark.asyncio
async def test_mistral_rate_limit_sleeps():
    """Patch time.sleep; call MistralProvider twice back to back; assert sleep called between 1.0 and 1.2."""
    llm_providers_module._last_mistral_call = 0.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "Mistral answer"}}]
    }

    provider = MistralProvider(api_key="test-mistral-api-key")

    with patch("time.sleep") as mock_sleep, patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
        await provider.call("system prompt", "user query 1")
        assert mock_sleep.call_count == 0

        await provider.call("system prompt", "user query 2")
        assert mock_sleep.call_count == 1
        sleep_arg = mock_sleep.call_args[0][0]
        assert 1.0 <= sleep_arg <= 1.2, f"Expected sleep between 1.0 and 1.2, got {sleep_arg}"


# =====================================================================
# 7. /api/analyze/email PROPAGATES 503 ON AI FAILURE (NO TEMPLATE FALLBACK)
# =====================================================================

def test_api_analyze_email_propagates_503_when_ai_down(client):
    """When AI reasoning fails, /api/analyze/email returns HTTP 503, not a fake success."""
    raw_email = b"""From: service@test.com
To: user@test.com
Subject: Test
Date: Fri, 09 Oct 2026 12:00:00 +0000
Message-ID: <test-503-propagate@test.com>
Content-Type: text/plain

Sample body text.
"""
    with patch("app.services.email_forensics.reason", side_effect=HTTPException(status_code=503, detail={"code": "AI_UNAVAILABLE", "message": "AI reasoning unavailable"})):
        resp = client.post(
            "/api/analyze/email",
            files={"file": ("test.eml", raw_email, "message/rfc822")},
        )
        assert resp.status_code == 503
