"""
Provider-agnostic LLM integration clients.
Supports Groq, Cloudflare Workers AI, and Mistral with unified calling interface and error handling.
"""

from abc import ABC, abstractmethod
import logging
import os
import time
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# Module-level timestamp to throttle Mistral API calls to 1.1s minimum gap
_last_mistral_call: float = 0.0


class LLMProviderError(Exception):
    """Raised when an LLM provider request fails, times out, or returns invalid payload."""

    def __init__(self, message: str, status_code: Optional[int] = None, is_rate_limit: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.is_rate_limit = is_rate_limit or (status_code == 429)


class LLMProvider(ABC):
    """Abstract Base Class for LLM providers."""

    name: str = "base"

    @abstractmethod
    async def call(self, system_prompt: str, user_prompt: str) -> str:
        """Execute chat completion / generate content call and return generated plain text."""
        pass


class GroqProvider(LLMProvider):
    """
    Groq Cloud API provider (OpenAI chat/completions compatible).
    Endpoint: https://api.groq.com/openai/v1/chat/completions
    """

    name: str = "groq"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY", "") or os.getenv("GROQ_API_KEY", "")
        self.model = model or os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
        self.endpoint = "https://api.groq.com/openai/v1/chat/completions"

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            raise LLMProviderError("Groq API key is missing", status_code=401)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.endpoint, json=payload, headers=headers)
                if resp.status_code == 429:
                    raise LLMProviderError("Groq rate limit exceeded (429)", status_code=429, is_rate_limit=True)
                if resp.status_code != 200:
                    raise LLMProviderError(
                        f"Groq API returned error status {resp.status_code}: {resp.text[:200]}",
                        status_code=resp.status_code,
                    )
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return content.strip()
        except LLMProviderError:
            raise
        except (httpx.TimeoutException, httpx.RequestError) as e:
            raise LLMProviderError(f"Groq network or timeout failure: {str(e)}")
        except Exception as e:
            raise LLMProviderError(f"Failed to parse Groq response: {str(e)}")


class CloudflareAIProvider(LLMProvider):
    """
    Cloudflare Workers AI provider.
    Endpoint: https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}
    """

    name: str = "cloudflare"

    def __init__(
        self,
        account_id: Optional[str] = None,
        api_token: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.account_id = account_id or os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
        self.api_token = api_token or os.getenv("CLOUDFLARE_API_TOKEN", "")
        self.model = model or os.getenv("CLOUDFLARE_AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        if not self.account_id or not self.api_token:
            raise LLMProviderError("Cloudflare Workers AI credentials missing", status_code=401)

        endpoint = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/ai/run/{self.model}"
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 512,
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(endpoint, json=payload, headers=headers)
                if resp.status_code == 429:
                    raise LLMProviderError(
                        "Cloudflare Workers AI rate limit exceeded (429)",
                        status_code=429,
                        is_rate_limit=True,
                    )
                if resp.status_code != 200:
                    raise LLMProviderError(
                        f"Cloudflare API returned error status {resp.status_code}: {resp.text[:200]}",
                        status_code=resp.status_code,
                    )
                data = resp.json()
                if "result" not in data or "response" not in data["result"]:
                    raise LLMProviderError("Cloudflare response missing 'result.response' field")
                return str(data["result"]["response"]).strip()
        except LLMProviderError:
            raise
        except (httpx.TimeoutException, httpx.RequestError) as e:
            raise LLMProviderError(f"Cloudflare network or timeout failure: {str(e)}")
        except Exception as e:
            raise LLMProviderError(f"Failed to parse Cloudflare response: {str(e)}")


class MistralProvider(LLMProvider):
    """
    Mistral AI provider (OpenAI chat/completions compatible).
    Endpoint: https://api.mistral.ai/v1/chat/completions
    Enforces a 1.1s minimum gap between calls.
    """

    name: str = "mistral"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("MISTRAL_API_KEY", "")
        self.model = model or os.getenv("MISTRAL_MODEL", "mistral-small-latest")
        self.endpoint = "https://api.mistral.ai/v1/chat/completions"

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            raise LLMProviderError("Mistral API key is missing", status_code=401)

        # Rate limit: enforce 1.1s minimum gap between calls
        global _last_mistral_call
        now = time.time()
        elapsed = now - _last_mistral_call
        if _last_mistral_call > 0 and elapsed < 1.1:
            diff = 1.1 - elapsed
            time.sleep(diff)
        _last_mistral_call = time.time()

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.endpoint, json=payload, headers=headers)
                if resp.status_code == 429:
                    raise LLMProviderError("Mistral rate limit exceeded (429)", status_code=429, is_rate_limit=True)
                if resp.status_code != 200:
                    raise LLMProviderError(
                        f"Mistral API returned error status {resp.status_code}: {resp.text[:200]}",
                        status_code=resp.status_code,
                    )
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return content.strip()
        except LLMProviderError:
            raise
        except (httpx.TimeoutException, httpx.RequestError) as e:
            raise LLMProviderError(f"Mistral network or timeout failure: {str(e)}")
        except Exception as e:
            raise LLMProviderError(f"Failed to parse Mistral response: {str(e)}")


def get_provider_by_name(name: str) -> Optional[LLMProvider]:
    """Factory helper to instantiate provider by name."""
    clean_name = name.strip().lower()
    if clean_name == "groq":
        return GroqProvider()
    elif clean_name in ("cloudflare", "cloudflare_ai", "cloudflare-ai"):
        return CloudflareAIProvider()
    elif clean_name == "mistral":
        return MistralProvider()
    return None
