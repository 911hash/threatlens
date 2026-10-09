"""
PII Anonymization Service.
Strips email addresses, telephone numbers, and URLs from text before transmission to LLMs.
Enforces strict zero-leakage invariant: zero '@' and zero 'http' in output.
Mapping dictionary stays strictly on the server and is never transmitted or logged.
"""

import re
from typing import Dict, Tuple

# Regex definitions
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.IGNORECASE)
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|"
    r"\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
)
URL_REGEX = re.compile(r"(?:https?://|ftp://|hxxps?://)[^\s<>'\"`]+|www\.[^\s<>'\"`]+", re.IGNORECASE)


def anonymize(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Anonymize PII in order:
    1. emails -> [EMAIL_1], [EMAIL_2], ...
    2. phones -> [PHONE_1], ...
    3. URLs   -> [URL_1], ...

    Returns (anonymized_text, mapping).
    """
    if not text:
        return "", {}

    mapping: Dict[str, str] = {}
    current_text = text

    # 1. Emails
    email_counter = 1
    found_emails = EMAIL_REGEX.findall(current_text)
    for raw_email in found_emails:
        clean_email = raw_email.strip(".,;:()[]{}<>")
        if clean_email and clean_email not in mapping:
            tag = f"[EMAIL_{email_counter}]"
            mapping[clean_email] = tag
            email_counter += 1
            current_text = current_text.replace(clean_email, tag)

    # 2. Phones
    phone_counter = 1
    found_phones = PHONE_REGEX.findall(current_text)
    for raw_phone in found_phones:
        clean_phone = raw_phone.strip(".,;:()[]{}<>")
        # Ensure it's not a year like 2026 or a small number
        digits = re.sub(r"\D", "", clean_phone)
        if len(digits) >= 7 and clean_phone not in mapping:
            tag = f"[PHONE_{phone_counter}]"
            mapping[clean_phone] = tag
            phone_counter += 1
            current_text = current_text.replace(clean_phone, tag)

    # 3. URLs
    url_counter = 1
    found_urls = URL_REGEX.findall(current_text)
    for raw_url in found_urls:
        clean_url = raw_url.strip(".,;:()[]{}<>")
        if clean_url and clean_url not in mapping:
            tag = f"[URL_{url_counter}]"
            mapping[clean_url] = tag
            url_counter += 1
            current_text = current_text.replace(clean_url, tag)

    # Final sanitization guard: ensure zero '@' and zero 'http' survive
    if "@" in current_text:
        # Catch any residual email fragment
        def _replace_residual_at(m):
            nonlocal email_counter
            tag = f"[EMAIL_{email_counter}]"
            email_counter += 1
            return tag
        current_text = re.sub(r"\S*@\S*", _replace_residual_at, current_text)

    if re.search(r"https?", current_text, re.IGNORECASE):
        # Catch any residual http/https protocol prefix
        def _replace_residual_http(m):
            nonlocal url_counter
            tag = f"[URL_{url_counter}]"
            url_counter += 1
            return tag
        current_text = re.sub(r"https?://\S*", _replace_residual_http, current_text, flags=re.IGNORECASE)
        # Any standalone http token
        current_text = re.sub(r"\bhttps?\b", "[URL_HTTP]", current_text, flags=re.IGNORECASE)

    return current_text, mapping
