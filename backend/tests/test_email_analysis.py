"""
Integration and forensic unit tests for Email Analysis (Phase 7 / 7.5).
Tests:
- Valid .eml with passing SPF/DKIM/DMARC
- Phishing-style .eml with failed SPF and mismatched Reply-To
- Malformed .eml (missing headers, graceful handling)
- HTML body with tracking pixel & scripts (sanitization)
- Attachment SHA-256 verification (in-memory stream hashing)
- Header injection: <script> tags in headers escaped in output
- Strict privacy: No temp files or payloads persisted to disk
- Invariant: detection_count <= total_engines always
- Email target is Message-ID (fallback to sha256)
- Zero real brands in fixtures
"""

import base64
import hashlib
import io
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app
from app.services.email_auth import parse_authentication_results
from app.services.email_headers import analyze_headers
from app.services.email_parser import parse_email
from app.services.html_sanitizer import sanitize_html


from unittest.mock import AsyncMock, patch
from app.services.llm_reasoner import LLMResult


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def mock_llm_reasoning():
    mock_res = LLMResult(
        summary="ThreatLens AI analysis: Email evaluated against RFC authentication and infrastructure signals.",
        provider_used="groq",
        latency_ms=45,
        cache_hit=False,
        raw_response="ThreatLens AI analysis: Email evaluated against RFC authentication and infrastructure signals.",
        anonymized_prompt="Anonymized prompt evidence",
    )
    with patch("app.services.email_forensics.reason", new=AsyncMock(return_value=mock_res)):
        yield


@pytest.fixture
def client():
    return TestClient(app)


VALID_EML = b"""From: security@example-corp.test
To: victim@example.test
Subject: Official Security Update
Date: Fri, 09 Oct 2026 10:00:00 +0000
Message-ID: <valid-12345@example-corp.test>
Authentication-Results: mx.mail-receiver.example.org;
       dkim=pass header.i=@example-corp.test header.s=202601;
       spf=pass (mail-receiver.example.org: domain of security@example-corp.test designates 192.0.2.1 as permitted sender) smtp.mailfrom=security@example-corp.test;
       dmarc=pass (p=REJECT sp=REJECT) header.from=example-corp.test;
       arc=pass
Received: from mail.example-corp.test ([192.0.2.1]) by mx.mail-receiver.example.org with ESMTPS; Fri, 09 Oct 2026 10:00:00 +0000
Content-Type: text/plain

Your Example Corp account security settings are up to date.
"""

PHISHING_EML = b"""From: service@example-corp.test
Reply-To: credential-harvest@evil-phishing-host.test
Subject: Urgent: Verify Your Account Immediately!
Date: Fri, 09 Oct 2026 10:00:00 +0000
Message-ID: <phish-999@evil-phishing-host.test>
Authentication-Results: mx.mail-receiver.example.org;
       dkim=fail;
       spf=fail (mail-receiver.example.org: domain of service@example-corp.test does not designate 198.51.100.99 as permitted sender) smtp.mailfrom=spoof@evil-phishing-host.test;
       dmarc=fail (p=REJECT) header.from=example-corp.test;
       arc=none
Received: from c2.evil-phishing-host.test ([198.51.100.99]) by mx.mail-receiver.example.org with ESMTP; Fri, 09 Oct 2026 10:00:00 +0000
Content-Type: text/plain

Click here to restore account access immediately.
"""

MALFORMED_EML = b"Corrupted raw stream with no RFC headers\x00\xff\xfe\x12\x34Just random words without delimiter."

TRACKING_PIXEL_EML = b"""From: newsletter@newsletter.example.test
To: user@example.test
Subject: Monthly Newsletter
Date: Fri, 09 Oct 2026 10:00:00 +0000
Message-ID: <news-456@newsletter.example.test>
Authentication-Results: mx.mail-receiver.example.org; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/html

<html>
<body>
  <h1>Newsletter</h1>
  <p style="color: blue; font-size: 14px;">Welcome to our update!</p>
  <img src="http://email-tracker.marketing.example.test/pixel.gif?uid=998877" width="1" height="1" alt="" />
  <script>alert('malicious_script_execution')</script>
  <iframe src="http://tracker.example.test/beacon"></iframe>
</body>
</html>
"""

ATTACHMENT_CONTENT = b"ThreatLens Attachment Test Payload - Stream Hash Verification"
ATTACHMENT_B64 = base64.b64encode(ATTACHMENT_CONTENT).decode("ascii")

ATTACHMENT_EML = f"""From: hr@example-company.test
To: employee@example-company.test
Subject: Quarterly Compensation Review
Date: Fri, 09 Oct 2026 10:00:00 +0000
Message-ID: <att-123@example-company.test>
Authentication-Results: mx.mail-receiver.example.org; spf=pass; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary-threatlens-99"

--boundary-threatlens-99
Content-Type: text/plain

Please find compensation statement attached.

--boundary-threatlens-99
Content-Type: text/plain; name="statement.txt"
Content-Disposition: attachment; filename="statement.txt"
Content-Transfer-Encoding: base64

{ATTACHMENT_B64}
--boundary-threatlens-99--
""".encode("utf-8")

HEADER_INJECTION_EML = b"""From: <script>alert('from_injection')</script>@example.test
To: victim@example.test
Subject: <script>alert('subject_injection')</script>
X-Mailer: <script>alert('xmailer_injection')</script>
X-Spam-Status: No, score=0.0 <script>alert('spam_status')</script>
Date: Fri, 09 Oct 2026 10:00:00 +0000
Message-ID: <xss-injection-1@example.test>
Content-Type: text/plain

Header injection test content.
"""


def test_valid_email_auth_and_parse(client):
    """Fixture: a valid .eml with passing SPF/DKIM/DMARC and Message-ID target."""
    files = {"file": ("valid.eml", io.BytesIO(VALID_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["target_type"] == "email"
    # Target must be Message-ID
    assert data["target"] == "<valid-12345@example-corp.test>"
    assert data["subject"] == "Official Security Update"
    assert data["auth_result"]["spf"] == "pass"
    assert data["auth_result"]["dkim"] == "pass"
    assert data["auth_result"]["dmarc"] == "pass"
    assert data["auth_result"]["arc"] == "pass"
    assert data["risk_score"] <= 10
    assert data["risk_level"] in ("SAFE", "LOW")
    assert any("Cryptographic Email Authentication" in f["title"] for f in data["factors"])


def test_phishing_email_detection(client):
    """Fixture: a phishing-style .eml with failed SPF, mismatched Reply-To, and Message-ID target."""
    files = {"file": ("phish.eml", io.BytesIO(PHISHING_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Target must be Message-ID
    assert data["target"] == "<phish-999@evil-phishing-host.test>"
    assert data["subject"] == "Urgent: Verify Your Account Immediately!"
    assert data["auth_result"]["spf"] == "fail"
    assert data["auth_result"]["dmarc"] == "fail"
    assert data["header_analysis"]["sender_reply_to_mismatch"] is True
    assert data["risk_level"] in ("CRITICAL", "HIGH")
    assert data["risk_score"] >= 55
    # Verify indicator factors
    indicator_titles = [f["title"] for f in data["factors"] if f["type"] == "indicator"]
    assert any("SPF" in t for t in indicator_titles)
    assert any("DMARC" in t for t in indicator_titles)
    assert any("Mismatch" in t or "Spoof" in t for t in indicator_titles)


def test_malformed_email_graceful_handling(client):
    """Fixture: a malformed .eml (missing headers) — fallback to sha256 target, never crash."""
    files = {"file": ("corrupt.eml", io.BytesIO(MALFORMED_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["parse_result"]["is_malformed"] is True
    # Target must fallback to SHA-256 of (sender + subject + date)
    assert len(data["target"]) == 64
    assert data["auth_result"]["spf"] == "none"
    assert data["auth_result"]["dkim"] == "none"
    assert data["auth_result"]["dmarc"] == "none"
    assert data["total_engines"] == 0
    assert data["detection_count"] == 0
    # Never crashes, returns UNKNOWN risk
    assert data["risk_level"] in ("UNKNOWN", "SAFE", "LOW")


def test_detection_count_le_total_engines_always(client):
    """
    Acceptance criterion 1:
    Never allow detection_count > total_engines across any email analysis.
    total_engines is set to the number of signals evaluated (auth checks + hops + attachments) or 0.
    """
    test_cases = [
        ("valid.eml", VALID_EML),
        ("phishing.eml", PHISHING_EML),
        ("malformed.eml", MALFORMED_EML),
        ("tracking.eml", TRACKING_PIXEL_EML),
        ("attachment.eml", ATTACHMENT_EML),
        ("injection.eml", HEADER_INJECTION_EML),
    ]

    for name, raw_bytes in test_cases:
        files = {"file": (name, io.BytesIO(raw_bytes), "message/rfc822")}
        resp = client.post("/api/analyze/email", files=files)
        assert resp.status_code == 200, f"Failed on {name}: {resp.text}"
        data = resp.json()

        det_count = data["detection_count"]
        tot_engines = data["total_engines"]

        # Strict invariant assertion
        assert det_count <= tot_engines, (
            f"Invariant violated on {name}: detection_count ({det_count}) > total_engines ({tot_engines})"
        )
        assert tot_engines >= 0


def test_tracking_pixel_and_html_sanitization(client):
    """Fixture: an .eml with an HTML body containing a tracking pixel & scripts."""
    files = {"file": ("tracking.eml", io.BytesIO(TRACKING_PIXEL_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    sanitized = data["sanitized_html"]
    assert sanitized is not None
    # Remote image tracking pixel must be completely stripped
    assert "<img" not in sanitized
    assert "pixel.gif" not in sanitized
    # Scripts and iframes must be completely stripped
    assert "<script" not in sanitized
    assert "alert" not in sanitized
    assert "<iframe" not in sanitized
    # Safe structure and styles must be preserved
    assert "Newsletter" in sanitized
    assert "color: blue" in sanitized


def test_attachment_sha256_computed_correctly(client):
    """Test: attachment SHA-256 computed correctly in memory."""
    expected_hash = hashlib.sha256(ATTACHMENT_CONTENT).hexdigest()
    expected_size = len(ATTACHMENT_CONTENT)

    files = {"file": ("attachment.eml", io.BytesIO(ATTACHMENT_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    attachments = data["parse_result"]["attachments"]
    assert len(attachments) == 1
    att = attachments[0]
    assert att["filename"] == "statement.txt"
    assert att["sha256"] == expected_hash
    assert att["size_bytes"] == expected_size


def test_header_injection_escaped(client):
    """Test: header injection — a header value containing <script> is escaped in output."""
    files = {"file": ("injection.eml", io.BytesIO(HEADER_INJECTION_EML), "message/rfc822")}
    resp = client.post("/api/analyze/email", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Raw '<script>' must NOT appear unescaped in parse_result or headers
    parse_res = data["parse_result"]
    headers = parse_res["headers"]

    # Subject must be escaped
    assert "<script>" not in (parse_res.get("subject") or "")
    assert "&lt;script&gt;" in (parse_res.get("subject") or "")

    # Headers must be escaped
    x_mailer = headers.get("X-Mailer") or headers.get("x-mailer")
    assert "<script>" not in str(x_mailer)
    assert "&lt;script&gt;" in str(x_mailer)


def test_no_temp_files_written_to_disk(client):
    """Test: no file written to disk (assert no temp files left behind)."""
    tmp_dir = tempfile.gettempdir()
    before_tmp_files = set(os.listdir(tmp_dir))
    workspace_dir = os.getcwd()
    before_workspace_files = set(os.listdir(workspace_dir))

    # Send multiple requests with emails and attachments
    for sample in (VALID_EML, PHISHING_EML, ATTACHMENT_EML, TRACKING_PIXEL_EML):
        files = {"file": ("test.eml", io.BytesIO(sample), "message/rfc822")}
        resp = client.post("/api/analyze/email", files=files)
        assert resp.status_code == 200

    after_tmp_files = set(os.listdir(tmp_dir))
    after_workspace_files = set(os.listdir(workspace_dir))

    # Assert no new files in /tmp or workspace
    new_tmp = after_tmp_files - before_tmp_files
    new_workspace = after_workspace_files - before_workspace_files

    assert len(new_tmp) == 0, f"Leaked temporary files in {tmp_dir}: {new_tmp}"
    assert len(new_workspace) == 0, f"Leaked temporary files in {workspace_dir}: {new_workspace}"


def test_sender_ips_hop_ordered_and_deduplicated():
    """Test: sender IPs in parse result are hop-ordered (closest relay first) and deduplicated."""
    sample_multi_hop = (
        b"From: sender@example-corp.test\r\n"
        b"To: victim@example.test\r\n"
        b"Subject: Multi-Hop Test\r\n"
        b"Message-ID: <multi-hop@example-corp.test>\r\n"
        b"X-Originating-IP: [103.21.244.2]\r\n"
        b"Received: from relay3.internal ([192.168.1.1]) by final.gateway ([10.0.0.1]); Fri, 09 Oct 2026 10:03:00 +0000\r\n"
        b"Received: from relay2.public ([198.51.100.22]) by relay3.internal ([192.168.1.1]); Fri, 09 Oct 2026 10:02:00 +0000\r\n"
        b"Received: from hop1.client ([203.0.113.10]) by relay2.public ([198.51.100.22]); Fri, 09 Oct 2026 10:01:00 +0000\r\n"
        b"Received: from hop1.client ([203.0.113.10]) by hop1.client ([203.0.113.10]); Fri, 09 Oct 2026 10:00:00 +0000\r\n\r\n"
        b"Multi-hop body\r\n"
    )
    result = parse_email(sample_multi_hop)
    assert result.sender_ips == ["103.21.244.2", "203.0.113.10", "198.51.100.22", "192.168.1.1"]

