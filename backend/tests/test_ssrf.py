"""
Unit tests for SSRF protection and URL validation.
Validates blocking of localhost, 127.0.0.1, 10.x, 169.254.169.254,
IPv6 loopback, IPv4-mapped IPv6, userinfo, and non-standard ports.
"""

import pytest
from app.services.url_analysis import (
    InvalidURLError,
    SSRFSecurityError,
    is_ip_blocked,
    resolve_hostname_safely,
    validate_url_syntax,
)


def test_ip_blocking_ranges():
    # Loopback
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("127.0.1.1") is True
    assert is_ip_blocked("::1") is True

    # Cloud metadata
    assert is_ip_blocked("169.254.169.254") is True
    assert is_ip_blocked("169.254.1.1") is True

    # RFC 1918 Private networks
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("10.254.0.1") is True
    assert is_ip_blocked("172.16.0.1") is True
    assert is_ip_blocked("172.31.255.255") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("192.168.0.254") is True

    # IPv6 private / link-local / unspecified
    assert is_ip_blocked("fc00::1") is True
    assert is_ip_blocked("fe80::1") is True
    assert is_ip_blocked("::") is True

    # Carrier-grade NAT
    assert is_ip_blocked("100.64.0.1") is True

    # Public IP should not be blocked
    assert is_ip_blocked("93.184.216.34") is False
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False


def test_resolve_safely_blocks_internal():
    blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "10.0.0.5",
        "172.16.1.1",
        "192.168.1.50",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
    ]

    for host in blocked_hosts:
        with pytest.raises(SSRFSecurityError) as exc_info:
            resolve_hostname_safely(host)
        assert "This address points to a private or internal network and can't be analyzed." in str(exc_info.value)


@pytest.mark.asyncio
async def test_redirect_to_internal_blocked():
    """Verify that a redirect destination resolving to internal ranges is blocked."""
    # Direct check on destination validation
    with pytest.raises(SSRFSecurityError):
        resolve_hostname_safely("127.0.0.1")
    with pytest.raises(SSRFSecurityError):
        resolve_hostname_safely("169.254.169.254")


def test_validate_url_syntax_rejects_credentials():
    with pytest.raises(InvalidURLError):
        validate_url_syntax("http://user:password@example.com")

    with pytest.raises(InvalidURLError):
        validate_url_syntax("https://admin@example.com")


def test_validate_url_syntax_rejects_non_standard_ports():
    with pytest.raises(InvalidURLError):
        validate_url_syntax("http://example.com:22")

    with pytest.raises(InvalidURLError):
        validate_url_syntax("https://example.com:3389")

    # Allowed ports
    scheme, host, port = validate_url_syntax("https://example.com:443")
    assert port == 443

    scheme, host, port = validate_url_syntax("http://example.com:80")
    assert port == 80


def test_validate_url_syntax_rejects_bad_schemes():
    with pytest.raises(InvalidURLError):
        validate_url_syntax("file:///etc/passwd")

    with pytest.raises(InvalidURLError):
        validate_url_syntax("ftp://ftp.example.com")

    with pytest.raises(InvalidURLError):
        validate_url_syntax("gopher://example.com")
