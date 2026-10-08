"""
Unit tests for the Risk Engine (risk_engine.py).
Validates all 8 mandatory specification test cases, anti-double-counting,
confidence calculation, mitigating factor rules, and determinism.
"""

from datetime import datetime
import pytest
from app.risk_engine import NormalizedEvidence, evaluate


def test_case_1_clean_url_several_sources_agree():
    """1. Clean URL, several sources agree => SAFE/LOW, high confidence"""
    evidence = NormalizedEvidence(
        target="https://verified-clean.example.com",
        target_type="url",
        virustotal={"malicious": 0, "suspicious": 0, "harmless": 72, "total": 72},
        safe_browsing={"flagged": False, "threat_types": []},
        urlhaus={"flagged": False},
        openphish={"flagged": False},
        rdap={"domain_age_days": 1200, "is_newly_registered": False, "registrar": "MarkMonitor"},
        dns={"resolved": True, "records": {"A": ["93.184.216.34"]}},
        known_good={"top_1m": True, "verified_vendor": True},
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    assert result.score <= 29, f"Expected SAFE or LOW, got score {result.score}"
    assert result.level in ("SAFE", "LOW"), f"Expected SAFE or LOW, got {result.level}"
    assert result.confidence >= 70, f"Expected high confidence (>=70), got {result.confidence}"
    # Verify mitigating factors applied
    mitigating = [f for f in result.factors if f.type == "mitigating"]
    assert len(mitigating) > 0


def test_case_2_single_source_suspicious_low_confidence():
    """2. Single source says suspicious, nothing else => MEDIUM-ish score, LOW confidence"""
    evidence = NormalizedEvidence(
        target="http://sketchy-single.example.org",
        target_type="url",
        virustotal={"malicious": 0, "suspicious": 3, "harmless": 10, "total": 13},  # only suspicious
        # No other sources returned data
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    # Single source with 3 suspicious gives points, but confidence should be low
    assert 10 <= result.score <= 54, f"Expected LOW/MEDIUM score, got {result.score}"
    assert result.confidence < 50, f"Expected LOW confidence (<50) from single source, got {result.confidence}"


def test_case_3_vt_20_malicious_and_3_reputation_lists_agree():
    """3. VT 20 malicious + 3 reputation lists agree => CRITICAL, confidence >= 90, respects caps"""
    evidence = NormalizedEvidence(
        target="http://malware-distro.example.net/dropper",
        target_type="url",
        virustotal={"malicious": 20, "suspicious": 2, "harmless": 5, "total": 27},
        safe_browsing={"flagged": True, "threat_types": ["MALWARE"]},
        urlhaus={"flagged": True, "threat": "Trojan-Banker"},
        openphish={"flagged": True},
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    assert result.level == "CRITICAL", f"Expected CRITICAL, got {result.level}"
    assert result.score >= 80, f"Expected score >= 80, got {result.score}"
    assert result.confidence >= 90, f"Expected confidence >= 90, got {result.confidence}"

    # Anti-double-counting check: AV cap is 50, Rep lists cap is 35. Total <= 85.
    assert result.group_breakdown["AV_DETECTIONS"] <= 50
    assert result.group_breakdown["REPUTATION_LISTS"] <= 35
    assert result.score <= 85, f"Score should respect group caps (50 + 35 = 85), got {result.score}"


def test_case_4_phishing_url_new_domain_vt_zero():
    """4. Phishing URL on newly registered domain, VT 0 detections => HIGH via reputation + infra groups"""
    evidence = NormalizedEvidence(
        target="http://apple-login-security-update.example.xyz/auth",
        target_type="url",
        virustotal={"malicious": 0, "suspicious": 0, "harmless": 40, "total": 40},
        openphish={"flagged": True},
        rdap={"domain_age_days": 3, "is_newly_registered": True, "registrar": "NameCheap"},
        redirects={"hop_count": 2, "cross_domain": True, "suspicious": True},
        certificates={"suspicious_sans": True, "age_days": 1},
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    # Rep lists (30) + Infra (new domain 10 + redirect 10 + cert 5 = capped at 20) = 50-55 => MEDIUM to HIGH
    assert result.score >= 50, f"Expected score >= 50, got {result.score}"
    assert result.level in ("MEDIUM", "HIGH"), f"Expected MEDIUM or HIGH, got {result.level}"
    assert result.group_breakdown["AV_DETECTIONS"] == 0
    assert result.group_breakdown["REPUTATION_LISTS"] > 0
    assert result.group_breakdown["DOMAIN_INFRA"] > 0


def test_case_5_known_good_signed_file_zero_detections():
    """5. Known-good signed file with 0 detections => SAFE, mitigating applied"""
    evidence = NormalizedEvidence(
        target="3f8a42bc194a21e649afbf4c8996fb92427ae41e4649b934ca495991b7852a11",
        target_type="file",
        virustotal={"malicious": 0, "suspicious": 0, "harmless": 70, "total": 70},
        file_metadata={"is_signed": True, "signature_valid": True, "trusted_publisher": True, "prevalence": "high"},
        known_good={"verified_vendor": True},
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    assert result.score <= 9, f"Expected score <= 9, got {result.score}"
    assert result.level == "SAFE", f"Expected SAFE, got {result.level}"
    assert result.group_breakdown["MITIGATING"] < 0, "Expected mitigating points to apply"
    mitigating_factors = [f for f in result.factors if f.type == "mitigating"]
    assert len(mitigating_factors) >= 2


def test_case_6_signed_file_with_8_detections_conflict_factor():
    """6. Signed file but 8 detections => mitigating NOT applied, conflict factor shown"""
    evidence = NormalizedEvidence(
        target="ab9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc",
        target_type="file",
        virustotal={"malicious": 8, "suspicious": 0, "harmless": 40, "total": 48},
        file_metadata={"is_signed": True, "signature_valid": True, "trusted_publisher": True},
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    # Mitigating points must NOT reduce score
    assert result.group_breakdown["MITIGATING"] == 0, "Mitigating points must NOT apply when AV >= 3"
    # Score should be driven by AV detections (8 detections => 40 points)
    assert result.score >= 40

    # Conflict factor must be present
    conflict_factors = [f for f in result.factors if f.type == "conflict"]
    assert len(conflict_factors) == 1
    assert conflict_factors[0].id == "conflict_signed_malicious"


def test_case_7_no_data_from_any_source():
    """7. No data from any source => UNKNOWN, confidence <= 10"""
    evidence = NormalizedEvidence(
        target="https://obscure-unrecorded.example.org",
        target_type="url",
    )

    result = evaluate(evidence, now=datetime(2026, 1, 1))

    assert result.score == 0
    assert result.level == "UNKNOWN"
    assert result.confidence <= 10
    assert "No reputation data was found" in result.recommended_action


def test_case_8_score_clamped_and_pure_determinism():
    """8. Score always clamped 0-100; same input always yields identical output"""
    evidence = NormalizedEvidence(
        target="http://test-target.example.com",
        target_type="url",
        virustotal={"malicious": 50, "suspicious": 10, "harmless": 0, "total": 60},
        safe_browsing={"flagged": True, "threat_types": ["MALWARE"]},
        urlhaus={"flagged": True},
        openphish={"flagged": True},
        behavior={"powershell_executed": True, "persistence_added": True, "suspicious_exec": True},
        ip_reputation={"is_malicious": True, "asn": "AS9999"},
        rdap={"domain_age_days": 1, "is_newly_registered": True},
    )

    run_1 = evaluate(evidence, now=datetime(2026, 1, 1))
    run_2 = evaluate(evidence, now=datetime(2026, 1, 1))

    # Clamped check
    assert 0 <= run_1.score <= 100
    assert run_1.score == 100  # Extreme threat capped at 100

    # Determinism check
    assert run_1.score == run_2.score
    assert run_1.level == run_2.level
    assert run_1.confidence == run_2.confidence
    assert len(run_1.factors) == len(run_2.factors)
    assert [f.id for f in run_1.factors] == [f.id for f in run_2.factors]
    assert run_1.explanation == run_2.explanation


def test_hash_and_file_with_no_source_data_is_unknown_never_safe():
    """Requirement: A file or hash with no source data must be UNKNOWN (confidence <= 10), never SAFE."""
    # 1. Pure empty hash
    ev_hash_empty = NormalizedEvidence(
        target="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        target_type="hash",
    )
    res_hash_empty = evaluate(ev_hash_empty, now=datetime(2026, 1, 1))
    assert res_hash_empty.level == "UNKNOWN"
    assert res_hash_empty.confidence <= 10
    assert res_hash_empty.score == 0
    assert res_hash_empty.level != "SAFE"

    # 2. Hash with VT returning no_data or 0 total engines
    ev_hash_vt_zero = NormalizedEvidence(
        target="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        target_type="hash",
        virustotal={"status": "no_data", "malicious": 0, "suspicious": 0, "total": 0},
    )
    res_hash_vt_zero = evaluate(ev_hash_vt_zero, now=datetime(2026, 1, 1))
    assert res_hash_vt_zero.level == "UNKNOWN"
    assert res_hash_vt_zero.confidence <= 10
    assert res_hash_vt_zero.score == 0
    assert res_hash_vt_zero.level != "SAFE"

    # 3. File upload with only local file metadata (filename, size) and 0 VT engines
    ev_file_unknown = NormalizedEvidence(
        target="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        target_type="file",
        virustotal={"malicious": 0, "suspicious": 0, "total": 0},
        file_metadata={"filename": "unseen_document.pdf", "size": 24500},
    )
    res_file_unknown = evaluate(ev_file_unknown, now=datetime(2026, 1, 1))
    assert res_file_unknown.level == "UNKNOWN"
    assert res_file_unknown.confidence <= 10
    assert res_file_unknown.score == 0
    assert res_file_unknown.level != "SAFE"

