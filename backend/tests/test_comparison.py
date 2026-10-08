"""
Unit tests for comparison service (services/comparison.py).
Tests pure comparison calculations, factor tracking, redirect diffs, and summary templates.
"""

from app.services.comparison import compare_scans


def test_comparison_deteriorated():
    scan_a = {
        "id": "scan_01",
        "risk_score": 18,
        "risk_level": "LOW",
        "detection_count": 0,
        "factors": [
            {"id": "infra_new_domain", "title": "Newly Registered Domain", "points": 10, "severity": "medium"}
        ],
        "raw_summary": {
            "redirects": {"final_domain": "service-cdn.example-phishing-login.com", "hop_count": 0},
            "reputation_lists_flagged": [],
        },
    }

    scan_b = {
        "id": "scan_02",
        "risk_score": 82,
        "risk_level": "CRITICAL",
        "detection_count": 28,
        "factors": [
            {"id": "infra_new_domain", "title": "Newly Registered Domain", "points": 10, "severity": "medium"},
            {"id": "av_detections_hit", "title": "28 AV Engines Flagged", "points": 50, "severity": "critical"},
            {"id": "rep_openphish", "title": "OpenPhish Threat Listing", "points": 30, "severity": "high"},
        ],
        "raw_summary": {
            "redirects": {"final_domain": "malicious-delivery.phish-cdn.xyz", "hop_count": 3},
            "reputation_lists_flagged": ["OpenPhish", "URLhaus"],
        },
    }

    diff = compare_scans(scan_a, scan_b)

    assert diff["score_delta"] == 64
    assert diff["detection_delta"] == 28
    assert diff["level_change"]["from"] == "LOW"
    assert diff["level_change"]["to"] == "CRITICAL"
    assert diff["level_change"]["changed"] is True
    assert len(diff["factors_added"]) == 2
    assert [f["id"] for f in diff["factors_added"]] == ["av_detections_hit", "rep_openphish"]
    assert len(diff["factors_removed"]) == 0
    assert diff["redirect_chain_change"]["final_domain_changed"] is True
    assert diff["redirect_chain_change"]["hop_count_delta"] == 3
    assert diff["reputation_changes"]["newly_flagged"] == ["OpenPhish", "URLhaus"]
    assert diff["summary"] == "Threat profile deteriorated significantly"


def test_comparison_improved():
    scan_a = {
        "id": "scan_a",
        "risk_score": 75,
        "risk_level": "HIGH",
        "detection_count": 14,
        "factors": [
            {"id": "av_detections_hit", "title": "14 AV Engines", "points": 40, "severity": "high"}
        ],
        "raw_summary": {"reputation_lists_flagged": ["URLhaus"]},
    }
    scan_b = {
        "id": "scan_b",
        "risk_score": 15,
        "risk_level": "LOW",
        "detection_count": 0,
        "factors": [],
        "raw_summary": {"reputation_lists_flagged": []},
    }

    diff = compare_scans(scan_a, scan_b)

    assert diff["score_delta"] == -60
    assert diff["detection_delta"] == -14
    assert diff["level_change"]["changed"] is True
    assert len(diff["factors_removed"]) == 1
    assert diff["reputation_changes"]["unflagged"] == ["URLhaus"]
    assert diff["summary"] == "Threat profile improved"


def test_comparison_unchanged():
    scan_a = {
        "id": "scan_a",
        "risk_score": 25,
        "risk_level": "LOW",
        "detection_count": 1,
        "factors": [{"id": "infra_new_domain", "points": 10, "severity": "medium"}],
        "raw_summary": {},
    }
    scan_b = {
        "id": "scan_b",
        "risk_score": 25,
        "risk_level": "LOW",
        "detection_count": 1,
        "factors": [{"id": "infra_new_domain", "points": 10, "severity": "medium"}],
        "raw_summary": {},
    }

    diff = compare_scans(scan_a, scan_b)

    assert diff["score_delta"] == 0
    assert diff["detection_delta"] == 0
    assert diff["level_change"]["changed"] is False
    assert len(diff["factors_added"]) == 0
    assert len(diff["factors_removed"]) == 0
    assert diff["summary"] == "Threat profile unchanged"


def test_comparison_minor_factor_changed():
    scan_a = {
        "id": "scan_a",
        "risk_score": 20,
        "risk_level": "LOW",
        "detection_count": 0,
        "factors": [{"id": "factor_1", "points": 10, "severity": "low"}],
        "raw_summary": {},
    }
    scan_b = {
        "id": "scan_b",
        "risk_score": 25,
        "risk_level": "LOW",
        "detection_count": 0,
        "factors": [{"id": "factor_1", "points": 15, "severity": "medium"}],
        "raw_summary": {},
    }

    diff = compare_scans(scan_a, scan_b)

    assert diff["score_delta"] == 5
    assert diff["level_change"]["changed"] is False
    assert len(diff["factors_changed"]) == 1
    assert diff["factors_changed"][0]["old_points"] == 10
    assert diff["factors_changed"][0]["new_points"] == 15
    assert diff["summary"] == "Threat profile changed without affecting the verdict"


def test_comparison_unchanged_level_large_delta():
    # Level unchanged (both HIGH), but score worsened by >= 15
    scan_a = {
        "id": "scan_a",
        "risk_score": 58,
        "risk_level": "HIGH",
        "detection_count": 8,
        "factors": [],
        "raw_summary": {},
    }
    scan_b = {
        "id": "scan_b",
        "risk_score": 75,
        "risk_level": "HIGH",
        "detection_count": 14,
        "factors": [],
        "raw_summary": {},
    }
    diff = compare_scans(scan_a, scan_b)
    assert diff["score_delta"] == 17
    assert diff["level_change"]["changed"] is False
    assert diff["summary"] == "Threat profile worsened significantly (verdict unchanged)"

    # Improved equivalent (both HIGH, delta <= -15)
    diff_rev = compare_scans(scan_b, scan_a)
    assert diff_rev["score_delta"] == -17
    assert diff_rev["level_change"]["changed"] is False
    assert diff_rev["summary"] == "Threat profile improved significantly (verdict unchanged)"
