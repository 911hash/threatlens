"""
Comparison service for ThreatLens.
Pure deterministic logic for computing verdict drift and threat evolution differences.
"""

from typing import Any, Dict, List, Optional


def compare_scans(scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scans (scan_a: earlier/baseline, scan_b: newer/current).
    Only reports differences that exist in the actual data.
    """
    score_a = int(scan_a.get("risk_score", 0))
    score_b = int(scan_b.get("risk_score", 0))
    score_delta = score_b - score_a

    det_a = int(scan_a.get("detection_count", 0))
    det_b = int(scan_b.get("detection_count", 0))
    det_delta = det_b - det_a

    level_a = scan_a.get("risk_level", "UNKNOWN")
    level_b = scan_b.get("risk_level", "UNKNOWN")
    level_changed = level_a != level_b

    # Parse factors
    factors_a = scan_a.get("factors") or []
    factors_b = scan_b.get("factors") or []

    factors_a_map = {f.get("id"): f for f in factors_a if isinstance(f, dict) and "id" in f}
    factors_b_map = {f.get("id"): f for f in factors_b if isinstance(f, dict) and "id" in f}

    factors_added = [
        f for fid, f in factors_b_map.items() if fid not in factors_a_map
    ]
    factors_removed = [
        f for fid, f in factors_a_map.items() if fid not in factors_b_map
    ]

    factors_changed = []
    for fid, fb in factors_b_map.items():
        if fid in factors_a_map:
            fa = factors_a_map[fid]
            if fa.get("points") != fb.get("points") or fa.get("severity") != fb.get("severity"):
                factors_changed.append({
                    "id": fid,
                    "title": fb.get("title", fa.get("title", fid)),
                    "old_points": fa.get("points", 0),
                    "new_points": fb.get("points", 0),
                    "old_severity": fa.get("severity", "info"),
                    "new_severity": fb.get("severity", "info"),
                    "source": fb.get("source", fa.get("source", "")),
                })

    # Redirect chain differences
    raw_a = scan_a.get("raw_summary") or {}
    raw_b = scan_b.get("raw_summary") or {}

    redir_a = raw_a.get("redirects") or {}
    redir_b = raw_b.get("redirects") or {}

    hops_a = redir_a.get("hop_count", 0)
    hops_b = redir_b.get("hop_count", 0)
    final_dom_a = redir_a.get("final_domain", "")
    final_dom_b = redir_b.get("final_domain", "")

    final_domain_changed = bool(final_dom_a and final_dom_b and final_dom_a != final_dom_b)
    redirect_chain_change = {
        "final_domain_changed": final_domain_changed,
        "hop_count_delta": hops_b - hops_a,
        "from_domain": final_dom_a,
        "to_domain": final_dom_b,
        "from_hops": hops_a,
        "to_hops": hops_b,
    }

    # Reputation list changes
    rep_a = set(raw_a.get("reputation_lists_flagged") or [])
    rep_b = set(raw_b.get("reputation_lists_flagged") or [])

    reputation_changes = {
        "newly_flagged": sorted(list(rep_b - rep_a)),
        "unflagged": sorted(list(rep_a - rep_b)),
    }

    # Deterministic summary sentence selection
    summary = _determine_summary(
        score_delta=score_delta,
        level_a=level_a,
        level_b=level_b,
        factors_added=factors_added,
        factors_removed=factors_removed,
        factors_changed=factors_changed,
        det_delta=det_delta,
        redirect_chain_change=redirect_chain_change,
        reputation_changes=reputation_changes,
    )

    return {
        "score_delta": score_delta,
        "detection_delta": det_delta,
        "level_change": {
            "from": level_a,
            "to": level_b,
            "changed": level_changed,
        },
        "factors_added": factors_added,
        "factors_removed": factors_removed,
        "factors_changed": factors_changed,
        "redirect_chain_change": redirect_chain_change,
        "reputation_changes": reputation_changes,
        "summary": summary,
        "scan_a_id": scan_a.get("id"),
        "scan_b_id": scan_b.get("id"),
        "scan_a_timestamp": scan_a.get("timestamp"),
        "scan_b_timestamp": scan_b.get("timestamp"),
        "scan_a_score": score_a,
        "scan_b_score": score_b,
        "scan_a_level": level_a,
        "scan_b_level": level_b,
    }


def _determine_summary(
    score_delta: int,
    level_a: str,
    level_b: str,
    factors_added: List[Dict[str, Any]],
    factors_removed: List[Dict[str, Any]],
    factors_changed: List[Dict[str, Any]],
    det_delta: int,
    redirect_chain_change: Optional[Dict[str, Any]] = None,
    reputation_changes: Optional[Dict[str, Any]] = None,
) -> str:
    """Select appropriate deterministic summary template based purely on factual metrics."""
    severity_order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}
    sev_a = severity_order.get(level_a, -1)
    sev_b = severity_order.get(level_b, -1)
    level_changed = level_a != level_b

    # When the level is unchanged but |score_delta| >= 15
    if not level_changed:
        if score_delta >= 15:
            return "Threat profile worsened significantly (verdict unchanged)"
        elif score_delta <= -15:
            return "Threat profile improved significantly (verdict unchanged)"

    # When level changed or score delta indicates overall trend
    if score_delta >= 20 or (sev_b > sev_a and sev_b >= 3):
        return "Threat profile deteriorated significantly"
    elif score_delta <= -15 or (sev_b < sev_a and sev_a >= 2):
        return "Threat profile improved"
    elif (
        score_delta == 0
        and not factors_added
        and not factors_removed
        and not factors_changed
        and det_delta == 0
        and (not redirect_chain_change or (
            not redirect_chain_change.get("final_domain_changed")
            and redirect_chain_change.get("hop_count_delta", 0) == 0
        ))
        and (not reputation_changes or (
            not reputation_changes.get("newly_flagged")
            and not reputation_changes.get("unflagged")
        ))
    ):
        return "Threat profile unchanged"
    else:
        return "Threat profile changed without affecting the verdict"
