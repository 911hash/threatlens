"""
History and scan comparison routes.
Provides timeline of past scans, verdict drift tracking, and detailed scan comparisons.
Per-browser multi-user session isolation via session cookies.
"""

from typing import List, Optional
from urllib.parse import unquote
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scan
from ..schemas import CompareResponse, ScanResponse
from ..services.comparison import compare_scans
from ..session import get_or_create_session_id
from .analyze import serialize_scan_response

router = APIRouter(prefix="/api", tags=["History & Compare"])


@router.get("/scans", response_model=List[ScanResponse])
def list_scans(
    request: Request,
    response: Response,
    type: Optional[str] = Query(None, description="Filter by type: url, hash, file"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    query = db.query(Scan).filter(Scan.user_session_id == session_id)
    if type and type != "all":
        query = query.filter(Scan.target_type == type)

    scans = query.order_by(Scan.timestamp.desc()).offset(offset).limit(limit).all()

    results = []
    for s in scans:
        prev = (
            db.query(Scan)
            .filter(
                Scan.target == s.target,
                Scan.timestamp < s.timestamp,
                Scan.user_session_id == session_id,
            )
            .order_by(Scan.timestamp.desc())
            .first()
        )
        delta = (s.risk_score - prev.risk_score) if prev else None
        level_changed = (s.risk_level != prev.risk_level) if prev else None
        results.append(
            serialize_scan_response(
                s,
                delta_vs_previous=delta,
                level_changed_vs_previous=level_changed,
                previous_scan_id=prev.id if prev else None,
            )
        )

    return results


@router.get("/scans/{id}", response_model=ScanResponse)
def get_scan(
    id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    scan = (
        db.query(Scan)
        .filter(Scan.id == id, Scan.user_session_id == session_id)
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_NOT_FOUND", "message": f"Scan with ID '{id}' was not found."},
        )
    prev = (
        db.query(Scan)
        .filter(
            Scan.target == scan.target,
            Scan.timestamp < scan.timestamp,
            Scan.user_session_id == session_id,
        )
        .order_by(Scan.timestamp.desc())
        .first()
    )
    delta = (scan.risk_score - prev.risk_score) if prev else None
    level_changed = (scan.risk_level != prev.risk_level) if prev else None
    return serialize_scan_response(
        scan,
        delta_vs_previous=delta,
        level_changed_vs_previous=level_changed,
        previous_scan_id=prev.id if prev else None,
    )


@router.get("/history/{target:path}")
def get_target_history(
    target: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    decoded_target = unquote(target).strip()
    scans = (
        db.query(Scan)
        .filter(
            Scan.target == decoded_target,
            Scan.user_session_id == session_id,
        )
        .order_by(Scan.timestamp.asc())
        .all()
    )

    if not scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NO_HISTORY", "message": f"No scan history found for target '{decoded_target}'."},
        )

    serialized = [serialize_scan_response(s).model_dump() for s in scans]

    # Calculate step-by-step deltas
    timeline_with_deltas = []
    for i, scan_dict in enumerate(serialized):
        if i == 0:
            scan_dict["delta_vs_previous"] = 0
            scan_dict["level_changed_vs_previous"] = False
        else:
            prev = serialized[i - 1]
            scan_dict["delta_vs_previous"] = scan_dict["risk_score"] - prev["risk_score"]
            scan_dict["level_changed_vs_previous"] = scan_dict["risk_level"] != prev["risk_level"]
        timeline_with_deltas.append(scan_dict)

    return {
        "target": decoded_target,
        "total_scans": len(scans),
        "first_scanned": scans[0].timestamp,
        "last_scanned": scans[-1].timestamp,
        "scans": timeline_with_deltas,
    }


@router.get("/compare/{id1}/{id2}", response_model=CompareResponse)
def compare_two_scans(
    id1: str,
    id2: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    session_id = get_or_create_session_id(request, response)
    scan1 = (
        db.query(Scan)
        .filter(Scan.id == id1, Scan.user_session_id == session_id)
        .first()
    )
    if not scan1:
        scan1 = db.query(Scan).filter(Scan.id == id1).first()

    scan2 = (
        db.query(Scan)
        .filter(Scan.id == id2, Scan.user_session_id == session_id)
        .first()
    )
    if not scan2:
        scan2 = db.query(Scan).filter(Scan.id == id2).first()

    if not scan1 or not scan2:
        missing = id1 if not scan1 else id2
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_NOT_FOUND", "message": f"Scan '{missing}' not found for comparison."},
        )

    # Sort chronologically so scan_a is older and scan_b is newer
    if scan1.timestamp > scan2.timestamp:
        scan_a, scan_b = scan2, scan1
    else:
        scan_a, scan_b = scan1, scan2

    data_a = serialize_scan_response(scan_a).model_dump()
    data_b = serialize_scan_response(scan_b).model_dump()

    diff_result = compare_scans(data_a, data_b)
    return CompareResponse(**diff_result)
