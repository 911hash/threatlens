"""
Forensics, Artifact Graph, and Case Management API Endpoints.

All endpoints resolve tenant_id via `get_tenant_id(request)` (defaults to 'default').
Strict multi-tenant isolation: every database query filters on tenant_id.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CaseAudit, GraphNode
from ..services import case_management, forensic_timeline, graph_service

logger = logging.getLogger("threatlens.routes.forensics")

router = APIRouter(prefix="/api", tags=["forensics"])


def get_tenant_id(request: Request) -> str:
    """
    Resolve tenant_id for the current request.
    Defaults to 'default' for this single-user deployment.
    Seam for future multi-user support: checks X-Tenant-ID header if present.
    """
    header_val = request.headers.get("X-Tenant-ID")
    if header_val and header_val.strip():
        return header_val.strip()
    return "default"


# --- Request Models ---

class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default="", max_length=5000)


class AddItemRequest(BaseModel):
    scan_id: str = Field(..., min_length=1, max_length=64)


class AddCommentRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=10000)


class CaseNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


# =====================================================================
# ARTIFACT GRAPH ENDPOINTS
# =====================================================================

@router.get("/graph/recent")
def get_recent_graph(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Return the most recently seen graph nodes and their connecting edges."""
    tenant_id = get_tenant_id(request)
    return graph_service.get_recent_nodes(tenant_id=tenant_id, limit=limit, db=db)


@router.get("/graph/nodes/{node_id}")
def get_node_neighbors(
    node_id: str,
    request: Request,
    depth: int = Query(default=1, ge=1, le=3),
    db: Session = Depends(get_db),
):
    """Return connected nodes and edges up to `depth` hops (cap 3)."""
    tenant_id = get_tenant_id(request)
    node = (
        db.query(GraphNode)
        .filter(GraphNode.id == node_id, GraphNode.tenant_id == tenant_id)
        .first()
    )
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NODE_NOT_FOUND", "message": f"Graph node '{node_id}' not found."},
        )

    res = graph_service.get_neighbors(node_id=node_id, tenant_id=tenant_id, depth=depth, db=db)
    return res


@router.get("/graph/pivot/{node_id}")
def get_node_pivot(
    node_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Return all entities connected to a node, grouped by type, with connection counts."""
    tenant_id = get_tenant_id(request)
    pivot = graph_service.get_pivot(node_id=node_id, tenant_id=tenant_id, db=db)
    if not pivot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NODE_NOT_FOUND", "message": f"Graph node '{node_id}' not found."},
        )
    return pivot


@router.get("/graph/path")
def get_graph_path(
    from_node_id: str = Query(...),
    to_node_id: str = Query(...),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """BFS shortest path between two nodes, capped at 5 hops."""
    tenant_id = get_tenant_id(request)
    path = graph_service.get_path(
        node_a_id=from_node_id,
        node_b_id=to_node_id,
        tenant_id=tenant_id,
        db=db,
    )
    return {"path": path}


@router.get("/graph/lookup")
def lookup_node(
    value: str = Query(...),
    type: Optional[str] = Query(default=None),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Lookup a graph node by value and optional indicator type."""
    tenant_id = get_tenant_id(request)
    node = graph_service.lookup_node_by_value(node_type=type, value=value, tenant_id=tenant_id, db=db)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NODE_NOT_FOUND", "message": f"No node found matching indicator '{value}'."},
        )
    return node


# =====================================================================
# FORENSIC TIMELINE ENDPOINT
# =====================================================================

@router.get("/timeline/{scan_id}")
def get_scan_timeline(
    scan_id: str,
    request: Request,
    force_rebuild: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    """
    Get or construct the forensic timeline for a scan.
    Returns chronologically sorted list of ForensicEvent.
    """
    tenant_id = get_tenant_id(request)
    events = forensic_timeline.build_timeline(
        scan_id=scan_id,
        tenant_id=tenant_id,
        db=db,
        force_rebuild=force_rebuild,
    )
    return {"scan_id": scan_id, "events": events}


# =====================================================================
# CASE MANAGEMENT ENDPOINTS
# =====================================================================

@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CreateCaseRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Create a new investigation case."""
    tenant_id = get_tenant_id(request)
    new_case = case_management.create_case(
        tenant_id=tenant_id,
        title=payload.title,
        description=payload.description or "",
        actor="system",
        db=db,
    )
    return new_case


@router.get("/cases")
def list_cases(
    request: Request,
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """List cases filtered by tenant and optional status."""
    tenant_id = get_tenant_id(request)
    return case_management.list_cases(tenant_id=tenant_id, status=status, db=db)


@router.get("/cases/{case_id}")
def get_case_detail(
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Retrieve full case details: case + items + comments + audit log."""
    tenant_id = get_tenant_id(request)
    case_data = case_management.get_case(case_id=case_id, tenant_id=tenant_id, db=db)
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return case_data


@router.post("/cases/{case_id}/items")
def add_case_item(
    case_id: str,
    payload: AddItemRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Add a scan/email item to a case."""
    tenant_id = get_tenant_id(request)
    try:
        item = case_management.add_scan_to_case(
            case_id=case_id,
            scan_id=payload.scan_id,
            tenant_id=tenant_id,
            actor="system",
            db=db,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_NOT_FOUND", "message": str(e)},
        )

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return item


@router.post("/cases/{case_id}/comments")
def add_case_comment(
    case_id: str,
    payload: AddCommentRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Add an analyst comment to a case."""
    tenant_id = get_tenant_id(request)
    comment = case_management.add_comment(
        case_id=case_id,
        body=payload.body,
        tenant_id=tenant_id,
        author="system",
        db=db,
    )
    if not comment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return comment


@router.post("/cases/{case_id}/escalate")
def escalate_case(
    case_id: str,
    payload: CaseNoteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Escalate a case with required note."""
    tenant_id = get_tenant_id(request)
    res = case_management.escalate_case(
        case_id=case_id,
        note=payload.note,
        tenant_id=tenant_id,
        actor="system",
        db=db,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return res


@router.post("/cases/{case_id}/resolve")
def resolve_case(
    case_id: str,
    payload: CaseNoteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Resolve a case with required note."""
    tenant_id = get_tenant_id(request)
    res = case_management.resolve_case(
        case_id=case_id,
        note=payload.note,
        tenant_id=tenant_id,
        actor="system",
        db=db,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return res


@router.post("/cases/{case_id}/reopen")
def reopen_case(
    case_id: str,
    payload: CaseNoteRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Reopen a resolved case with required note."""
    tenant_id = get_tenant_id(request)
    res = case_management.reopen_case(
        case_id=case_id,
        note=payload.note,
        tenant_id=tenant_id,
        actor="system",
        db=db,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )
    return res


@router.get("/cases/{case_id}/audit")
def get_case_audit_trail(
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Retrieve immutable audit trail for a case."""
    tenant_id = get_tenant_id(request)
    case_obj = (
        db.query(case_management.Case)
        .filter(case_management.Case.id == case_id, case_management.Case.tenant_id == tenant_id)
        .first()
    )
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case '{case_id}' not found."},
        )

    audits = (
        db.query(CaseAudit)
        .filter(CaseAudit.case_id == case_id, CaseAudit.tenant_id == tenant_id)
        .order_by(CaseAudit.timestamp.desc())
        .all()
    )
    return [case_management._serialize_audit(a) for a in audits]
