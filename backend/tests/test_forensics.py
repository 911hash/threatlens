"""
Integration tests for Forensic Platform (Phase 10):
- Artifact Graph (indexing, deduplication/idempotency, pivot, shortest path, privacy mode)
- Forensic Timeline (chronological sorting, missing source handling, caching)
- Case Management (full lifecycle, comments, escalation, resolution, audit trail)
- Retention Policy (purging expired only, never purging open cases)
- Multi-Tenant Isolation
"""

from datetime import datetime, timedelta, timezone
import json
import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import (
    Case,
    CaseAudit,
    CaseComment,
    CaseItem,
    ForensicEvent,
    GraphEdge,
    GraphNode,
    Scan,
    generate_id,
)
from app.services import case_management, forensic_timeline, graph_service
from app.services.retention import purge_expired


@pytest.fixture(scope="module", autouse=True)
def setup_forensics_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    return TestClient(app, headers={"X-Session-ID": "migrated_default"})


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _create_sample_email_scan(
    db,
    scan_id: str,
    target: str = "<test_msg_001@phish.net>",
    from_address: str = "attacker@malicious-sender.com",
    sender_ips: list = None,
    attachments: list = None,
    date_header: str = "Mon, 10 Oct 2026 10:00:00 +0000",
    hops: list = None,
    rdap_reg_date: str = None,
    crt_timestamp: str = None,
    vt_first_seen: int = None,
    body_content: str = "Please click this link: https://evil-login.com/auth",
) -> Scan:
    """Helper to seed an email Scan with structured analytical metadata."""
    existing = db.query(Scan).filter(Scan.id == scan_id).first()
    if existing:
        db.delete(existing)
        db.commit()
    if sender_ips is None:
        sender_ips = ["198.51.100.50"]
    if hops is None:
        hops = [
            {"hop_index": 1, "ip": "198.51.100.50", "timestamp": "Mon, 10 Oct 2026 10:01:00 +0000"},
            {"hop_index": 2, "ip": "203.0.113.10", "timestamp": "Mon, 10 Oct 2026 10:02:15 +0000"},
        ]
    if attachments is None:
        attachments = [
            {
                "filename": "payload.exe",
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "size_bytes": 45000,
                "mime_type": "application/x-dosexec",
                "is_suspicious": True,
            }
        ]

    geo_results = [
        {
            "ip": sender_ips[0],
            "country_name": "Romania",
            "city": "Bucharest",
            "asn": "AS45678",
            "as_org": "Host Provider Ltd",
        }
    ]

    raw_summary = {
        "from_address": from_address,
        "to_addresses": ["victim@corporate.org"],
        "date": date_header,
        "subject": "Overdue Invoice Notice",
        "plain_body": body_content,
        "sanitized_html": f"<p>{body_content}</p>",
        "sender_ips": sender_ips,
        "geo_results": geo_results,
        "header_analysis": {"hops": hops},
        "attachments": attachments,
    }

    sources = {}
    if rdap_reg_date:
        sources["RDAP"] = {
            "name": "RDAP",
            "status": "ok",
            "data": {
                "domain": "malicious-sender.com",
                "registrar": "NameCheap Inc",
                "registration_date": rdap_reg_date,
            },
        }
    if crt_timestamp:
        sources["crt.sh"] = {
            "name": "crt.sh",
            "status": "ok",
            "data": {
                "recent_entries": [
                    {
                        "issuer": "Let's Encrypt Authority",
                        "entry_timestamp": crt_timestamp,
                    }
                ]
            },
        }
    if vt_first_seen:
        sources["VirusTotal"] = {
            "name": "VirusTotal",
            "status": "ok",
            "data": {
                "first_submission_date": vt_first_seen,
            },
        }

    scan = Scan(
        id=scan_id,
        target=target,
        target_type="email",
        timestamp=datetime.utcnow(),
        risk_score=85,
        risk_level="HIGH",
        confidence=90,
        detection_count=4,
        total_engines=6,
        factors_json="[]",
        raw_summary_json=json.dumps(raw_summary),
        sources_json=json.dumps(sources),
        is_demo=False,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# =====================================================================
# 1. GRAPH TESTS
# =====================================================================

def test_graph_index_email_creates_nodes_and_edges(db):
    """Indexing an email scan extracts nodes and edges into the graph."""
    tenant = "test_tenant_idx"
    scan_id = "scan_graph_idx_01"
    _create_sample_email_scan(db, scan_id=scan_id)

    res = graph_service.index_email(scan_id=scan_id, tenant_id=tenant, db=db)
    assert len(res["nodes"]) > 0
    assert len(res["edges"]) > 0

    # Verify created node types
    nodes = db.query(GraphNode).filter(GraphNode.tenant_id == tenant).all()
    node_types = {n.node_type for n in nodes}
    assert "Email" in node_types
    assert "Sender" in node_types
    assert "Recipient" in node_types
    assert "IP" in node_types
    assert "ASN" in node_types
    assert "AttachmentHash" in node_types
    assert "URL" in node_types

    # Verify edge types
    edges = db.query(GraphEdge).filter(GraphEdge.tenant_id == tenant).all()
    edge_types = {e.edge_type for e in edges}
    assert "SENT_FROM" in edge_types
    assert "SENT_TO" in edge_types
    assert "CONTAINS" in edge_types
    assert "HOSTED_IN" in edge_types


def test_graph_index_email_is_idempotent(db):
    """Re-indexing the exact same scan does not create duplicate nodes or edges."""
    tenant = "test_tenant_idemp"
    scan_id = "scan_idemp_01"
    _create_sample_email_scan(db, scan_id=scan_id)

    # First index
    res1 = graph_service.index_email(scan_id=scan_id, tenant_id=tenant, db=db)
    node_count_1 = db.query(GraphNode).filter(GraphNode.tenant_id == tenant).count()
    edge_count_1 = db.query(GraphEdge).filter(GraphEdge.tenant_id == tenant).count()

    # Second index (re-indexing same scan)
    res2 = graph_service.index_email(scan_id=scan_id, tenant_id=tenant, db=db)
    node_count_2 = db.query(GraphNode).filter(GraphNode.tenant_id == tenant).count()
    edge_count_2 = db.query(GraphEdge).filter(GraphEdge.tenant_id == tenant).count()

    assert node_count_1 == node_count_2
    assert edge_count_1 == edge_count_2
    assert len(res1["nodes"]) == len(res2["nodes"])


def test_graph_pivot_returns_connected_entities(db):
    """Three emails sharing a sender IP: pivot from that IP returns all three."""
    tenant = "test_tenant_pivot"
    shared_ip = "192.0.2.144"

    scan1 = _create_sample_email_scan(db, scan_id="scan_piv_01", sender_ips=[shared_ip])
    scan2 = _create_sample_email_scan(db, scan_id="scan_piv_02", sender_ips=[shared_ip])
    scan3 = _create_sample_email_scan(db, scan_id="scan_piv_03", sender_ips=[shared_ip])

    graph_service.index_email(scan_id=scan1.id, tenant_id=tenant, db=db)
    graph_service.index_email(scan_id=scan2.id, tenant_id=tenant, db=db)
    graph_service.index_email(scan_id=scan3.id, tenant_id=tenant, db=db)

    # Find the shared IP node
    ip_node = (
        db.query(GraphNode)
        .filter(
            GraphNode.tenant_id == tenant,
            GraphNode.node_type == "IP",
            GraphNode.value == shared_ip,
        )
        .first()
    )
    assert ip_node is not None

    # Pivot on the IP
    pivot = graph_service.get_pivot(node_id=ip_node.id, tenant_id=tenant, db=db)
    assert pivot is not None
    assert "Email" in pivot["grouped"]
    assert pivot["counts"]["Email"] == 3

    connected_email_ids = [n["value"] for n in pivot["grouped"]["Email"]]
    assert scan1.id in connected_email_ids
    assert scan2.id in connected_email_ids
    assert scan3.id in connected_email_ids


def test_graph_no_raw_content_stored(db):
    """Grep graph_nodes.metadata_json for raw body and subject strings: assert zero matches."""
    tenant = "test_tenant_privacy"
    canary_body = "CANARY_CONFIDENTIAL_PAYROLL_2026_SECRET_TEXT"
    canary_subject = "CANARY_URGENT_CONFIDENTIAL_BOARD_MEETING"

    scan = _create_sample_email_scan(
        db,
        scan_id="scan_privacy_01",
        target="<privacy_test@threatlens.io>",
        body_content=f"Secret report details: {canary_body}",
    )
    # Set custom subject in raw summary
    summary = json.loads(scan.raw_summary_json)
    summary["subject"] = canary_subject
    scan.raw_summary_json = json.dumps(summary)
    db.commit()

    graph_service.index_email(scan_id=scan.id, tenant_id=tenant, db=db)

    nodes = db.query(GraphNode).filter(GraphNode.tenant_id == tenant).all()
    assert len(nodes) > 0

    for n in nodes:
        meta_str = n.metadata_json or ""
        assert canary_body not in meta_str, f"Found raw body leak in node {n.id}"
        assert canary_subject not in meta_str, f"Found subject leak in node {n.id}"
        assert "CONFIDENTIAL" not in meta_str
        assert "PAYROLL" not in meta_str


# =====================================================================
# 2. FORENSIC TIMELINE TESTS
# =====================================================================

def test_timeline_sorted_chronologically(db):
    """Events are constructed from multiple intelligence sources and sorted ascending."""
    tenant = "test_tenant_tl"
    scan_id = "scan_tl_sorted"

    # Out of order timestamps in source metadata:
    # Event 1 (Earliest): RDAP registration -> 2026-01-15T00:00:00Z
    # Event 2: crt.sh cert -> 2026-04-10T12:00:00Z
    # Event 3: email_sent -> 2026-10-10T08:00:00Z
    # Event 4: email_delivered -> 2026-10-10T08:05:00Z
    # Event 5: url_first_seen -> 2026-10-10T09:00:00Z (timestamp 1791622800)
    _create_sample_email_scan(
        db,
        scan_id=scan_id,
        rdap_reg_date="2026-01-15T00:00:00Z",
        crt_timestamp="2026-04-10T12:00:00Z",
        date_header="Sat, 10 Oct 2026 08:00:00 +0000",
        hops=[{"hop_index": 1, "ip": "1.2.3.4", "timestamp": "Sat, 10 Oct 2026 08:05:00 +0000"}],
        vt_first_seen=int(datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc).timestamp()),
    )

    events = forensic_timeline.build_timeline(
        scan_id=scan_id,
        tenant_id=tenant,
        db=db,
        force_rebuild=True,
    )

    assert len(events) == 5
    categories = [e["category"] for e in events]
    assert categories == [
        "domain_registered",
        "certificate_issued",
        "email_sent",
        "email_delivered",
        "url_first_seen",
    ]

    # Verify strictly ascending order
    timestamps = [datetime.fromisoformat(e["event_timestamp"]) for e in events]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1]


def test_timeline_missing_sources_produce_no_events(db):
    """Missing sources produce no event, not a placeholder."""
    tenant = "test_tenant_tl_missing"
    scan_id = "scan_tl_minimal"

    # Scan with ONLY date header, no RDAP, no crt.sh, no VT
    _create_sample_email_scan(
        db,
        scan_id=scan_id,
        rdap_reg_date=None,
        crt_timestamp=None,
        vt_first_seen=None,
        date_header="Tue, 11 Oct 2026 12:00:00 +0000",
        hops=[],
    )

    events = forensic_timeline.build_timeline(
        scan_id=scan_id,
        tenant_id=tenant,
        db=db,
        force_rebuild=True,
    )

    # Only email_sent should exist
    assert len(events) == 1
    assert events[0]["category"] == "email_sent"
    for e in events:
        assert "placeholder" not in e["description"].lower()
        assert "unknown" not in e["description"].lower()


# =====================================================================
# 3. CASE MANAGEMENT & AUDIT TESTS
# =====================================================================

def test_case_create_add_comment_escalate_resolve_full_cycle(db):
    """Full lifecycle: create -> add scan -> comment -> escalate -> resolve -> reopen."""
    tenant = "test_tenant_case"
    scan = _create_sample_email_scan(db, scan_id="scan_case_item_01")

    # 1. Create case
    case = case_management.create_case(
        tenant_id=tenant,
        title="Incident 402: Phishing Outbreak",
        description="Investigation into credential harvester email campaign.",
    )
    case_id = case["id"]
    assert case["status"] == "open"

    # 2. Add scan item
    item = case_management.add_scan_to_case(
        case_id=case_id,
        scan_id=scan.id,
        tenant_id=tenant,
        actor="soc_analyst_1",
    )
    assert item["scan_id"] == scan.id

    # 3. Add comment
    cmt = case_management.add_comment(
        case_id=case_id,
        body="Observed matching SHA-256 hash across two other mailboxes.",
        tenant_id=tenant,
        author="soc_analyst_1",
    )
    assert cmt["author"] == "soc_analyst_1"

    # 4. Escalate case
    esc = case_management.escalate_case(
        case_id=case_id,
        note="Elevating to Tier 2: Credential entered on external phish landing page.",
        tenant_id=tenant,
        actor="soc_lead",
    )
    assert esc["status"] == "escalated"

    # 5. Resolve case
    res = case_management.resolve_case(
        case_id=case_id,
        note="User session invalidated, firewall rule added for IP 198.51.100.50.",
        tenant_id=tenant,
        actor="soc_lead",
    )
    assert res["status"] == "resolved"
    assert res["resolved_at"] is not None

    # 6. Reopen case
    reop = case_management.reopen_case(
        case_id=case_id,
        note="Reopening: Second message observed from same sender.",
        tenant_id=tenant,
        actor="soc_analyst_2",
    )
    assert reop["status"] == "open"
    assert reop["resolved_at"] is None


def test_case_audit_log_complete(db):
    """Every action in the case lifecycle appears in case_audit with timestamp."""
    tenant = "test_tenant_audit"
    scan = _create_sample_email_scan(db, scan_id="scan_audit_item_01")

    case = case_management.create_case(tenant_id=tenant, title="Audit Trail Verification")
    case_id = case["id"]

    case_management.add_scan_to_case(case_id, scan.id, tenant_id=tenant)
    case_management.add_comment(case_id, "Analyst note", tenant_id=tenant)
    case_management.escalate_case(case_id, "Needs escalation", tenant_id=tenant)
    case_management.resolve_case(case_id, "Resolved cleanly", tenant_id=tenant)

    full_case = case_management.get_case(case_id=case_id, tenant_id=tenant)
    assert full_case is not None

    audit_actions = [a["action"] for a in full_case["audit"]]
    expected_actions = [
        "case_resolved",
        "case_escalated",
        "comment_added",
        "scan_added",
        "case_created",
    ]
    for action in expected_actions:
        assert action in audit_actions

    # Check audit rows contain actors and valid timestamps
    for a in full_case["audit"]:
        assert a["actor"] is not None
        assert a["timestamp"] is not None


# =====================================================================
# 4. RETENTION TESTS
# =====================================================================

def test_retention_purges_only_expired(db):
    """Purge job deletes graph nodes/edges older than 90d and resolved cases older than 180d."""
    tenant = "test_tenant_retention"
    now = datetime.utcnow()

    # Create expired node & edge (> 90 days)
    old_node_id = graph_service._upsert_node("IP", "1.1.1.1", tenant_id=tenant, db=db)
    old_node = db.query(GraphNode).filter(GraphNode.id == old_node_id).first()
    old_node.last_seen_at = now - timedelta(days=95)

    old_edge_id = graph_service._upsert_edge(old_node_id, old_node_id, "SENT_FROM", tenant_id=tenant, db=db)
    old_edge = db.query(GraphEdge).filter(GraphEdge.id == old_edge_id).first()
    old_edge.last_seen_at = now - timedelta(days=95)

    # Create fresh node & edge (< 90 days)
    fresh_node_id = graph_service._upsert_node("IP", "2.2.2.2", tenant_id=tenant, db=db)
    fresh_node = db.query(GraphNode).filter(GraphNode.id == fresh_node_id).first()
    fresh_node.last_seen_at = now - timedelta(days=10)

    # Create expired resolved case (> 180 days)
    old_case = Case(
        id=generate_id("case"),
        tenant_id=tenant,
        title="Old Resolved Case",
        status="resolved",
        created_at=now - timedelta(days=200),
        updated_at=now - timedelta(days=190),
        resolved_at=now - timedelta(days=185),
    )
    db.add(old_case)

    # Create fresh resolved case (< 180 days)
    fresh_case = Case(
        id=generate_id("case"),
        tenant_id=tenant,
        title="Recent Resolved Case",
        status="resolved",
        created_at=now - timedelta(days=30),
        updated_at=now - timedelta(days=20),
        resolved_at=now - timedelta(days=15),
    )
    db.add(fresh_case)
    db.commit()

    # Run purge
    res = purge_expired(tenant_id=tenant, db=db)
    assert res["edges_purged"] >= 1
    assert res["nodes_purged"] >= 1
    assert res["cases_purged"] >= 1

    # Verify old items gone
    assert db.query(GraphNode).filter(GraphNode.id == old_node_id).first() is None
    assert db.query(GraphEdge).filter(GraphEdge.id == old_edge_id).first() is None
    assert db.query(Case).filter(Case.id == old_case.id).first() is None

    # Verify fresh items intact
    assert db.query(GraphNode).filter(GraphNode.id == fresh_node_id).first() is not None
    assert db.query(Case).filter(Case.id == fresh_case.id).first() is not None


def test_retention_never_purges_open_cases(db):
    """Retention job NEVER deletes cases where status != 'resolved' even if older than 180d."""
    tenant = "test_tenant_open_cases"
    now = datetime.utcnow()

    # Ancient open case (365 days old)
    ancient_open = Case(
        id=generate_id("case"),
        tenant_id=tenant,
        title="Active Ongoing Cold Case",
        status="open",
        created_at=now - timedelta(days=365),
        updated_at=now - timedelta(days=365),
        resolved_at=None,
    )
    # Ancient escalated case (300 days old)
    ancient_escalated = Case(
        id=generate_id("case"),
        tenant_id=tenant,
        title="Severe Escalated Breach",
        status="escalated",
        created_at=now - timedelta(days=300),
        updated_at=now - timedelta(days=300),
        resolved_at=None,
    )
    db.add(ancient_open)
    db.add(ancient_escalated)
    db.commit()

    purge_expired(tenant_id=tenant, db=db)

    # Must both still exist
    assert db.query(Case).filter(Case.id == ancient_open.id).first() is not None
    assert db.query(Case).filter(Case.id == ancient_escalated.id).first() is not None


# =====================================================================
# 5. MULTI-TENANT ISOLATION TESTS
# =====================================================================

def test_multi_tenant_isolation(db, client):
    """Data created under tenant_id='TenantA' is never returned to queries for 'TenantB'."""
    tenant_a = "TenantA"
    tenant_b = "TenantB"

    # 1. Create node in TenantA
    node_a_id = graph_service._upsert_node(
        node_type="IP",
        value="198.51.100.99",
        tenant_id=tenant_a,
        db=db,
    )

    # 2. Create case in TenantA
    case_a = case_management.create_case(
        tenant_id=tenant_a,
        title="Tenant A Confidential Case",
        db=db,
    )

    # Query TenantB via service layer
    nbrs_b = graph_service.get_neighbors(node_id=node_a_id, tenant_id=tenant_b, db=db)
    assert len(nbrs_b["nodes"]) == 0

    pivot_b = graph_service.get_pivot(node_id=node_a_id, tenant_id=tenant_b, db=db)
    assert pivot_b is None

    cases_b = case_management.list_cases(tenant_id=tenant_b, db=db)
    assert all(c["id"] != case_a["id"] for c in cases_b)

    case_detail_b = case_management.get_case(case_id=case_a["id"], tenant_id=tenant_b, db=db)
    assert case_detail_b is None

    # Query TenantB via API route with header
    resp = client.get(
        f"/api/cases/{case_a['id']}",
        headers={"X-Tenant-ID": tenant_b},
    )
    assert resp.status_code == 404


def test_graph_recent_endpoint(db, client):
    """Test GET /api/graph/recent returns most recent nodes and their connecting edges."""
    tenant = "default"
    # Upsert two connected nodes
    ip_id = graph_service._upsert_node(
        node_type="IP",
        value="203.0.113.88",
        tenant_id=tenant,
        db=db,
    )
    domain_id = graph_service._upsert_node(
        node_type="Domain",
        value="recent-test.com",
        tenant_id=tenant,
        db=db,
    )
    edge_id = graph_service._upsert_edge(
        from_id=domain_id,
        to_id=ip_id,
        edge_type="RESOLVES_TO",
        tenant_id=tenant,
        db=db,
    )
    db.commit()

    resp = client.get("/api/graph/recent?limit=20")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    node_ids = [n["id"] for n in data["nodes"]]
    assert ip_id in node_ids
    assert domain_id in node_ids
    edge_ids = [e["id"] for e in data["edges"]]
    assert edge_id in edge_ids

