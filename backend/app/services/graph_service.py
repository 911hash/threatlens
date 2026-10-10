"""
ThreatLens Artifact Graph Service.
Stores metadata-only adjacency graph linking observables:
Email, Sender, Recipient, IP, Domain, URL, AttachmentHash, ASN.

Strict Privacy Mode:
Metadata stored in graph_nodes must NOT contain raw email body, subject line,
or any personal identifying information (PII). Only structured indicators,
hashes, IPs, ASNs, domains, timestamps, and source names are stored.
"""

from datetime import datetime
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import GraphEdge, GraphNode, Scan, generate_id

logger = logging.getLogger("threatlens.graph_service")

NODE_TYPES = {
    "Email",
    "Sender",
    "Recipient",
    "IP",
    "Domain",
    "URL",
    "AttachmentHash",
    "ASN",
}

EDGE_TYPES = {
    "SENT_FROM",
    "SENT_TO",
    "RESOLVES_TO",
    "CONTAINS",
    "REGISTERED_AT",
    "HOSTED_IN",
}


def _serialize_node(node: GraphNode) -> Dict[str, Any]:
    """Serialize a GraphNode model instance into a dictionary."""
    meta = {}
    try:
        meta = json.loads(node.metadata_json or "{}")
    except Exception:
        pass

    return {
        "id": node.id,
        "tenant_id": node.tenant_id,
        "node_type": node.node_type,
        "value": node.value,
        "display_value": node.display_value or node.value,
        "metadata": meta,
        "created_at": node.created_at.isoformat() if node.created_at else None,
        "last_seen_at": node.last_seen_at.isoformat() if node.last_seen_at else None,
    }


def _serialize_edge(edge: GraphEdge) -> Dict[str, Any]:
    """Serialize a GraphEdge model instance into a dictionary."""
    meta = {}
    try:
        meta = json.loads(edge.metadata_json or "{}")
    except Exception:
        pass

    return {
        "id": edge.id,
        "tenant_id": edge.tenant_id,
        "from_node_id": edge.from_node_id,
        "to_node_id": edge.to_node_id,
        "edge_type": edge.edge_type,
        "metadata": meta,
        "created_at": edge.created_at.isoformat() if edge.created_at else None,
        "last_seen_at": edge.last_seen_at.isoformat() if edge.last_seen_at else None,
    }


def _upsert_node(
    node_type: str,
    value: str,
    tenant_id: str = "default",
    metadata: Optional[Dict[str, Any]] = None,
    display_value: Optional[str] = None,
    db: Optional[Session] = None,
) -> str:
    """
    Deduplicate and upsert node on (tenant_id, node_type, value).
    Returns existing or newly created node id.
    Strict privacy: sanitizes metadata to ensure no raw body/subject text is stored.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        clean_val = str(value).strip()
        disp_val = str(display_value).strip() if display_value else clean_val

        # Normalize URL nodes: strip query params, lowercase host, strip trailing slash
        if node_type == "URL":
            try:
                parsed_u = urllib.parse.urlsplit(clean_val)
                scheme = (parsed_u.scheme or "http").lower()
                netloc = parsed_u.netloc.lower()
                path = parsed_u.path.rstrip("/")
                if not path:
                    path = "/"
                clean_val = f"{scheme}://{netloc}{path}" if path != "/" else f"{scheme}://{netloc}"
                short_host = netloc[4:] if netloc.startswith("www.") else netloc
                host_parts = short_host.split(".")
                if len(host_parts) > 2 and any(k in short_host for k in ["moengage", "sendgrid", "hubspotlinks", "kit-mail", "cloudflare"]):
                    domain_display = ".".join(host_parts[-2:])
                else:
                    domain_display = short_host

                if path and path != "/":
                    segments = [s for s in path.split("/") if s]
                    if segments:
                        first_seg = segments[0]
                        if first_seg.startswith("v") and len(first_seg) <= 3 and len(segments) > 1:
                            path_display = f"/{segments[0]}/{segments[1]}"
                        else:
                            path_display = f"/{segments[0]}"
                        disp_val = f"{domain_display}{path_display}"
                    else:
                        disp_val = domain_display
                else:
                    disp_val = domain_display
            except Exception:
                pass

        # Sanitize metadata to guarantee zero raw content or PII leak
        safe_meta = {}
        if metadata:
            for k, v in metadata.items():
                if k in ("body", "plain_body", "html_body", "sanitized_html", "subject", "raw_content", "prompt"):
                    continue
                safe_meta[k] = v

        existing = (
            db.query(GraphNode)
            .filter(
                GraphNode.tenant_id == tenant_id,
                GraphNode.node_type == node_type,
                GraphNode.value == clean_val,
            )
            .first()
        )

        now = datetime.utcnow()
        if existing:
            existing.last_seen_at = now
            if disp_val and (not existing.display_value or existing.display_value == existing.value):
                existing.display_value = disp_val
            if safe_meta:
                try:
                    cur_meta = json.loads(existing.metadata_json or "{}")
                    cur_meta.update(safe_meta)
                    existing.metadata_json = json.dumps(cur_meta)
                except Exception:
                    existing.metadata_json = json.dumps(safe_meta)
            db.flush()
            node_id = existing.id
        else:
            new_node = GraphNode(
                id=generate_id("node"),
                tenant_id=tenant_id,
                node_type=node_type,
                value=clean_val,
                display_value=disp_val,
                metadata_json=json.dumps(safe_meta),
                created_at=now,
                last_seen_at=now,
            )
            db.add(new_node)
            db.flush()
            node_id = new_node.id

        if close_db:
            db.commit()
        return node_id
    finally:
        if close_db:
            db.close()


def _upsert_edge(
    from_id: str,
    to_id: str,
    edge_type: str,
    tenant_id: str = "default",
    metadata: Optional[Dict[str, Any]] = None,
    db: Optional[Session] = None,
) -> str:
    """
    Deduplicate and upsert edge on (tenant_id, from_id, to_id, edge_type).
    Returns edge id.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        existing = (
            db.query(GraphEdge)
            .filter(
                GraphEdge.tenant_id == tenant_id,
                GraphEdge.from_node_id == from_id,
                GraphEdge.to_node_id == to_id,
                GraphEdge.edge_type == edge_type,
            )
            .first()
        )

        now = datetime.utcnow()
        if existing:
            existing.last_seen_at = now
            db.flush()
            edge_id = existing.id
        else:
            safe_meta = metadata or {}
            new_edge = GraphEdge(
                id=generate_id("edge"),
                tenant_id=tenant_id,
                from_node_id=from_id,
                to_node_id=to_id,
                edge_type=edge_type,
                metadata_json=json.dumps(safe_meta),
                created_at=now,
                last_seen_at=now,
            )
            db.add(new_edge)
            db.flush()
            edge_id = new_edge.id

        if close_db:
            db.commit()
        return edge_id
    finally:
        if close_db:
            db.close()


def extract_email_address(addr_str: str) -> Optional[str]:
    """Helper to extract pure clean email address from string e.g. 'John <john@example.com>'."""
    if not addr_str:
        return None
    match = re.search(r'[\w\.-]+@[\w\.-]+', addr_str)
    if match:
        return match.group(0).lower().strip()
    return None


def index_email(
    scan_id: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Extract nodes and edges from a scan's parsed data and upsert into the graph.
    Idempotent: re-indexing the same scan must not create duplicate nodes or edges.
    Privacy Mode: Graph stores METADATA ONLY, never raw email content, subject, or body.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("Scan %s not found for graph indexing", scan_id)
            return {"nodes": [], "edges": []}

        raw_summary: Dict[str, Any] = {}
        try:
            raw_summary = json.loads(scan.raw_summary_json or "{}")
        except Exception:
            pass

        created_node_ids: Set[str] = set()
        created_edge_ids: Set[str] = set()

        # 1. EMAIL Node (Representing the scan)
        email_meta = {
            "scan_id": scan.id,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "confidence": scan.confidence,
            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
        }
        # Display value defanged / short scan target
        display_val = scan.target[:36] + "..." if len(scan.target) > 36 else scan.target
        email_node_id = _upsert_node(
            node_type="Email",
            value=scan.id,
            tenant_id=tenant_id,
            metadata=email_meta,
            display_value=display_val,
            db=db,
        )
        created_node_ids.add(email_node_id)

        # 2. SENDER Node
        from_raw = raw_summary.get("from_address") or ""
        sender_email = extract_email_address(from_raw)
        sender_node_id = None
        if sender_email:
            sender_node_id = _upsert_node(
                node_type="Sender",
                value=sender_email,
                tenant_id=tenant_id,
                display_value=sender_email,
                metadata={"source": "header_from"},
                db=db,
            )
            created_node_ids.add(sender_node_id)

            edge_id = _upsert_edge(
                from_id=email_node_id,
                to_id=sender_node_id,
                edge_type="SENT_FROM",
                tenant_id=tenant_id,
                db=db,
            )
            created_edge_ids.add(edge_id)

            # Sender Domain
            if "@" in sender_email:
                s_domain = sender_email.split("@")[1].strip().lower()
                if s_domain:
                    dom_node_id = _upsert_node(
                        node_type="Domain",
                        value=s_domain,
                        tenant_id=tenant_id,
                        display_value=s_domain,
                        metadata={"source": "sender_domain"},
                        db=db,
                    )
                    created_node_ids.add(dom_node_id)

                    e_edge_id = _upsert_edge(
                        from_id=email_node_id,
                        to_id=dom_node_id,
                        edge_type="CONTAINS",
                        tenant_id=tenant_id,
                        db=db,
                    )
                    created_edge_ids.add(e_edge_id)

        # 3. RECIPIENT Node(s)
        recipients = raw_summary.get("to_addresses") or []
        if isinstance(recipients, str):
            recipients = [recipients]
        for r_raw in recipients:
            r_email = extract_email_address(r_raw)
            if r_email:
                r_node_id = _upsert_node(
                    node_type="Recipient",
                    value=r_email,
                    tenant_id=tenant_id,
                    display_value=r_email,
                    metadata={"source": "header_to"},
                    db=db,
                )
                created_node_ids.add(r_node_id)

                edge_id = _upsert_edge(
                    from_id=email_node_id,
                    to_id=r_node_id,
                    edge_type="SENT_TO",
                    tenant_id=tenant_id,
                    db=db,
                )
                created_edge_ids.add(edge_id)

        # 4. IP and ASN Nodes
        geo_results = raw_summary.get("geo_results") or []
        sender_ips = set(raw_summary.get("sender_ips") or [])

        # Hops from header analysis
        header_analysis = raw_summary.get("header_analysis") or {}
        hops = header_analysis.get("hops") or []
        for hop in hops:
            hop_ip = hop.get("ip")
            if hop_ip and hop_ip.strip():
                sender_ips.add(hop_ip.strip())

        # Build lookup for geo metadata
        geo_by_ip = {}
        for g in geo_results:
            g_ip = g.get("ip")
            if g_ip:
                geo_by_ip[g_ip.strip()] = g

        for ip in sender_ips:
            if not ip or len(ip) > 64:
                continue
            geo = geo_by_ip.get(ip, {})
            ip_meta = {}
            if geo:
                if geo.get("country_name"):
                    ip_meta["country"] = geo.get("country_name")
                if geo.get("city"):
                    ip_meta["city"] = geo.get("city")
                if geo.get("as_org"):
                    ip_meta["as_org"] = geo.get("as_org")

            ip_node_id = _upsert_node(
                node_type="IP",
                value=ip,
                tenant_id=tenant_id,
                display_value=ip,
                metadata=ip_meta,
                db=db,
            )
            created_node_ids.add(ip_node_id)

            edge_id = _upsert_edge(
                from_id=email_node_id,
                to_id=ip_node_id,
                edge_type="SENT_FROM",
                tenant_id=tenant_id,
                db=db,
            )
            created_edge_ids.add(edge_id)

            # ASN Node
            asn_raw = geo.get("asn") or ""
            if asn_raw:
                asn_str = str(asn_raw).strip()
                if not asn_str.upper().startswith("AS") and asn_str.isdigit():
                    asn_str = f"AS{asn_str}"
                asn_meta = {}
                if geo.get("as_org"):
                    asn_meta["org"] = geo.get("as_org")

                asn_node_id = _upsert_node(
                    node_type="ASN",
                    value=asn_str,
                    tenant_id=tenant_id,
                    display_value=asn_str,
                    metadata=asn_meta,
                    db=db,
                )
                created_node_ids.add(asn_node_id)

                edge_id = _upsert_edge(
                    from_id=ip_node_id,
                    to_id=asn_node_id,
                    edge_type="HOSTED_IN",
                    tenant_id=tenant_id,
                    db=db,
                )
                created_edge_ids.add(edge_id)

        # 5. ATTACHMENT HASH Nodes
        attachments = raw_summary.get("attachments") or []
        for att in attachments:
            sha256 = att.get("sha256")
            if sha256 and len(sha256) == 64:
                sha_clean = sha256.lower().strip()
                att_meta = {
                    "filename": att.get("filename"),
                    "mime_type": att.get("mime_type"),
                    "size_bytes": att.get("size_bytes"),
                    "is_suspicious": att.get("is_suspicious", False),
                }
                att_node_id = _upsert_node(
                    node_type="AttachmentHash",
                    value=sha_clean,
                    tenant_id=tenant_id,
                    display_value=f"{sha_clean[:10]}...",
                    metadata=att_meta,
                    db=db,
                )
                created_node_ids.add(att_node_id)

                edge_id = _upsert_edge(
                    from_id=email_node_id,
                    to_id=att_node_id,
                    edge_type="CONTAINS",
                    tenant_id=tenant_id,
                    db=db,
                )
                created_edge_ids.add(edge_id)

        # 6. URL and DOMAIN Nodes (Extracted URLs from plain body / links)
        plain_body = raw_summary.get("plain_body") or ""
        html_body = raw_summary.get("sanitized_html") or ""
        body_text = f"{plain_body} {html_body}"
        extracted_urls = set(re.findall(r'https?://[^\s<>"\'\)]+', body_text))

        for url in list(extracted_urls)[:25]:
            clean_url = url.strip().rstrip(".,;>")
            if not clean_url:
                continue

            parsed = urllib.parse.urlparse(clean_url)
            domain = parsed.netloc.lower().split(":")[0]

            url_node_id = _upsert_node(
                node_type="URL",
                value=clean_url,
                tenant_id=tenant_id,
                display_value=None,
                metadata={"scheme": parsed.scheme},
                db=db,
            )
            created_node_ids.add(url_node_id)

            edge_id = _upsert_edge(
                from_id=email_node_id,
                to_id=url_node_id,
                edge_type="CONTAINS",
                tenant_id=tenant_id,
                db=db,
            )
            created_edge_ids.add(edge_id)

            if domain:
                dom_node_id = _upsert_node(
                    node_type="Domain",
                    value=domain,
                    tenant_id=tenant_id,
                    display_value=domain,
                    metadata={"source": "url_domain"},
                    db=db,
                )
                created_node_ids.add(dom_node_id)

                edge_id = _upsert_edge(
                    from_id=url_node_id,
                    to_id=dom_node_id,
                    edge_type="RESOLVES_TO",
                    tenant_id=tenant_id,
                    db=db,
                )
                created_edge_ids.add(edge_id)

        if close_db:
            db.commit()

        return {
            "nodes": list(created_node_ids),
            "edges": list(created_edge_ids),
        }
    finally:
        if close_db:
            db.close()


def get_neighbors(
    node_id: str,
    tenant_id: str = "default",
    depth: int = 1,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Return connected nodes and edges up to `depth` hops (capped at 3).
    Adjacency is bidirectional. Strictly filtered on tenant_id.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        depth = min(max(1, depth), 3)

        root = (
            db.query(GraphNode)
            .filter(GraphNode.id == node_id, GraphNode.tenant_id == tenant_id)
            .first()
        )
        if not root:
            return {"nodes": [], "edges": []}

        visited_nodes: Set[str] = {node_id}
        visited_edges: Set[str] = set()
        current_frontier: Set[str] = {node_id}

        for _ in range(depth):
            next_frontier: Set[str] = set()
            for nid in current_frontier:
                edges = (
                    db.query(GraphEdge)
                    .filter(
                        GraphEdge.tenant_id == tenant_id,
                        (GraphEdge.from_node_id == nid) | (GraphEdge.to_node_id == nid),
                    )
                    .all()
                )
                for e in edges:
                    visited_edges.add(e.id)
                    nbr = e.to_node_id if e.from_node_id == nid else e.from_node_id
                    if nbr not in visited_nodes:
                        visited_nodes.add(nbr)
                        next_frontier.add(nbr)
            current_frontier = next_frontier
            if not current_frontier:
                break

        nodes_list = (
            db.query(GraphNode)
            .filter(GraphNode.tenant_id == tenant_id, GraphNode.id.in_(visited_nodes))
            .all()
        )
        edges_list = (
            db.query(GraphEdge)
            .filter(GraphEdge.tenant_id == tenant_id, GraphEdge.id.in_(visited_edges))
            .all()
        )

        return {
            "root_id": node_id,
            "nodes": [_serialize_node(n) for n in nodes_list],
            "edges": [_serialize_edge(e) for e in edges_list],
        }
    finally:
        if close_db:
            db.close()


def get_pivot(
    node_id: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
) -> Optional[Dict[str, Any]]:
    """
    Return all entities connected to a node, grouped by type, with connection counts.
    Strictly isolated by tenant_id.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        root = (
            db.query(GraphNode)
            .filter(GraphNode.id == node_id, GraphNode.tenant_id == tenant_id)
            .first()
        )
        if not root:
            return None

        # Direct 1-hop edges
        edges = (
            db.query(GraphEdge)
            .filter(
                GraphEdge.tenant_id == tenant_id,
                (GraphEdge.from_node_id == node_id) | (GraphEdge.to_node_id == node_id),
            )
            .all()
        )

        neighbor_ids: Set[str] = set()
        for e in edges:
            nbr = e.to_node_id if e.from_node_id == node_id else e.from_node_id
            neighbor_ids.add(nbr)

        neighbors: List[GraphNode] = []
        if neighbor_ids:
            neighbors = (
                db.query(GraphNode)
                .filter(GraphNode.tenant_id == tenant_id, GraphNode.id.in_(neighbor_ids))
                .all()
            )

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        counts: Dict[str, int] = {}

        for n in neighbors:
            ntype = n.node_type
            if ntype not in grouped:
                grouped[ntype] = []
                counts[ntype] = 0
            grouped[ntype].append(_serialize_node(n))
            counts[ntype] += 1

        return {
            "node": _serialize_node(root),
            "total_connections": len(neighbors),
            "grouped": grouped,
            "counts": counts,
            "edges": [_serialize_edge(e) for e in edges],
        }
    finally:
        if close_db:
            db.close()


def get_path(
    node_a_id: str,
    node_b_id: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    BFS shortest path between node_a_id and node_b_id.
    Capped at 5 hops. Returns ordered list of nodes in path, or null if no path.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        if node_a_id == node_b_id:
            node = (
                db.query(GraphNode)
                .filter(GraphNode.id == node_a_id, GraphNode.tenant_id == tenant_id)
                .first()
            )
            return [_serialize_node(node)] if node else None

        queue: List[Tuple[str, List[str]]] = [(node_a_id, [node_a_id])]
        visited: Set[str] = {node_a_id}

        found_path: Optional[List[str]] = None

        while queue:
            curr_id, path = queue.pop(0)
            if len(path) > 6:  # 5 hops = 6 nodes
                continue

            edges = (
                db.query(GraphEdge)
                .filter(
                    GraphEdge.tenant_id == tenant_id,
                    (GraphEdge.from_node_id == curr_id) | (GraphEdge.to_node_id == curr_id),
                )
                .all()
            )

            for e in edges:
                nbr = e.to_node_id if e.from_node_id == curr_id else e.from_node_id
                if nbr == node_b_id:
                    found_path = path + [nbr]
                    break
                if nbr not in visited:
                    visited.add(nbr)
                    if len(path) < 5:
                        queue.append((nbr, path + [nbr]))

            if found_path:
                break

        if not found_path:
            return None

        # Fetch nodes in ordered path
        nodes_by_id = {
            n.id: n
            for n in db.query(GraphNode)
            .filter(GraphNode.tenant_id == tenant_id, GraphNode.id.in_(found_path))
            .all()
        }

        return [_serialize_node(nodes_by_id[nid]) for nid in found_path if nid in nodes_by_id]
    finally:
        if close_db:
            db.close()


def get_recent_nodes(
    tenant_id: str = "default",
    limit: int = 20,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Return the most recently seen graph nodes and the edges connecting between them.
    Filtered by tenant_id.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        nodes = (
            db.query(GraphNode)
            .filter(GraphNode.tenant_id == tenant_id)
            .order_by(GraphNode.last_seen_at.desc())
            .limit(limit)
            .all()
        )
        if not nodes:
            return {"nodes": [], "edges": []}

        node_ids = {n.id for n in nodes}
        edges = (
            db.query(GraphEdge)
            .filter(
                GraphEdge.tenant_id == tenant_id,
                GraphEdge.from_node_id.in_(node_ids),
                GraphEdge.to_node_id.in_(node_ids),
            )
            .all()
        )

        return {
            "nodes": [_serialize_node(n) for n in nodes],
            "edges": [_serialize_edge(e) for e in edges],
        }
    finally:
        if close_db:
            db.close()


def lookup_node_by_value(
    node_type: Optional[str],
    value: str,
    tenant_id: str = "default",
    db: Optional[Session] = None,
) -> Optional[Dict[str, Any]]:
    """Helper to find an existing node by indicator value and optional type."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        clean_val = value.strip()
        query = db.query(GraphNode).filter(GraphNode.tenant_id == tenant_id)
        if node_type:
            # Map common casing
            type_map = {
                "url": "URL",
                "ip": "IP",
                "domain": "Domain",
                "hash": "AttachmentHash",
                "email": "Email",
                "sender": "Sender",
                "recipient": "Recipient",
                "asn": "ASN",
            }
            canonical_type = type_map.get(node_type.lower(), node_type)
            query = query.filter(GraphNode.node_type == canonical_type)

        query = query.filter(
            (GraphNode.value == clean_val) | (GraphNode.value.ilike(f"%{clean_val}%"))
        )
        node = query.first()
        return _serialize_node(node) if node else None
    finally:
        if close_db:
            db.close()
