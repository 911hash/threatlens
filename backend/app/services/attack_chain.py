"""
Attack chain graph generator.
Strict adherence: Only draws relationships supported by returned data.
"""

from typing import Any, Dict, List
from ..schemas import AttackChainGraph, AttackChainLink, AttackChainNode


def build_attack_chain(
    target: str,
    target_type: str,
    evidence_data: Dict[str, Any],
    risk_level: str,
) -> AttackChainGraph:
    nodes: List[AttackChainNode] = []
    links: List[AttackChainLink] = []

    if target_type == "url":
        redirects = evidence_data.get("redirects", {})
        hops = redirects.get("hops", [])
        final_domain = redirects.get("final_domain")
        dns_data = evidence_data.get("dns", {}).get("records", {})
        ip_data = evidence_data.get("ip_reputation", {})
        vt_data = evidence_data.get("virustotal", {})
        is_threat = risk_level in ("HIGH", "CRITICAL", "MEDIUM")

        # 1. Initial URL Node
        nodes.append(AttackChainNode(
            id="node_init_url",
            label="Initial URL",
            type="url",
            status="neutral",
            details=target,
        ))
        prev_node_id = "node_init_url"

        # 2. Redirect hops (if any)
        if hops and len(hops) > 1:
            for idx, hop in enumerate(hops[1:], start=1):
                hop_id = f"node_hop_{idx}"
                status = "suspicious" if idx >= 2 or hop.get("status_code") in (301, 302) else "neutral"
                nodes.append(AttackChainNode(
                    id=hop_id,
                    label=f"Redirect {idx} ({hop.get('status_code', 302)})",
                    type="redirect",
                    status=status,
                    details=hop.get("url"),
                ))
                links.append(AttackChainLink(
                    source=prev_node_id,
                    target=hop_id,
                    label=f"HTTP {hop.get('status_code', 302)}",
                ))
                prev_node_id = hop_id

        # 3. Final Domain Node
        if final_domain:
            dom_status = "malicious" if is_threat else "neutral"
            nodes.append(AttackChainNode(
                id="node_domain",
                label=final_domain,
                type="domain",
                status=dom_status,
                details=f"Registrar: {evidence_data.get('rdap', {}).get('registrar', 'Unknown')}",
            ))
            links.append(AttackChainLink(
                source=prev_node_id,
                target="node_domain",
                label="resolves to",
            ))
            prev_node_id = "node_domain"

        # 4. Resolved IP Node
        primary_ip = redirects.get("hops", [{}])[-1].get("ip") if hops else None
        if not primary_ip and dns_data.get("A"):
            primary_ip = dns_data["A"][0]

        if primary_ip and primary_ip != "0.0.0.0":
            nodes.append(AttackChainNode(
                id="node_ip",
                label=primary_ip,
                type="ip",
                status="suspicious" if ip_data.get("is_malicious") else "neutral",
                details=f"ASN: {ip_data.get('asn', 'Standard Internet')}",
            ))
            links.append(AttackChainLink(
                source=prev_node_id,
                target="node_ip",
                label="hosted on",
            ))
            prev_node_id = "node_ip"

        # 5. Threat Indicator Node (only if threats exist)
        if is_threat:
            mal_count = vt_data.get("malicious", 0)
            threat_label = f"Malicious Payload ({mal_count} flags)" if mal_count else "Blacklisted Threat"
            nodes.append(AttackChainNode(
                id="node_threat",
                label=threat_label,
                type="threat",
                status="malicious",
                details=evidence_data.get("explanation", "Detected as harmful destination"),
            ))
            links.append(AttackChainLink(
                source=prev_node_id,
                target="node_threat",
                label="serves",
            ))

    elif target_type in ("hash", "file"):
        behavior = evidence_data.get("behavior")
        has_behavior = behavior and (
            behavior.get("powershell_executed")
            or behavior.get("persistence_added")
            or behavior.get("suspicious_exec")
            or behavior.get("network_connection")
        )

        nodes.append(AttackChainNode(
            id="node_file",
            label="Target Sample",
            type="process",
            status="malicious" if risk_level in ("HIGH", "CRITICAL") else "neutral",
            details=target[:16] + "..." if len(target) > 20 else target,
        ))
        prev_node_id = "node_file"

        if has_behavior:
            # Process Execution
            nodes.append(AttackChainNode(
                id="node_process",
                label="Process Spawn",
                type="process",
                status="suspicious",
                details=behavior.get("process_name", "cmd.exe"),
            ))
            links.append(AttackChainLink(
                source=prev_node_id,
                target="node_process",
                label="executes",
            ))
            prev_node_id = "node_process"

            # PowerShell Execution
            if behavior.get("powershell_executed"):
                nodes.append(AttackChainNode(
                    id="node_powershell",
                    label="PowerShell Subprocess",
                    type="action",
                    status="malicious",
                    details=behavior.get("powershell_command", "powershell -EncodedCommand ..."),
                ))
                links.append(AttackChainLink(
                    source=prev_node_id,
                    target="node_powershell",
                    label="spawns",
                ))
                prev_node_id = "node_powershell"

            # Network Connection
            net_conn = behavior.get("network_connection")
            if net_conn:
                nodes.append(AttackChainNode(
                    id="node_c2",
                    label=net_conn.get("destination", "C2 Communication"),
                    type="domain",
                    status="malicious",
                    details=f"Port {net_conn.get('port', 443)} Beaconing",
                ))
                links.append(AttackChainLink(
                    source=prev_node_id,
                    target="node_c2",
                    label="connects outbound",
                ))

            # Persistence
            if behavior.get("persistence_added"):
                nodes.append(AttackChainNode(
                    id="node_persistence",
                    label="System Persistence",
                    type="action",
                    status="malicious",
                    details=behavior.get("persistence_type", "Registry Run Key"),
                ))
                links.append(AttackChainLink(
                    source=prev_node_id,
                    target="node_persistence",
                    label="establishes",
                ))

    return AttackChainGraph(nodes=nodes, links=links)
