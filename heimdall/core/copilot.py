"""
Threat Copilot - Natural Language Graph Querying and Automated CISO Threat Briefings.

Provides deterministic zero-key heuristic intent parsing for OSINT graph exploration,
natural language entity filtering, risk isolation, and automated executive threat
intelligence briefing generation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from heimdall.core.models import EntityType, GraphEdge, GraphNode


class ThreatCopilot:
    """Intelligent threat intelligence copilot for graph querying and briefing."""

    def __init__(self) -> None:
        self.port_service_map = {
            "22": "SSH",
            "21": "FTP",
            "23": "Telnet",
            "25": "SMTP",
            "53": "DNS",
            "80": "HTTP",
            "443": "HTTPS",
            "445": "SMB",
            "3389": "RDP",
            "3306": "MySQL",
            "5432": "PostgreSQL",
            "6379": "Redis",
            "27017": "MongoDB",
            "9200": "Elasticsearch",
            "8080": "HTTP-Alt",
            "8443": "HTTPS-Alt",
        }

    def parse_query(
        self,
        query: str,
        nodes: List[GraphNode],
        edges: List[GraphEdge],
    ) -> Dict[str, Any]:
        """
        Parse natural language query against graph nodes & edges.

        Returns matching node IDs, edge IDs, human-readable answer, and actionable filters.
        """
        q = query.lower().strip()
        matched_nodes: Set[str] = set()
        interpretation = "Full graph search"
        intent_type = "general"

        # 1. High risk / critical assets
        if any(term in q for term in ["high risk", "critical", "vulnerab", "threat", "danger", "severe"]):
            intent_type = "high_risk"
            interpretation = "Filtering high-risk assets (threat score >= 50 or vulnerability indicators)"
            for n in nodes:
                score = n.properties.get("threat_score", 0)
                if (
                    score >= 50
                    or n.entity_type in (EntityType.TAKEOVER_VULNERABILITY, EntityType.EXPOSURE_LEAK)
                    or "vulnerability" in n.properties
                    or n.properties.get("is_vulnerable")
                ):
                    matched_nodes.add(n.urn)

        # 2. Cloud buckets & storage
        elif any(term in q for term in ["bucket", "s3", "storage", "cloud blob", "azure blob", "gcs"]):
            intent_type = "cloud_storage"
            interpretation = "Filtering cloud storage buckets and public data repositories"
            for n in nodes:
                if n.entity_type == EntityType.CLOUD_BUCKET or "bucket" in n.value.lower() or "s3" in n.value.lower():
                    matched_nodes.add(n.urn)

        # 3. Subdomain takeover
        elif any(term in q for term in ["takeover", "dangling", "cname", "hijack"]):
            intent_type = "subdomain_takeover"
            interpretation = "Filtering dangling CNAMEs and potential subdomain takeovers"
            for n in nodes:
                if (
                    n.entity_type == EntityType.TAKEOVER_VULNERABILITY
                    or n.properties.get("is_vulnerable")
                    or "takeover" in n.properties
                    or "takeover" in n.value.lower()
                ):
                    matched_nodes.add(n.urn)

        # 4. Exposure leaks (.env, git, backups)
        elif any(term in q for term in ["leak", "exposure", ".env", "git", "config", "backup", "secret", "credential"]):
            intent_type = "exposure_leaks"
            interpretation = "Filtering sensitive file exposures, config leaks, and secret dumps"
            for n in nodes:
                if n.entity_type == EntityType.EXPOSURE_LEAK or "leak" in n.value.lower() or ".env" in n.value.lower():
                    matched_nodes.add(n.urn)

        # 5. Databases
        elif any(term in q for term in ["database", "db", "sql", "postgres", "mysql", "mongo", "redis", "elastic"]):
            intent_type = "database_assets"
            interpretation = "Filtering exposed database servers and persistent stores"
            db_ports = {"3306", "5432", "6379", "27017", "9200", "1433", "1521"}
            for n in nodes:
                port = str(n.properties.get("port", ""))
                val = n.value.lower()
                if port in db_ports or any(db in val for db in ["postgres", "mysql", "mongo", "redis", "elastic"]):
                    matched_nodes.add(n.urn)

        # 6. Remote access / Admin management (RDP, SSH, Telnet, SMB)
        elif any(term in q for term in ["rdp", "ssh", "remote", "admin", "management", "smb"]):
            intent_type = "remote_admin"
            interpretation = "Filtering exposed administrative management ports (SSH, RDP, SMB)"
            mgmt_ports = {"22", "3389", "445", "23", "21"}
            for n in nodes:
                port = str(n.properties.get("port", ""))
                val = n.value.lower()
                if port in mgmt_ports or any(p in val for p in ["ssh", "rdp", "smb"]):
                    matched_nodes.add(n.urn)

        # 7. Specific Entity Types (e.g., "show subdomains", "list ip", "show emails")
        elif "subdomain" in q:
            intent_type = "entity_filter"
            interpretation = "Filtering all discovered subdomains"
            for n in nodes:
                if n.entity_type == EntityType.SUBDOMAIN:
                    matched_nodes.add(n.urn)
        elif "ip" in q or "ipv4" in q or "address" in q:
            intent_type = "entity_filter"
            interpretation = "Filtering all IP addresses"
            for n in nodes:
                if n.entity_type in (EntityType.IPV4, EntityType.IPV6):
                    matched_nodes.add(n.urn)
        elif "email" in q:
            intent_type = "entity_filter"
            interpretation = "Filtering email addresses"
            for n in nodes:
                if n.entity_type == EntityType.EMAIL:
                    matched_nodes.add(n.urn)
        elif "port" in q or "service" in q:
            intent_type = "entity_filter"
            interpretation = "Filtering open ports and listening services"
            for n in nodes:
                if n.entity_type in (EntityType.PORT, EntityType.SERVICE):
                    matched_nodes.add(n.urn)

        # 8. Specific port number search (e.g., "port 443" or "3389")
        else:
            port_match = re.search(r"\bport\s*(\d+)\b", q)
            if port_match:
                port_num = port_match.group(1)
                intent_type = "port_filter"
                interpretation = f"Filtering nodes associated with port {port_num}"
                for n in nodes:
                    if str(n.properties.get("port", "")) == port_num or f":{port_num}" in n.value:
                        matched_nodes.add(n.urn)
            else:
                # 9. Free-text search across node values and property contents
                search_term = q
                intent_type = "text_search"
                interpretation = f"Searching for keyword '{search_term}' across graph entities"
                for n in nodes:
                    if (
                        search_term in n.value.lower()
                        or any(search_term in str(v).lower() for v in n.properties.values())
                    ):
                        matched_nodes.add(n.urn)

        # Filter edges where both endpoints are in matched_nodes (or at least one endpoint)
        matched_edges: List[Dict[str, Any]] = []
        for e in edges:
            if e.source_urn in matched_nodes or e.target_urn in matched_nodes:
                matched_edges.append(
                    {
                        "source": e.source_urn,
                        "target": e.target_urn,
                        "relationship": e.relationship,
                    }
                )

        # Format descriptive answer
        count = len(matched_nodes)
        if count == 0:
            answer = f"No entities matched your query: '{query}'. Try searching for 'high risk', 'cloud buckets', 'databases', or 'subdomains'."
        else:
            answer = f"Found {count} matching asset{'s' if count != 1 else ''} based on: {interpretation}."

        return {
            "query": query,
            "interpretation": interpretation,
            "intent_type": intent_type,
            "matched_count": count,
            "matched_nodes": sorted(list(matched_nodes)),
            "matched_edges": matched_edges,
            "answer": answer,
        }

    def generate_executive_briefing(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge],
        attack_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate an automated CISO Executive Threat Intelligence Briefing.
        Synthesizes graph telemetry, risk distribution, and attack chain posture.
        """
        total_assets = len(nodes)
        high_risk_nodes = [n for n in nodes if n.properties.get("threat_score", 0) >= 70]
        medium_risk_nodes = [n for n in nodes if 40 <= n.properties.get("threat_score", 0) < 70]
        takeover_nodes = [
            n for n in nodes if n.entity_type == EntityType.TAKEOVER_VULNERABILITY or n.properties.get("is_vulnerable")
        ]
        bucket_nodes = [n for n in nodes if n.entity_type == EntityType.CLOUD_BUCKET]
        leak_nodes = [n for n in nodes if n.entity_type == EntityType.EXPOSURE_LEAK]
        exposed_services = [n for n in nodes if n.entity_type in (EntityType.PORT, EntityType.SERVICE)]

        # Calculate overall threat posture rating
        if len(takeover_nodes) > 0 or len(leak_nodes) > 0 or len(high_risk_nodes) >= 3:
            posture_rating = "CRITICAL"
            posture_color = "#ef4444"
        elif len(high_risk_nodes) > 0 or len(bucket_nodes) > 0 or len(medium_risk_nodes) >= 5:
            posture_rating = "ELEVATED"
            posture_color = "#f97316"
        elif len(medium_risk_nodes) > 0 or len(exposed_services) > 5:
            posture_rating = "MODERATE"
            posture_color = "#eab308"
        else:
            posture_rating = "SECURE / LOW"
            posture_color = "#22c55e"

        # Generate top strategic key findings
        key_findings: List[str] = []
        if takeover_nodes:
            key_findings.append(
                f"[HIGH SEVERITY] Identified {len(takeover_nodes)} dangling DNS CNAME records vulnerable to Subdomain Takeover."
            )
        if leak_nodes:
            key_findings.append(
                f"[CRITICAL] Detected {len(leak_nodes)} exposed configuration/credential files (.env, .git, docker-compose)."
            )
        if bucket_nodes:
            key_findings.append(
                f"[WARNING] Discovered {len(bucket_nodes)} public cloud storage buckets (S3 / Azure / GCS)."
            )
        if attack_paths:
            key_findings.append(
                f"[ATTACK SURFACE] Mapped {len(attack_paths)} active attack progression paths from external perimeter to high-value assets."
            )
        if not key_findings:
            key_findings.append("No critical vulnerabilities or exposed infrastructure leaks observed on inspected surface.")

        # Strategic recommendations
        recommendations: List[str] = []
        if takeover_nodes:
            recommendations.append("Immediately remove dangling CNAME records at the authoritative DNS provider or reclaim abandoned cloud resources.")
        if leak_nodes:
            recommendations.append("Block web server directory traversal / dotfile access and rotate all credentials found in leaked configuration files.")
        if bucket_nodes:
            recommendations.append("Apply Cloud Storage Public Access Prevention (Uniform Bucket-Level Access) and audit ACLs on discovered buckets.")
        if exposed_services:
            recommendations.append("Place administrative interfaces (SSH, RDP, Database ports) behind zero-trust network access (ZTNA) or VPN.")
        if not recommendations:
            recommendations.append("Continue periodic reconnaissance and automated monitoring of DNS and certificate transparency changes.")

        briefing_text = (
            f"EXECUTIVE SUMMARY:\n"
            f"Heimdall completed autonomous link analysis on {total_assets} infrastructure assets across {len(edges)} relational linkages.\n"
            f"The current attack surface threat posture is rated as {posture_rating}.\n\n"
            f"KEY RISK METRICS:\n"
            f"- High-Risk Perimeter Assets: {len(high_risk_nodes)}\n"
            f"- Subdomain Takeovers: {len(takeover_nodes)}\n"
            f"- Sensitive File Leaks: {len(leak_nodes)}\n"
            f"- Exposed Cloud Buckets: {len(bucket_nodes)}\n"
            f"- Open Services/Ports: {len(exposed_services)}\n"
            f"- Mapped Exploitable Attack Paths: {len(attack_paths or [])}\n"
        )

        return {
            "posture_rating": posture_rating,
            "posture_color": posture_color,
            "total_assets": total_assets,
            "high_risk_count": len(high_risk_nodes),
            "takeovers_count": len(takeover_nodes),
            "leaks_count": len(leak_nodes),
            "buckets_count": len(bucket_nodes),
            "exposed_services_count": len(exposed_services),
            "attack_paths_count": len(attack_paths or []),
            "key_findings": key_findings,
            "recommendations": recommendations,
            "summary_text": briefing_text,
        }
