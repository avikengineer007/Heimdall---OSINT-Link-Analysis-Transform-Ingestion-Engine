"""
Threat Intelligence Scoring Engine.

Computes a composite Threat Score (0–100) per node using a weighted
categorized-maximum-ceiling model as specified in the architecture guide:

    ThreatScore = min(100,
        W_abuse  * S_abuse   +   # 0.35 — AbuseIPDB confidence (direct, 0–100)
        W_vt     * S_vt      +   # 0.30 — VirusTotal malicious ratio scaled
        W_cve    * S_cve     +   # 0.25 — CVE severity weighted sum
        W_ports  * S_ports       # 0.10 — High-risk exposed ports
    )

Scoring factors:
  AbuseIPDB (W=0.35): Direct 0–100 confidence score from AbuseIPDB report
  VirusTotal (W=0.30): min(100, (malicious/total) * 200) — ratio amplified
  CVE Severity (W=0.25): CVSS 9.0+ → 30 pts each, 7.0–8.9 → 15 pts each
  Critical Ports (W=0.10): High-risk open ports (3389 RDP, 445 SMB, etc.)

Risk Levels:
  0–24:  Low
  25–49: Medium
  50–74: High
  75+:   Critical
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from heimdall.core.models import EntityType, GraphEdge, GraphNode
from heimdall.graph.base import BaseGraphStore

logger = logging.getLogger("heimdall.core.threat_scorer")

# Weights must sum to 1.0
W_ABUSE = 0.35
W_VT    = 0.30
W_CVE   = 0.25
W_PORTS = 0.10

# High-risk ports and their individual risk contributions (0–100 scale pre-weight)
HIGH_RISK_PORTS: Dict[int, int] = {
    23:   100,  # Telnet — plaintext remote shell
    3389: 95,   # RDP — frequent ransomware vector
    445:  90,   # SMB — EternalBlue / WannaCry
    5900: 85,   # VNC — remote desktop, often no auth
    1433: 80,   # MSSQL
    3306: 75,   # MySQL exposed to internet
    5432: 75,   # PostgreSQL
    27017: 80,  # MongoDB
    6379: 80,   # Redis (unauthenticated by default)
    9200: 75,   # Elasticsearch
    2375: 95,   # Docker daemon — unauthenticated
    2376: 85,   # Docker daemon (TLS)
    11211: 70,  # Memcached
    8080: 30,   # Alt-HTTP
    8443: 25,   # Alt-HTTPS
}


def _parse_port(port_service_value: str) -> Optional[int]:
    """Extracts port number from PortService URN value like '80/tcp' or '443'."""
    try:
        return int(port_service_value.split("/")[0])
    except (ValueError, IndexError):
        return None


def _cvss_score_to_points(cvss: float) -> int:
    """Maps a single CVE's CVSS score to threat contribution points."""
    if cvss >= 9.0:
        return 30
    elif cvss >= 7.0:
        return 15
    elif cvss >= 4.0:
        return 5
    return 0


def _risk_level(score: float) -> str:
    """Returns the categorical risk label for a numeric threat score."""
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    return "Low"


def _risk_color(level: str) -> str:
    """Returns a hex color for the risk level, used in UI rendering."""
    return {"Critical": "#ef4444", "High": "#f59e0b", "Medium": "#fbbf24", "Low": "#34d399"}.get(level, "#94a3b8")


class ThreatScorer:
    """
    Computes threat scores for graph nodes by aggregating edge properties
    contributed by intelligence transforms (Shodan, VirusTotal, AbuseIPDB).
    """

    def score_node(
        self,
        node: GraphNode,
        incoming_edges: List[GraphEdge],
        outgoing_edges: List[GraphEdge],
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Computes the threat score for a single node.

        Returns:
            (score: float, risk_level: str, breakdown: dict)
        """
        s_abuse = self._abuse_score(incoming_edges + outgoing_edges)
        s_vt    = self._vt_score(incoming_edges + outgoing_edges)
        s_cve   = self._cve_score(incoming_edges + outgoing_edges, outgoing_edges)
        s_ports = self._port_score(outgoing_edges)

        raw = W_ABUSE * s_abuse + W_VT * s_vt + W_CVE * s_cve + W_PORTS * s_ports
        score = round(min(100.0, raw), 1)
        level = _risk_level(score)

        breakdown = {
            "abuse_component": round(W_ABUSE * s_abuse, 1),
            "virustotal_component": round(W_VT * s_vt, 1),
            "cve_component": round(W_CVE * s_cve, 1),
            "ports_component": round(W_PORTS * s_ports, 1),
        }

        return score, level, breakdown

    def _abuse_score(self, edges: List[GraphEdge]) -> float:
        """AbuseIPDB: directly use the confidence_score (0–100)."""
        for edge in edges:
            if edge.rel == "HAS_ABUSE_REPORT":
                score = edge.properties.get("confidence_score")
                if isinstance(score, (int, float)):
                    return float(score)
        return 0.0

    def _vt_score(self, edges: List[GraphEdge]) -> float:
        """VirusTotal: min(100, (malicious / total) * 200)."""
        for edge in edges:
            if edge.rel == "DETECTED_BY_VIRUSTOTAL":
                malicious = edge.properties.get("malicious_engines", 0)
                total = edge.properties.get("total_engines", 1) or 1
                return min(100.0, (malicious / total) * 200.0)
        return 0.0

    def _cve_score(
        self,
        edges: List[GraphEdge],
        outgoing_edges: List[GraphEdge],
    ) -> float:
        """CVE Severity: sum CVSS-weighted points from Shodan CVE data."""
        total_points = 0.0
        for edge in edges:
            props = edge.properties
            # Shodan embeds CVEs in PortService edge properties
            vulns = props.get("vulns") or props.get("cves") or []
            if isinstance(vulns, list):
                for vuln in vulns:
                    cvss = vuln.get("cvss") if isinstance(vuln, dict) else 0
                    total_points += _cvss_score_to_points(float(cvss or 0))
            # Also handle flat dict: {"CVE-2021-xxx": {"cvss": 9.8}}
            elif isinstance(vulns, dict):
                for cve_id, cve_data in vulns.items():
                    cvss = cve_data.get("cvss", 0) if isinstance(cve_data, dict) else 0
                    total_points += _cvss_score_to_points(float(cvss or 0))
        return min(100.0, total_points)

    def _port_score(self, outgoing_edges: List[GraphEdge]) -> float:
        """Critical Attack Surface: high-risk exposed ports contribution."""
        max_port_risk = 0.0
        for edge in outgoing_edges:
            if edge.target_type == EntityType.PORT_SERVICE.value:
                port_val = edge.target.split(":", 1)[-1]
                port_num = _parse_port(port_val)
                if port_num is not None:
                    risk = HIGH_RISK_PORTS.get(port_num, 0)
                    max_port_risk = max(max_port_risk, float(risk))
        return max_port_risk

    def enrich_graph(self, store: BaseGraphStore) -> List[GraphEdge]:
        """
        Scores all scoreable nodes in the graph and injects ThreatScore edges.

        Only nodes with score > 0 receive ThreatScore graph nodes to keep the
        visualization clean.

        Returns:
            List of new ThreatScore edges added to the store.
        """
        scoreable_types = {
            EntityType.IPV4.value,
            EntityType.DOMAIN.value,
            EntityType.SUBDOMAIN.value,
            EntityType.PORT_SERVICE.value,
        }
        new_edges: List[GraphEdge] = []

        for node in store.get_nodes():
            if node.entity_type not in scoreable_types:
                continue

            all_edges = store.get_edges()
            incoming = [e for e in all_edges if e.target == node.urn]
            outgoing = [e for e in all_edges if e.source == node.urn]

            score, level, breakdown = self.score_node(node, incoming, outgoing)
            if score <= 0:
                continue

            # Store score as node property
            node.properties["threat_score"] = score
            node.properties["risk_level"] = level
            node.properties["threat_breakdown"] = breakdown

            # Emit a ThreatScore graph node linked back
            threat_key = hashlib.sha256(node.urn.encode()).hexdigest()[:16]
            threat_urn = f"{EntityType.THREAT_SCORE.value}:{threat_key}"
            edge = GraphEdge(
                source=node.urn,
                target=threat_urn,
                target_type=EntityType.THREAT_SCORE.value,
                rel="HAS_THREAT_SCORE",
                properties={
                    "score": score,
                    "risk_level": level,
                    "color": _risk_color(level),
                    **breakdown,
                },
            )
            store.add_edge(edge)
            new_edges.append(edge)
            logger.info(f"Threat score [{level}] {score}/100 → {node.urn}")

        return new_edges


# Module-level singleton
_scorer = ThreatScorer()


def compute_threat_scores(store: BaseGraphStore) -> List[GraphEdge]:
    """Convenience function: scores all nodes in the store and returns injected edges."""
    return _scorer.enrich_graph(store)
