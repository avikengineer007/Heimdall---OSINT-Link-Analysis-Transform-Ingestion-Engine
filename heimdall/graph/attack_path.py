"""
Attack Path Analysis Engine.

Computes optimal lateral movement vectors and shortest attack paths across
the OSINT infrastructure graph using both unweighted (fewest hops) and
risk-weighted (least resistance Dijkstra) algorithms.
"""

from __future__ import annotations

import collections
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from heimdall.core.models import GraphEdge, GraphNode

logger = logging.getLogger("heimdall.graph.attack_path")

# Ports generally considered high-value or high-risk targets
SENSITIVE_PORTS: Set[int] = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    3389,  # RDP
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    27017, # MongoDB
    8080,  # Alternative HTTP / Management
    8443,  # Alternative HTTPS / Management
    9000,  # SonarQube / Admin
}


@dataclass
class AttackHop:
    """Represents a single traversal step along an attack path."""
    source_urn: str
    target_urn: str
    relation: str
    target_type: str
    target_threat_score: float
    hop_resistance: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathResult:
    """Detailed analysis result for a single attack path."""
    source_urn: str
    target_urn: str
    hop_count: int
    total_resistance: float
    average_threat_score: float
    path_urns: List[str]
    hops: List[AttackHop]
    narrative: str
    chokepoints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_urn": self.source_urn,
            "target_urn": self.target_urn,
            "hop_count": self.hop_count,
            "total_resistance": round(self.total_resistance, 2),
            "average_threat_score": round(self.average_threat_score, 1),
            "path_urns": self.path_urns,
            "hops": [h.to_dict() for h in self.hops],
            "narrative": self.narrative,
            "chokepoints": self.chokepoints,
        }


class AttackPathAnalyzer:
    """
    Computes shortest attack paths and critical attack vectors across an OSINT graph.
    """

    def __init__(self, nodes: List[GraphNode], edges: List[GraphEdge]):
        self.nodes_map: Dict[str, GraphNode] = {n.urn: n for n in nodes}
        self.edges = edges
        self._graph = self._build_graph(nodes, edges)

    @staticmethod
    def _build_graph(nodes: List[GraphNode], edges: List[GraphEdge]) -> nx.DiGraph:
        """
        Builds a directed NetworkX graph with resistance weights.
        Lower resistance = easier for an adversary to traverse.
        """
        g = nx.DiGraph()

        for n in nodes:
            t_score = n.properties.get("threat_score") if hasattr(n, "properties") else getattr(n, "threat_score", 0.0)
            g.add_node(
                n.urn,
                threat_score=float(t_score or 0.0),
                entity_type=n.entity_type,
                value=n.value,
                properties=n.properties,
            )

        for e in edges:
            if not g.has_node(e.source):
                s_type, s_val = e.source.split(":", 1) if ":" in e.source else ("Unknown", e.source)
                g.add_node(e.source, threat_score=0.0, entity_type=s_type, value=s_val, properties={})
            if not g.has_node(e.target):
                t_type, t_val = e.target.split(":", 1) if ":" in e.target else (e.target_type, e.target)
                g.add_node(e.target, threat_score=0.0, entity_type=t_type, value=t_val, properties={})

            target_threat = g.nodes[e.target].get("threat_score", 0.0)
            # Resistance: High threat or high exposure nodes have low resistance (easy attack vector)
            # Resistance ranges from 1.0 (trivial, highly vulnerable) to 100.0 (well hardened)
            resistance = max(1.0, 100.0 - target_threat)

            # In link-analysis, relationships can often be traversed forward or backward by an attacker
            # (e.g. Domain -> IP via RESOLVES_TO can also mean attacker on IP compromises hosted Domain)
            # We record forward edge with primary weight and reverse with slight penalty
            g.add_edge(e.source, e.target, rel=e.rel, weight=resistance, forward=True)
            if not g.has_edge(e.target, e.source):
                g.add_edge(e.target, e.source, rel=f"REV_{e.rel}", weight=resistance * 1.25, forward=False)

        return g

    def find_shortest_path(
        self,
        source_urn: str,
        target_urn: str,
        weighted: bool = True,
    ) -> Optional[AttackPathResult]:
        """
        Finds the shortest attack path between source and target.
        If weighted=True, uses Dijkstra on attack resistance (least resistance path).
        If weighted=False, uses standard BFS (fewest hops).
        """
        if not self._graph.has_node(source_urn) or not self._graph.has_node(target_urn):
            return None
        if source_urn == target_urn:
            return None

        try:
            if weighted:
                path = nx.dijkstra_path(self._graph, source_urn, target_urn, weight="weight")
            else:
                path = nx.shortest_path(self._graph, source_urn, target_urn)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

        return self._construct_path_result(path)

    def find_critical_attack_paths(
        self,
        source_urn: Optional[str] = None,
        top_k: int = 5,
        min_risk: float = 60.0,
        weighted: bool = True,
    ) -> List[AttackPathResult]:
        """
        Automatically identifies high-value / critical targets in the graph and computes
        the shortest paths to each from the given source (or seed entrypoint).
        """
        # Determine source
        if not source_urn:
            # Pick first Domain or high-degree root node as default entry
            domain_nodes = [
                u for u, d in self._graph.nodes(data=True)
                if d.get("entity_type") in ("Domain", "DomainName")
            ]
            source_urn = domain_nodes[0] if domain_nodes else (list(self._graph.nodes())[0] if self._graph.nodes() else None)

        if not source_urn or not self._graph.has_node(source_urn):
            return []

        # Identify Crown Jewels / High-Risk Targets
        critical_targets: List[Tuple[str, float]] = []
        for urn, data in self._graph.nodes(data=True):
            if urn == source_urn:
                continue

            threat = data.get("threat_score", 0.0)
            entity_type = data.get("entity_type", "")
            val = data.get("value", "")

            is_sensitive_port = False
            if entity_type in ("Port", "Service", "PortService"):
                import re
                match = re.search(r"(\d+)", val)
                if match:
                    try:
                        port_num = int(match.group(1))
                        if port_num in SENSITIVE_PORTS:
                            is_sensitive_port = True
                    except ValueError:
                        pass

            if threat >= min_risk or is_sensitive_port:
                effective_priority = threat + (25.0 if is_sensitive_port else 0.0)
                critical_targets.append((urn, effective_priority))

        # Graceful fallback: If graph has 0 high-risk nodes, target highest-exposure operational nodes (IPs, Ports, Services)
        if not critical_targets:
            for urn, data in self._graph.nodes(data=True):
                if urn == source_urn:
                    continue
                threat = data.get("threat_score", 0.0)
                e_type = data.get("entity_type", "")
                type_boost = 15.0 if e_type in ("IPv4", "IPv6", "Port", "Service", "PortService") else 0.0
                critical_targets.append((urn, threat + type_boost))

        # Sort targets by priority descending
        critical_targets.sort(key=lambda x: x[1], reverse=True)

        results: List[AttackPathResult] = []
        for target_urn, _ in critical_targets:
            res = self.find_shortest_path(source_urn, target_urn, weighted=weighted)
            if res:
                results.append(res)
            if len(results) >= top_k:
                break

        # Calculate chokepoints across all discovered paths
        if results:
            chokepoints = self._identify_chokepoints(results, exclude_nodes={source_urn})
            for r in results:
                r.chokepoints = [cp for cp in chokepoints if cp in r.path_urns]

        return results

    def _construct_path_result(self, path: List[str]) -> AttackPathResult:
        """Constructs rich narrative and metrics for a traversal path."""
        hops: List[AttackHop] = []
        total_resistance = 0.0
        threat_scores: List[float] = []

        for i in range(len(path) - 1):
            u = path[i]
            v = path[i + 1]
            edge_data = self._graph.get_edge_data(u, v) or {}
            rel = edge_data.get("rel", "CONNECTED_TO")
            resistance = edge_data.get("weight", 1.0)
            target_data = self._graph.nodes[v]
            target_threat = target_data.get("threat_score", 0.0)
            target_type = target_data.get("entity_type", v.split(":", 1)[0] if ":" in v else "Unknown")

            total_resistance += resistance
            threat_scores.append(target_threat)

            hops.append(
                AttackHop(
                    source_urn=u,
                    target_urn=v,
                    relation=rel,
                    target_type=target_type,
                    target_threat_score=target_threat,
                    hop_resistance=round(resistance, 2),
                )
            )

        avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
        narrative = self._generate_narrative(path, hops)

        return AttackPathResult(
            source_urn=path[0],
            target_urn=path[-1],
            hop_count=len(path) - 1,
            total_resistance=total_resistance,
            average_threat_score=avg_threat,
            path_urns=path,
            hops=hops,
            narrative=narrative,
        )

    @staticmethod
    def _generate_narrative(path: List[str], hops: List[AttackHop]) -> str:
        """Generates a human-readable kill-chain narrative."""
        if not hops:
            return f"Entrypoint {path[0]} is identical to target."

        parts = [f"Adversary begins at entrypoint `{path[0]}`."]
        for i, hop in enumerate(hops, 1):
            parts.append(
                f"Hop {i}: Pivots via `{hop.relation}` to `{hop.target_urn}` "
                f"[{hop.target_type}] (threat score: {hop.target_threat_score})."
            )
        parts.append(f"Compromise vector reaches terminal target `{path[-1]}`.")
        return " ".join(parts)

    @staticmethod
    def _identify_chokepoints(
        paths: List[AttackPathResult],
        exclude_nodes: Optional[Set[str]] = None,
    ) -> List[str]:
        """
        Finds nodes that appear most frequently across multiple attack vectors.
        Isolating these nodes delivers maximum defensive ROI.
        """
        exclude = exclude_nodes or set()
        counts: collections.Counter[str] = collections.Counter()

        for p in paths:
            # Exclude endpoints of each path
            intermediates = set(p.path_urns[1:-1])
            for node in intermediates:
                if node not in exclude:
                    counts[node] += 1

        # Return top intermediary nodes sorted by frequency
        return [node for node, cnt in counts.most_common(5) if cnt > 1]
