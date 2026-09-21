"""
Graph Community Detection & Infrastructure Clustering Engine.

Uses NetworkX modularity optimization to partition the infrastructure graph
into distinct functional clusters (e.g. DNS routing, Cloud Storage, Web Surface,
Internal Staging). Identifies key hub nodes and bridge conduits.
"""

from __future__ import annotations

import collections
import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from heimdall.core.models import GraphEdge, GraphNode

logger = logging.getLogger("heimdall.graph.clustering")


@dataclass
class CommunityCluster:
    cluster_id: str
    label: str
    size: int
    hub_node: str
    density: float
    average_threat_score: float
    node_urns: List[str]
    dominant_type: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["node_count"] = self.size
        d["nodes"] = self.node_urns
        d["avg_threat_score"] = self.average_threat_score
        return d


class GraphCommunityDetector:
    """
    Partitions complex link-analysis topology into modular communities.
    """

    def detect_communities(self, nodes: List[GraphNode], edges: List[GraphEdge]) -> List[Dict[str, Any]]:
        clusters = self.detect(nodes, edges)
        return [c.to_dict() for c in clusters]

    @classmethod
    def detect(cls, nodes: List[GraphNode], edges: List[GraphEdge]) -> List[CommunityCluster]:

        if not nodes:
            return []

        # Build undirected graph for modularity clustering
        g = nx.Graph()
        nodes_dict = {n.urn: n for n in nodes}

        for n in nodes:
            t_score = n.properties.get("threat_score") if hasattr(n, "properties") else getattr(n, "threat_score", 0.0)
            g.add_node(
                n.urn,
                entity_type=n.entity_type,
                threat_score=float(t_score or 0.0),
            )

        for e in edges:
            if not g.has_node(e.source):
                g.add_node(e.source, entity_type=e.source.split(":", 1)[0] if ":" in e.source else "Unknown", threat_score=0.0)
            if not g.has_node(e.target):
                g.add_node(e.target, entity_type=e.target_type, threat_score=0.0)
            g.add_edge(e.source, e.target)

        # Detect communities using Clauset-Newman-Moore greedy modularity maximization
        try:
            communities = list(nx.community.greedy_modularity_communities(g))
        except Exception as exc:
            logger.warning(f"Community detection fallback to connected components: {exc}")
            communities = list(nx.connected_components(g))

        clusters: List[CommunityCluster] = []
        for idx, comm in enumerate(communities, 1):
            comm_nodes = list(comm)
            if not comm_nodes:
                continue

            subgraph = g.subgraph(comm_nodes)
            density = nx.density(subgraph) if len(comm_nodes) > 1 else 1.0

            # Hub node is the node with highest degree in the cluster
            degrees = dict(subgraph.degree())
            hub_node = max(degrees.items(), key=lambda x: x[1])[0]

            # Determine dominant type and average threat score
            type_counts = collections.Counter()
            threat_sum = 0.0

            for u in comm_nodes:
                u_data = g.nodes[u]
                type_counts[u_data.get("entity_type", "Unknown")] += 1
                threat_sum += u_data.get("threat_score", 0.0)

            dominant_type = type_counts.most_common(1)[0][0] if type_counts else "Generic"
            avg_threat = threat_sum / len(comm_nodes)

            # Assign intuitive semantic label
            label = cls._generate_cluster_label(dominant_type, hub_node, idx)

            clusters.append(
                CommunityCluster(
                    cluster_id=f"cluster_{idx}",
                    label=label,
                    size=len(comm_nodes),
                    hub_node=hub_node,
                    density=round(density, 3),
                    average_threat_score=round(avg_threat, 1),
                    node_urns=comm_nodes,
                    dominant_type=dominant_type,
                )
            )

        # Sort clusters by size descending
        clusters.sort(key=lambda c: c.size, reverse=True)
        return clusters

    @staticmethod
    def _generate_cluster_label(dominant_type: str, hub_node: str, idx: int) -> str:
        hub_clean = hub_node.split(":", 1)[1] if ":" in hub_node else hub_node
        if dominant_type in ("Domain", "Subdomain"):
            return f"Web & Domain Perimeter ({hub_clean})"
        elif dominant_type in ("IPv4", "IPv6", "ASNumber"):
            return f"IP & Routing Infrastructure ({hub_clean})"
        elif dominant_type in ("CloudBucket",):
            return f"Cloud Storage Cluster ({hub_clean})"
        elif dominant_type in ("Port", "Service", "PortService"):
            return f"Exposed Services Cluster ({hub_clean})"
        elif dominant_type in ("MXServer", "SPFRecord", "DMARCPolicy"):
            return f"Email & Mail Exchange Perimeter ({hub_clean})"
        return f"{dominant_type} Community #{idx}"


GraphClusterEngine = GraphCommunityDetector

