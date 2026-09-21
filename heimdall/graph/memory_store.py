"""
In-Memory High Performance Graph Store powered by NetworkX.
"""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.base import BaseGraphStore


class MemoryGraphStore(BaseGraphStore):
    """
    In-memory graph repository providing fast traversal, neighborhood extraction,
    and link-analysis metrics.
    """

    def __init__(self):
        self._graph = nx.MultiDiGraph()
        self._edges_map: Dict[Tuple[str, str, str], GraphEdge] = {}

    def add_node(self, node: GraphNode) -> None:
        if not self._graph.has_node(node.urn):
            self._graph.add_node(
                node.urn,
                entity_type=node.entity_type,
                value=node.value,
                properties=node.properties,
            )
        else:
            self._graph.nodes[node.urn]["properties"].update(node.properties)

    def add_edge(self, edge: GraphEdge) -> bool:
        key = edge.edge_key
        if key in self._edges_map:
            # Update properties
            self._edges_map[key].properties.update(edge.properties)
            return False

        self._edges_map[key] = edge

        # Ensure endpoints exist
        if not self._graph.has_node(edge.source):
            src_type, src_val = edge.source.split(":", 1)
            self._graph.add_node(edge.source, entity_type=src_type, value=src_val, properties={})
        if not self._graph.has_node(edge.target):
            self._graph.add_node(
                edge.target,
                entity_type=edge.target_type,
                value=edge.target.split(":", 1)[1],
                properties={},
            )

        self._graph.add_edge(
            edge.source,
            edge.target,
            key=edge.rel,
            rel=edge.rel,
            target_type=edge.target_type,
            properties=edge.properties,
        )
        return True

    def add_edges(self, edges: List[GraphEdge]) -> int:
        count = 0
        for e in edges:
            if self.add_edge(e):
                count += 1
        return count

    def get_neighbors(self, urn: str, direction: str = "both") -> List[str]:
        if not self._graph.has_node(urn):
            return []
        neighbors: Set[str] = set()
        if direction in ("out", "both"):
            neighbors.update(self._graph.successors(urn))
        if direction in ("in", "both"):
            neighbors.update(self._graph.predecessors(urn))
        return list(neighbors)

    def get_edges(self) -> List[GraphEdge]:
        return list(self._edges_map.values())

    def get_node(self, urn: str) -> Optional[GraphNode]:
        if not self._graph.has_node(urn):
            return None
        data = self._graph.nodes[urn]
        return GraphNode(
            urn=urn,
            entity_type=data.get("entity_type", urn.split(":", 1)[0]),
            value=data.get("value", urn.split(":", 1)[1]),
            properties=dict(data.get("properties", {})),
        )

    def get_nodes(self) -> List[GraphNode]:
        nodes = []
        for urn, data in self._graph.nodes(data=True):
            nodes.append(
                GraphNode(
                    urn=urn,
                    entity_type=data.get("entity_type", urn.split(":", 1)[0]),
                    value=data.get("value", urn.split(":", 1)[1]),
                    properties=dict(data.get("properties", {})),
                )
            )
        return nodes

    def get_stats(self) -> Dict[str, Any]:
        node_types = collections.Counter()
        for _, data in self._graph.nodes(data=True):
            node_types[data.get("entity_type", "Unknown")] += 1

        rel_types = collections.Counter()
        for _, _, data in self._graph.edges(data=True):
            rel_types[data.get("rel", "UNKNOWN")] += 1

        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": len(self._edges_map),
            "density": round(nx.density(self._graph), 4) if self._graph.number_of_nodes() > 1 else 0.0,
            "node_types": dict(node_types),
            "relationship_types": dict(rel_types),
        }

    def extract_subgraph(self, center_urn: str, radius: int = 2) -> List[GraphEdge]:
        """Extracts ego subgraph edges within `radius` hops of the target node."""
        if not self._graph.has_node(center_urn):
            return []
        # Convert to undirected view for ego graph calculation
        undirected = self._graph.to_undirected(as_view=True)
        sub_nodes = set(nx.ego_graph(undirected, center_urn, radius=radius).nodes())
        return [e for e in self._edges_map.values() if e.source in sub_nodes and e.target in sub_nodes]

    def get_networkx_graph(self) -> nx.MultiDiGraph:
        """Returns the internal NetworkX graph instance."""
        return self._graph

    def analyze_attack_path(
        self,
        source_urn: Optional[str] = None,
        target_urn: Optional[str] = None,
        weighted: bool = True,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Computes shortest attack paths and critical attack vectors.
        If target_urn is supplied, computes path from source to target.
        If omitted, automatically finds paths from source to critical crown-jewel assets.
        """
        from heimdall.graph.attack_path import AttackPathAnalyzer
        analyzer = AttackPathAnalyzer(self.get_nodes(), self.get_edges())
        if target_urn and source_urn:
            res = analyzer.find_shortest_path(source_urn, target_urn, weighted=weighted)
            return [res.to_dict()] if res else []
        return [p.to_dict() for p in analyzer.find_critical_attack_paths(source_urn=source_urn, top_k=top_k, weighted=weighted)]

