"""
Graph Database and Storage Abstraction Layer.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Set
from heimdall.core.models import GraphEdge, GraphNode


class BaseGraphStore(abc.ABC):
    """Abstract interface for graph persistence and topology exploration."""

    @abc.abstractmethod
    def add_node(self, node: GraphNode) -> None:
        """Adds or updates a node in the graph."""
        pass

    @abc.abstractmethod
    def add_edge(self, edge: GraphEdge) -> bool:
        """Adds a directed edge. Returns True if edge was newly inserted."""
        pass

    @abc.abstractmethod
    def add_edges(self, edges: List[GraphEdge]) -> int:
        """Batch adds edges. Returns count of newly inserted edges."""
        pass

    @abc.abstractmethod
    def get_neighbors(self, urn: str, direction: str = "both") -> List[str]:
        """Returns adjacent node URNs (direction: 'out', 'in', 'both')."""
        pass

    @abc.abstractmethod
    def get_edges(self) -> List[GraphEdge]:
        """Returns all recorded graph edges."""
        pass

    @abc.abstractmethod
    def get_nodes(self) -> List[GraphNode]:
        """Returns all recorded graph nodes."""
        pass

    @abc.abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Returns graph metrics (node count, edge count, density, types breakdown)."""
        pass
