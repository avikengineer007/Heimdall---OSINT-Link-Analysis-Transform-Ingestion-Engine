"""
Heimdall Graph Diff Engine.

Computes temporal deltas between two investigation sessions:
  - Added nodes (new attack surface discovered)
  - Removed nodes (decommissioned or unreachable infrastructure)
  - Added / removed edges (relationship shifts)
  - Property mutations (threat score escalation, new open ports, new CVEs)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from heimdall.core.config import settings
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.graph.sqlite_store import SqliteGraphStore


@dataclass
class GraphDelta:
    """Represents the structural and attribute differences between two graphs."""
    session_a: str
    session_b: str
    computed_at: str
    added_nodes: List[Dict[str, Any]] = field(default_factory=list)
    removed_nodes: List[Dict[str, Any]] = field(default_factory=list)
    added_edges: List[Dict[str, Any]] = field(default_factory=list)
    removed_edges: List[Dict[str, Any]] = field(default_factory=list)
    changed_props: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def diff_sessions(
    session_a: str,
    session_b: str,
    db_path: Optional[str] = None,
    store_a: Optional[Any] = None,
    store_b: Optional[Any] = None,
) -> GraphDelta:
    """
    Computes a symmetric and property delta between session_a and session_b.

    Can load from in-memory stores or directly from SQLite by session_id.
    """
    # 1. Resolve nodes and edges for Session A
    nodes_a_map: Dict[str, GraphNode] = {}
    edges_a_list: List[GraphEdge] = []

    if store_a is not None:
        nodes_a_map = {n.urn: n for n in store_a.get_nodes()}
        edges_a_list = store_a.get_edges()
    else:
        target_db = db_path or settings.sqlite_db_path
        store = SqliteGraphStore(target_db)
        nodes_a = store.get_nodes_by_session(session_a)
        nodes_a_map = {n.urn: n for n in nodes_a}
        edges_a_list = store.get_edges_by_session(session_a)

    # 2. Resolve nodes and edges for Session B
    nodes_b_map: Dict[str, GraphNode] = {}
    edges_b_list: List[GraphEdge] = []

    if store_b is not None:
        nodes_b_map = {n.urn: n for n in store_b.get_nodes()}
        edges_b_list = store_b.get_edges()
    else:
        target_db = db_path or settings.sqlite_db_path
        store = SqliteGraphStore(target_db)
        nodes_b = store.get_nodes_by_session(session_b)
        nodes_b_map = {n.urn: n for n in nodes_b}
        edges_b_list = store.get_edges_by_session(session_b)

    # 3. Compute Node differences
    urns_a = set(nodes_a_map.keys())
    urns_b = set(nodes_b_map.keys())

    added_urns = urns_b - urns_a
    removed_urns = urns_a - urns_b
    common_urns = urns_a & urns_b

    added_nodes = [nodes_b_map[u].model_dump() for u in sorted(added_urns)]
    removed_nodes = [nodes_a_map[u].model_dump() for u in sorted(removed_urns)]

    # Detect changed properties on common nodes
    changed_props: Dict[str, Dict[str, Any]] = {}
    for urn in common_urns:
        na = nodes_a_map[urn]
        nb = nodes_b_map[urn]
        props_diff: Dict[str, Any] = {}

        # Check dictionary properties difference
        all_keys = set(na.properties.keys()) | set(nb.properties.keys())
        for k in all_keys:
            val_a = na.properties.get(k)
            val_b = nb.properties.get(k)
            if val_a != val_b:
                props_diff[k] = {"old": val_a, "new": val_b}

        if props_diff:
            changed_props[urn] = props_diff

    # 4. Compute Edge differences keyed by (source, rel, target)
    def edge_key(e: GraphEdge) -> Tuple[str, str, str]:
        return (e.source, e.rel, e.target)

    edges_a_map = {edge_key(e): e for e in edges_a_list}
    edges_b_map = {edge_key(e): e for e in edges_b_list}

    keys_a = set(edges_a_map.keys())
    keys_b = set(edges_b_map.keys())

    added_keys = keys_b - keys_a
    removed_keys = keys_a - keys_b

    added_edges = [edges_b_map[k].model_dump() for k in added_keys]
    removed_edges = [edges_a_map[k].model_dump() for k in removed_keys]

    summary = (
        f"Diff from {session_a[:8]} to {session_b[:8]}: "
        f"+{len(added_nodes)} / -{len(removed_nodes)} nodes, "
        f"+{len(added_edges)} / -{len(removed_edges)} edges, "
        f"{len(changed_props)} modified entities."
    )

    return GraphDelta(
        session_a=session_a,
        session_b=session_b,
        computed_at=datetime.now(timezone.utc).isoformat(),
        added_nodes=added_nodes,
        removed_nodes=removed_nodes,
        added_edges=added_edges,
        removed_edges=removed_edges,
        changed_props=changed_props,
        summary=summary,
    )
