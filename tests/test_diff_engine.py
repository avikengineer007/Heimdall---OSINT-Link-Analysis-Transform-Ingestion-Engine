"""
Tests for Heimdall Graph Diff Engine.
"""

import pytest
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.diff_engine import diff_sessions
from heimdall.graph.memory_store import MemoryGraphStore


@pytest.mark.asyncio
async def test_diff_identical_stores():
    store_a = MemoryGraphStore()
    store_b = MemoryGraphStore()

    node1 = GraphNode.from_urn("Domain:target.com", properties={"name": "target.com"})
    node2 = GraphNode.from_urn("IPv4:1.2.3.4")
    edge1 = GraphEdge(
        source=node1.urn,
        target=node2.urn,
        target_type=node2.entity_type,
        rel="RESOLVES_TO",
    )

    store_a.add_node(node1)
    store_a.add_node(node2)
    store_a.add_edge(edge1)

    store_b.add_node(node1)
    store_b.add_node(node2)
    store_b.add_edge(edge1)

    delta = await diff_sessions("sess_a", "sess_b", store_a=store_a, store_b=store_b)
    assert len(delta.added_nodes) == 0
    assert len(delta.removed_nodes) == 0
    assert len(delta.added_edges) == 0
    assert len(delta.removed_edges) == 0
    assert len(delta.changed_props) == 0


@pytest.mark.asyncio
async def test_diff_added_and_removed_nodes():
    store_a = MemoryGraphStore()
    store_b = MemoryGraphStore()

    n_common = GraphNode.from_urn("Domain:target.com")
    n_old = GraphNode.from_urn("IPv4:9.9.9.9")
    n_new = GraphNode.from_urn("Domain:new-sub.target.com")

    store_a.add_node(n_common)
    store_a.add_node(n_old)

    store_b.add_node(n_common)
    store_b.add_node(n_new)

    delta = await diff_sessions("sess_a", "sess_b", store_a=store_a, store_b=store_b)
    assert len(delta.added_nodes) == 1
    assert delta.added_nodes[0]["urn"] == "Domain:new-sub.target.com"

    assert len(delta.removed_nodes) == 1
    assert delta.removed_nodes[0]["urn"] == "IPv4:9.9.9.9"


@pytest.mark.asyncio
async def test_diff_changed_threat_score_and_properties():
    store_a = MemoryGraphStore()
    store_b = MemoryGraphStore()

    n_a = GraphNode.from_urn(
        "Domain:vuln.com",
        properties={"ports": [80], "status": "active", "threat_score": 20},
    )

    n_b = GraphNode.from_urn(
        "Domain:vuln.com",
        properties={"ports": [80, 443], "status": "active", "threat_score": 85},
    )

    store_a.add_node(n_a)
    store_b.add_node(n_b)

    delta = await diff_sessions("sess_a", "sess_b", store_a=store_a, store_b=store_b)
    assert "Domain:vuln.com" in delta.changed_props
    changes = delta.changed_props["Domain:vuln.com"]
    assert "threat_score" in changes
    assert changes["threat_score"]["old"] == 20
    assert changes["threat_score"]["new"] == 85
    assert "ports" in changes


@pytest.mark.asyncio
async def test_diff_added_and_removed_edges():
    store_a = MemoryGraphStore()
    store_b = MemoryGraphStore()

    n1 = GraphNode.from_urn("Domain:test.com")
    n2 = GraphNode.from_urn("IPv4:1.1.1.1")
    n3 = GraphNode.from_urn("IPv4:2.2.2.2")

    store_a.add_node(n1)
    store_a.add_node(n2)
    store_a.add_node(n3)

    store_b.add_node(n1)
    store_b.add_node(n2)
    store_b.add_node(n3)

    edge_old = GraphEdge(source=n1.urn, target=n2.urn, target_type="IPv4", rel="RESOLVES_TO")
    edge_new = GraphEdge(source=n1.urn, target=n3.urn, target_type="IPv4", rel="RESOLVES_TO")

    store_a.add_edge(edge_old)
    store_b.add_edge(edge_new)

    delta = await diff_sessions("sess_a", "sess_b", store_a=store_a, store_b=store_b)
    assert len(delta.added_edges) == 1
    assert delta.added_edges[0]["target"] == n3.urn
    assert len(delta.removed_edges) == 1
    assert delta.removed_edges[0]["target"] == n2.urn


@pytest.mark.asyncio
async def test_diff_summary_formatting():
    store_a = MemoryGraphStore()
    store_b = MemoryGraphStore()
    delta = await diff_sessions("session_11111111", "session_22222222", store_a=store_a, store_b=store_b)
    assert "session_" in delta.summary
    assert "+0 / -0 nodes" in delta.summary
