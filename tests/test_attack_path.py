"""
Unit and integration tests for Shortest Path of Attack analysis engine.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from heimdall.api.app import app, investigation_stores
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.attack_path import AttackPathAnalyzer
from heimdall.graph.memory_store import MemoryGraphStore


def _build_test_graph() -> MemoryGraphStore:
    """
    Constructs a multi-hop test attack surface graph:
    Domain:corp.com
      ├──> Subdomain:vpn.corp.com (Threat: 20)
      │     └──> IPv4:10.0.0.1 (Threat: 30)
      │           └──> Port:443 (Threat: 10)
      └──> Subdomain:legacy.corp.com (Threat: 80)  <-- Weak link / easy vector
            └──> IPv4:10.0.0.2 (Threat: 75)
                  └──> Port:3389 (Threat: 95)       <-- Crown Jewel / Target
    """
    store = MemoryGraphStore()

    nodes = [
        GraphNode(urn="Domain:corp.com", entity_type="Domain", value="corp.com", threat_score=10.0),
        GraphNode(urn="Subdomain:vpn.corp.com", entity_type="Subdomain", value="vpn.corp.com", threat_score=20.0),
        GraphNode(urn="IPv4:10.0.0.1", entity_type="IPv4", value="10.0.0.1", threat_score=30.0),
        GraphNode(urn="Port:443", entity_type="Port", value="443", threat_score=10.0),
        GraphNode(urn="Subdomain:legacy.corp.com", entity_type="Subdomain", value="legacy.corp.com", threat_score=80.0),
        GraphNode(urn="IPv4:10.0.0.2", entity_type="IPv4", value="10.0.0.2", threat_score=75.0),
        GraphNode(urn="Port:3389", entity_type="Port", value="3389", threat_score=95.0),
    ]
    for n in nodes:
        store.add_node(n)

    edges = [
        GraphEdge(source="Domain:corp.com", target="Subdomain:vpn.corp.com", rel="HAS_SUBDOMAIN", target_type="Subdomain"),
        GraphEdge(source="Subdomain:vpn.corp.com", target="IPv4:10.0.0.1", rel="RESOLVES_TO", target_type="IPv4"),
        GraphEdge(source="IPv4:10.0.0.1", target="Port:443", rel="EXPOSES_PORT", target_type="Port"),
        GraphEdge(source="Domain:corp.com", target="Subdomain:legacy.corp.com", rel="HAS_SUBDOMAIN", target_type="Subdomain"),
        GraphEdge(source="Subdomain:legacy.corp.com", target="IPv4:10.0.0.2", rel="RESOLVES_TO", target_type="IPv4"),
        GraphEdge(source="IPv4:10.0.0.2", target="Port:3389", rel="EXPOSES_PORT", target_type="Port"),
    ]
    store.add_edges(edges)
    return store


def test_shortest_path_unweighted_and_weighted():
    store = _build_test_graph()
    analyzer = AttackPathAnalyzer(store.get_nodes(), store.get_edges())

    # Path from Domain:corp.com to Port:3389
    res = analyzer.find_shortest_path("Domain:corp.com", "Port:3389", weighted=True)
    assert res is not None
    assert res.source_urn == "Domain:corp.com"
    assert res.target_urn == "Port:3389"
    assert res.hop_count == 3
    assert res.path_urns == [
        "Domain:corp.com",
        "Subdomain:legacy.corp.com",
        "IPv4:10.0.0.2",
        "Port:3389",
    ]
    assert len(res.hops) == 3
    assert "narrative" in res.to_dict()
    assert "Adversary begins" in res.narrative


def test_dijkstra_least_resistance_choice():
    """
    Verify that Dijkstra prioritizes the path with lower resistance (higher threat score).
    """
    store = MemoryGraphStore()
    # Route 1: corp -> hard_pivot -> target (resistance high: 100 - 10 = 90)
    # Route 2: corp -> weak_pivot -> target (resistance low: 100 - 90 = 10)
    store.add_node(GraphNode(urn="Domain:corp.com", entity_type="Domain", value="corp.com", threat_score=0.0))
    store.add_node(GraphNode(urn="Host:hard", entity_type="Host", value="hard", threat_score=10.0))
    store.add_node(GraphNode(urn="Host:weak", entity_type="Host", value="weak", threat_score=90.0))
    store.add_node(GraphNode(urn="Target:crown", entity_type="Target", value="crown", threat_score=100.0))

    store.add_edge(GraphEdge(source="Domain:corp.com", target="Host:hard", rel="CONNECTS", target_type="Host"))
    store.add_edge(GraphEdge(source="Host:hard", target="Target:crown", rel="ACCESSES", target_type="Target"))
    store.add_edge(GraphEdge(source="Domain:corp.com", target="Host:weak", rel="CONNECTS", target_type="Host"))
    store.add_edge(GraphEdge(source="Host:weak", target="Target:crown", rel="ACCESSES", target_type="Target"))

    analyzer = AttackPathAnalyzer(store.get_nodes(), store.get_edges())
    res = analyzer.find_shortest_path("Domain:corp.com", "Target:crown", weighted=True)
    assert res is not None
    assert res.path_urns[1] == "Host:weak"  # Weak link selected by least resistance


def test_auto_detect_critical_targets():
    store = _build_test_graph()
    analyzer = AttackPathAnalyzer(store.get_nodes(), store.get_edges())

    # Critical targets: Port:3389 (sensitive port & threat 95), Subdomain:legacy, IPv4:10.0.0.2
    critical_paths = analyzer.find_critical_attack_paths("Domain:corp.com", top_k=3, min_risk=70.0)
    assert len(critical_paths) >= 1
    # Port:3389 should be the highest priority target
    top_target = critical_paths[0].target_urn
    assert top_target == "Port:3389"


def test_chokepoints_detection():
    store = MemoryGraphStore()
    # Shared gateway node through which multiple attack paths must pass
    store.add_node(GraphNode(urn="Domain:entry.com", entity_type="Domain", value="entry.com", threat_score=0.0))
    store.add_node(GraphNode(urn="Gateway:chokepoint", entity_type="Gateway", value="chokepoint", threat_score=50.0))
    store.add_node(GraphNode(urn="Target:db1", entity_type="Target", value="db1", threat_score=90.0))
    store.add_node(GraphNode(urn="Target:db2", entity_type="Target", value="db2", threat_score=95.0))

    store.add_edge(GraphEdge(source="Domain:entry.com", target="Gateway:chokepoint", rel="ROUTES", target_type="Gateway"))
    store.add_edge(GraphEdge(source="Gateway:chokepoint", target="Target:db1", rel="HOSTS", target_type="Target"))
    store.add_edge(GraphEdge(source="Gateway:chokepoint", target="Target:db2", rel="HOSTS", target_type="Target"))

    analyzer = AttackPathAnalyzer(store.get_nodes(), store.get_edges())
    critical_paths = analyzer.find_critical_attack_paths("Domain:entry.com", top_k=5, min_risk=70.0)
    assert len(critical_paths) == 2
    # Gateway:chokepoint must be identified as a defensive chokepoint
    assert "Gateway:chokepoint" in critical_paths[0].chokepoints


@pytest.mark.asyncio
async def test_attack_path_api_endpoint():
    store = _build_test_graph()
    session_id = "test-attack-path-session"
    investigation_stores[session_id] = store

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/investigations/{session_id}/attack-path",
                json={
                    "source_urn": "Domain:corp.com",
                    "target_urn": "Port:3389",
                    "weighted": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["session_id"] == session_id
            assert data["path_count"] == 1
            assert data["paths"][0]["target_urn"] == "Port:3389"
            assert data["paths"][0]["hop_count"] == 3

            # Test auto-discovery of critical targets via API
            resp_auto = await client.post(
                f"/api/v1/investigations/{session_id}/attack-path",
                json={
                    "source_urn": "Domain:corp.com",
                    "target_urn": None,
                    "top_k": 3,
                },
            )
            assert resp_auto.status_code == 200
            data_auto = resp_auto.json()
            assert data_auto["path_count"] >= 1
    finally:
        investigation_stores.pop(session_id, None)
