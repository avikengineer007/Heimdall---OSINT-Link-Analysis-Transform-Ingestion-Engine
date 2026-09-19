"""
Unit tests for graph storage, Cypher compilation, and exports.
"""

import json
import zipfile
import io
import pytest
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.graph.cypher_engine import CypherEngine
from heimdall.graph.exporters import GraphExporter


def test_memory_graph_store():
    store = MemoryGraphStore()

    e1 = GraphEdge(
        source="Domain:example.com",
        target="IPv4:93.184.216.34",
        target_type="IPv4",
        rel="RESOLVES_TO",
        properties={"ttl": 300},
    )
    e2 = GraphEdge(
        source="Domain:example.com",
        target="Subdomain:api.example.com",
        target_type="Subdomain",
        rel="HAS_SUBDOMAIN",
    )

    assert store.add_edge(e1) is True
    # Duplicate edge should return False
    assert store.add_edge(e1) is False
    assert store.add_edge(e2) is True

    assert len(store.get_edges()) == 2
    assert len(store.get_nodes()) == 3

    neighbors = store.get_neighbors("Domain:example.com")
    assert "IPv4:93.184.216.34" in neighbors
    assert "Subdomain:api.example.com" in neighbors

    stats = store.get_stats()
    assert stats["total_nodes"] == 3
    assert stats["total_edges"] == 2


def test_cypher_engine():
    edges = [
        GraphEdge(
            source="Domain:example.com",
            target="IPv4:93.184.216.34",
            target_type="IPv4",
            rel="RESOLVES_TO",
            properties={"ttl": 300},
        )
    ]

    merges = CypherEngine.build_native_merges(edges)
    assert len(merges) == 1
    assert "MERGE (s:`Domain` {urn: $src_urn})" in merges[0]["query"]
    assert "MERGE (t:`IPv4` {urn: $tgt_urn})" in merges[0]["query"]
    assert "MERGE (s)-[r:`RESOLVES_TO`]->(t)" in merges[0]["query"]
    assert merges[0]["params"]["src_urn"] == "Domain:example.com"

    unwind = CypherEngine.build_batch_unwind(edges)
    assert "UNWIND $batch AS row" in unwind["query"]
    assert len(unwind["params"]["batch"]) == 1


def test_graph_exporters():
    store = MemoryGraphStore()
    store.add_edge(
        GraphEdge(
            source="Domain:test.org",
            target="IPv4:1.2.3.4",
            target_type="IPv4",
            rel="RESOLVES_TO",
        )
    )

    # 1. JSON Export
    json_out = GraphExporter.to_json(store)
    data = json.loads(json_out)
    assert len(data["nodes"]) == 2
    assert len(data["links"]) == 1

    # 2. GraphML Export
    graphml_out = GraphExporter.to_graphml(store)
    assert "<graphml" in graphml_out
    assert 'id="Domain:test.org"' in graphml_out
    assert 'id="IPv4:1.2.3.4"' in graphml_out

    # 3. Maltego MTGX Export
    mtgx_bytes = GraphExporter.to_maltego_mtgx(store)
    assert len(mtgx_bytes) > 0
    with zipfile.ZipFile(io.BytesIO(mtgx_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "Graphs/Graph1.graphml" in namelist
        assert "manifest.json" in namelist
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["generator"] == "Heimdall OSINT Engine"
