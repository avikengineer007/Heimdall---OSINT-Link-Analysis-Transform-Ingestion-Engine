"""
Unit tests for GraphEdge schema contract and GraphNode representations.
"""

import pytest
from pydantic import ValidationError
from heimdall.core.models import GraphEdge, GraphNode


def test_valid_graph_edge():
    edge = GraphEdge(
        source="Domain:example.com",
        target="IPv4:93.184.216.34",
        target_type="IPv4",
        rel="RESOLVES_TO",
        properties={"ttl": 300},
    )
    assert edge.source == "Domain:example.com"
    assert edge.target == "IPv4:93.184.216.34"
    assert edge.target_type == "IPv4"
    assert edge.rel == "RESOLVES_TO"
    assert edge.properties == {"ttl": 300}
    assert edge.edge_key == ("Domain:example.com", "RESOLVES_TO", "IPv4:93.184.216.34")
    assert len(edge.hash_id) == 64

    contract_dict = edge.to_contract_dict()
    assert contract_dict == {
        "source": "Domain:example.com",
        "target": "IPv4:93.184.216.34",
        "target_type": "IPv4",
        "rel": "RESOLVES_TO",
        "properties": {"ttl": 300},
    }


def test_invalid_graph_edge_missing_prefix():
    with pytest.raises(ValidationError):
        GraphEdge(
            source="example.com",  # Missing Type: prefix
            target="IPv4:93.184.216.34",
            target_type="IPv4",
            rel="RESOLVES_TO",
        )


def test_graph_node_from_urn():
    node = GraphNode.from_urn("Domain:test.org", {"tags": ["target"]})
    assert node.urn == "Domain:test.org"
    assert node.entity_type == "Domain"
    assert node.value == "test.org"
    assert node.properties == {"tags": ["target"]}
