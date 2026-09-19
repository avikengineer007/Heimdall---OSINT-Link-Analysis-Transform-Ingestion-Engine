"""
Unit tests for Pipeline Orchestrator and multi-hop execution.
"""

import pytest
from heimdall.core.models import GraphEdge
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.pipeline.orchestrator import PipelineOrchestrator
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry


class MockRecursiveTransform(BaseTransform):
    name = "mock_recursive"
    display_name = "Mock Transform"
    description = "Generates synthetic edges for testing."
    input_types = {"Domain"}
    output_types = {"IPv4", "Domain"}

    async def execute(self, node_urn: str, value: str, transport, **kwargs):
        if value == "root.com":
            return [
                GraphEdge(
                    source=node_urn,
                    target="Domain:child.com",
                    target_type="Domain",
                    rel="LINKS_TO",
                )
            ]
        elif value == "child.com":
            return [
                # Points back to root.com (cycle) plus a new node
                GraphEdge(
                    source=node_urn,
                    target="Domain:root.com",
                    target_type="Domain",
                    rel="LINKS_TO",
                ),
                GraphEdge(
                    source=node_urn,
                    target="IPv4:8.8.8.8",
                    target_type="IPv4",
                    rel="RESOLVES_TO",
                ),
            ]
        return []


def test_seed_inference():
    assert PipelineOrchestrator.infer_and_normalize_seed("example.com") == "Domain:example.com"
    assert PipelineOrchestrator.infer_and_normalize_seed("https://TEST.ORG/path") == "Domain:test.org"
    assert PipelineOrchestrator.infer_and_normalize_seed("192.168.1.1") == "IPv4:192.168.1.1"
    assert PipelineOrchestrator.infer_and_normalize_seed("user@example.com") == "Email:user@example.com"
    assert PipelineOrchestrator.infer_and_normalize_seed("Domain:custom.net") == "Domain:custom.net"


@pytest.mark.asyncio
async def test_pipeline_crawl_and_cycle_prevention():
    store = MemoryGraphStore()
    events = []

    def on_event(ev):
        events.append(ev)

    mock_t = MockRecursiveTransform()
    TransformRegistry.register(mock_t)

    orchestrator = PipelineOrchestrator(graph_store=store, event_callback=on_event)

    session = await orchestrator.run_investigation(
        seed="root.com",
        max_depth=3,
        allowed_transforms=["mock_recursive"],
    )

    assert session.total_nodes >= 3  # root.com, child.com, 8.8.8.8
    assert session.total_edges >= 3

    # Ensure no infinite loop despite cyclic references
    event_types = [e["type"] for e in events]
    assert "INVESTIGATION_STARTED" in event_types
    assert "INVESTIGATION_COMPLETED" in event_types
