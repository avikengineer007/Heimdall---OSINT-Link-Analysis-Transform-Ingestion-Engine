"""
Tests for Heimdall Smart Pivot Agent and Heuristic Rules Engine.
"""

import pytest
from heimdall.core.models import GraphNode
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.pipeline.smart_agent import PivotAgent
from heimdall.transforms.registry import TransformRegistry


def test_smart_agent_rules_loading():
    agent = PivotAgent()
    rules = agent.get_active_rules()
    assert len(rules) >= 4
    rule_ids = [r["id"] for r in rules]
    assert "mail_port_priority" in rule_ids
    assert "cdn_ip_suppression" in rule_ids


def test_smart_agent_score_transforms_mail_priority():
    agent = PivotAgent(top_k=2)

    # Candidate transforms for a port
    t_mx = TransformRegistry.get("mx_security")
    t_rdap = TransformRegistry.get("rdap_domain")
    candidates = [t for t in [t_rdap, t_mx] if t is not None]

    # Port 25 exposes SMTP -> should boost mx_security
    scored = agent.score_transforms(
        node_urn="PortService:example.com:25",
        properties={"port": 25},
        candidate_transforms=candidates,
    )
    assert len(scored) > 0
    # mx_security should have the top score
    assert scored[0][0].name == "mx_security"


def test_smart_agent_cdn_suppression():
    agent = PivotAgent()
    store = MemoryGraphStore()

    # Create normal IP and Cloudflare CDN IP using from_urn
    node_normal = GraphNode.from_urn("IPv4:198.51.100.1", properties={"org": "University Lab"})
    node_cdn = GraphNode.from_urn("IPv4:104.16.0.1", properties={"org": "Cloudflare, Inc."})

    store.add_node(node_normal)
    store.add_node(node_cdn)

    frontier = {"IPv4:198.51.100.1", "IPv4:104.16.0.1", "Domain:target.org"}
    filtered = agent.filter_frontier(frontier, store)

    assert "IPv4:198.51.100.1" in filtered
    assert "Domain:target.org" in filtered
    # CDN IP must be suppressed from recursive crawl
    assert "IPv4:104.16.0.1" not in filtered


@pytest.mark.asyncio
async def test_smart_agent_llm_fallback():
    # When no LLM endpoint is provided, rank_with_llm falls back gracefully to deterministic heuristics
    agent = PivotAgent()
    t_dns = TransformRegistry.get("dns_resolve")
    t_web = TransformRegistry.get("web_surface")
    candidates = [t for t in [t_dns, t_web] if t is not None]

    scored = await agent.rank_with_llm(
        node_urn="Domain:target.com",
        properties={"name": "target.com"},
        candidate_transforms=candidates,
    )
    assert len(scored) > 0
    assert all(isinstance(score, int) for _, score in scored)


def test_smart_agent_top_k_limiting():
    agent = PivotAgent(top_k=1)
    t_dns = TransformRegistry.get("dns_resolve")
    t_web = TransformRegistry.get("web_surface")
    candidates = [t for t in [t_dns, t_web] if t is not None]

    scored = agent.score_transforms("Domain:example.com", {}, candidates)
    assert len(scored) == 1


def test_smart_agent_asn_priority():
    agent = PivotAgent()
    t_bgp = TransformRegistry.get("bgp_routing")
    if t_bgp:
        scored = agent.score_transforms("ASNumber:13335", {}, [t_bgp])
        assert len(scored) == 1
        # ASN priority rule boosts score
        assert scored[0][1] >= 15
