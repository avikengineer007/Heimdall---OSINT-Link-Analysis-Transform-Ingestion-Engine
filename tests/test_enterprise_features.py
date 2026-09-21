"""
Enterprise Features Test Suite.

Validates:
1. Subdomain Takeover & Dangling DNS Detection
2. Cloud Storage Bucket Permutation & Probing
3. Historical Reconnaissance (Wayback CDX & AlienVault OTX)
4. Vulnerability & Sensitive Exposure Probing
5. Graph Community Detection & Modularity Clustering
6. AI / LLM Threat Copilot & Natural Language Querying
7. Executive Threat Intelligence Report Generation (HTML/Markdown)
8. API Endpoints
"""

import pytest
from httpx import ASGITransport, AsyncClient

from heimdall.api.app import app, investigation_meta, investigation_stores
from heimdall.core.copilot import ThreatCopilot
from heimdall.core.models import EntityType, GraphEdge, GraphNode
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.graph.clustering import GraphClusterEngine
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.graph.reports import ExecutiveReportGenerator
from heimdall.transforms.cloud_buckets import CloudBucketHunterTransform
from heimdall.transforms.exposure_probe import ExposureProbeTransform
from heimdall.transforms.historical import HistoricalReconTransform
from heimdall.transforms.registry import TransformRegistry
from heimdall.transforms.takeover import SubdomainTakeoverTransform


@pytest.mark.asyncio
async def test_subdomain_takeover_transform():
    """Validates subdomain takeover transform instantiation and registry presence."""
    transform = TransformRegistry.get("subdomain_takeover")
    assert transform is not None
    assert isinstance(transform, SubdomainTakeoverTransform)

    # Test signature recognition logic
    cname_sig = transform.check_cname_signatures("test-app.herokuapp.com")
    assert cname_sig is not None
    assert "Heroku" in cname_sig["service"]


    s3_sig = transform.check_cname_signatures("bucket.s3.amazonaws.com")
    assert s3_sig is not None
    assert s3_sig["service"] == "AWS S3"

    # Test body fingerprint matching
    matched = transform.check_body_signatures("The specified bucket does not exist")
    assert matched is not None
    assert "AWS S3" in matched["service"]


@pytest.mark.asyncio
async def test_cloud_bucket_hunter_transform():
    """Validates multi-cloud bucket permutation generation and transform."""
    transform = TransformRegistry.get("cloud_bucket_hunter")
    assert transform is not None
    assert isinstance(transform, CloudBucketHunterTransform)

    names = transform.generate_bucket_names("targetcorp.com")
    assert "targetcorp" in names
    assert "targetcorp-assets" in names
    assert "targetcorp-backup" in names


@pytest.mark.asyncio
async def test_historical_recon_transform():
    """Validates historical recon transform registration."""
    transform = TransformRegistry.get("historical_recon")
    assert transform is not None
    assert isinstance(transform, HistoricalReconTransform)
    assert transform.can_process("Domain")


@pytest.mark.asyncio
async def test_exposure_probe_transform():
    """Validates sensitive exposure probe paths and signatures."""
    transform = TransformRegistry.get("exposure_probe")
    assert transform is not None
    assert isinstance(transform, ExposureProbeTransform)
    assert len(transform.PROBE_PATHS) >= 10
    assert any(p["path"] == "/.env" for p in transform.PROBE_PATHS)
    assert any(p["path"] == "/.git/HEAD" for p in transform.PROBE_PATHS)


def test_graph_community_clustering():
    """Validates modularity community detection on synthetic infrastructure cluster."""
    engine = GraphClusterEngine()

    nodes = [
        GraphNode(urn="Domain:target.com", entity_type=EntityType.DOMAIN, value="target.com"),
        GraphNode(urn="Subdomain:api.target.com", entity_type=EntityType.SUBDOMAIN, value="api.target.com"),
        GraphNode(urn="Subdomain:app.target.com", entity_type=EntityType.SUBDOMAIN, value="app.target.com"),
        GraphNode(urn="IPv4:1.2.3.4", entity_type=EntityType.IPV4, value="1.2.3.4"),
        GraphNode(urn="Domain:unrelated.org", entity_type=EntityType.DOMAIN, value="unrelated.org"),
        GraphNode(urn="IPv4:9.9.9.9", entity_type=EntityType.IPV4, value="9.9.9.9"),
    ]

    edges = [
        GraphEdge(source="Domain:target.com", target="Subdomain:api.target.com", target_type=EntityType.SUBDOMAIN, rel="HAS_SUBDOMAIN"),
        GraphEdge(source="Domain:target.com", target="Subdomain:app.target.com", target_type=EntityType.SUBDOMAIN, rel="HAS_SUBDOMAIN"),
        GraphEdge(source="Subdomain:api.target.com", target="IPv4:1.2.3.4", target_type=EntityType.IPV4, rel="RESOLVES_TO"),
        GraphEdge(source="Domain:unrelated.org", target="IPv4:9.9.9.9", target_type=EntityType.IPV4, rel="RESOLVES_TO"),
    ]

    communities = engine.detect_communities(nodes, edges)
    assert len(communities) >= 1
    # Check that communities contain metrics
    assert "density" in communities[0]
    assert "node_count" in communities[0]
    assert "hub_node" in communities[0]


def test_threat_copilot():
    """Validates natural language intent parsing and CISO briefing generation."""
    copilot = ThreatCopilot()

    nodes = [
        GraphNode(urn="Domain:target.com", entity_type=EntityType.DOMAIN, value="target.com"),
        GraphNode(urn="Subdomain:dev.target.com", entity_type=EntityType.SUBDOMAIN, value="dev.target.com", properties={"threat_score": 75}),
        GraphNode(urn="CloudBucket:https://target-backup.s3.amazonaws.com", entity_type=EntityType.CLOUD_BUCKET, value="target-backup.s3.amazonaws.com", properties={"threat_score": 90}),
        GraphNode(urn="TakeoverVulnerability:dev.target.com:AWS S3", entity_type=EntityType.TAKEOVER_VULNERABILITY, value="dev.target.com", properties={"threat_score": 95, "is_vulnerable": True}),
        GraphNode(urn="Port:3306", entity_type=EntityType.PORT, value="3306", properties={"port": "3306"}),
        GraphNode(urn="Port:22", entity_type=EntityType.PORT, value="22", properties={"port": "22"}),
    ]

    edges = [
        GraphEdge(source="Domain:target.com", target="Subdomain:dev.target.com", target_type=EntityType.SUBDOMAIN, rel="HAS_SUBDOMAIN"),
        GraphEdge(source="Subdomain:dev.target.com", target="CloudBucket:https://target-backup.s3.amazonaws.com", target_type=EntityType.CLOUD_BUCKET, rel="REFERENCES_BUCKET"),
    ]

    # 1. Query: high risk
    res_high = copilot.parse_query("show high risk assets", nodes, edges)
    assert res_high["matched_count"] >= 2
    assert "Subdomain:dev.target.com" in res_high["matched_nodes"]

    # 2. Query: cloud buckets
    res_buckets = copilot.parse_query("find cloud buckets", nodes, edges)
    assert res_buckets["matched_count"] >= 1
    assert "CloudBucket:https://target-backup.s3.amazonaws.com" in res_buckets["matched_nodes"]

    # 3. Query: databases
    res_db = copilot.parse_query("exposed databases", nodes, edges)
    assert res_db["matched_count"] >= 1
    assert "Port:3306" in res_db["matched_nodes"]

    # 4. Query: remote admin
    res_admin = copilot.parse_query("find ssh and rdp", nodes, edges)
    assert res_admin["matched_count"] >= 1
    assert "Port:22" in res_admin["matched_nodes"]

    # 5. Briefing generation
    briefing = copilot.generate_executive_briefing(nodes, edges)
    assert briefing["posture_rating"] == "CRITICAL"
    assert briefing["total_assets"] == 6
    assert briefing["buckets_count"] >= 1
    assert briefing["takeovers_count"] >= 1
    assert len(briefing["key_findings"]) >= 1
    assert len(briefing["recommendations"]) >= 1


def test_executive_report_generator():
    """Validates Markdown and HTML executive report creation."""
    generator = ExecutiveReportGenerator()

    nodes = [
        GraphNode(urn="Domain:target.com", entity_type=EntityType.DOMAIN, value="target.com"),
        GraphNode(urn="Subdomain:dangling.target.com", entity_type=EntityType.TAKEOVER_VULNERABILITY, value="dangling.target.com", properties={"threat_score": 95, "reason": "Dangling Heroku CNAME"}),
    ]
    edges = [
        GraphEdge(source="Domain:target.com", target="Subdomain:dangling.target.com", target_type=EntityType.TAKEOVER_VULNERABILITY, rel="VULNERABLE_TO_TAKEOVER"),
    ]

    # Test Markdown report
    md = generator.generate_markdown("target.com", nodes, edges)
    assert "# Executive Threat Intelligence Assessment: target.com" in md
    assert "Total Assets Discovered" in md
    assert "Actionable Remediation Roadmap" in md

    # Test HTML report
    html = generator.generate_html("target.com", nodes, edges)
    assert "<!DOCTYPE html>" in html
    assert "Heimdall Threat Intelligence Report" in html
    assert "target.com" in html
    assert "CRITICAL" in html
    assert "window.print()" in html


@pytest.mark.asyncio
async def test_enterprise_api_routes():
    """Validates REST endpoints for communities, copilot, and executive reports."""
    session_id = "test-enterprise-session"
    store = MemoryGraphStore()

    store.add_node(GraphNode(urn="Domain:corp.com", entity_type=EntityType.DOMAIN, value="corp.com"))
    store.add_node(GraphNode(urn="CloudBucket:https://corp-data.s3.amazonaws.com", entity_type=EntityType.CLOUD_BUCKET, value="corp-data.s3.amazonaws.com", properties={"threat_score": 90}))
    store.add_edge(GraphEdge(source="Domain:corp.com", target="CloudBucket:https://corp-data.s3.amazonaws.com", target_type=EntityType.CLOUD_BUCKET, rel="REFERENCES_BUCKET"))

    investigation_stores[session_id] = store
    investigation_meta[session_id] = {"seed": "corp.com", "max_depth": 2, "status": "completed"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Communities endpoint
        res = await client.get(f"/api/v1/investigations/{session_id}/communities")
        assert res.status_code == 200
        data = res.json()
        assert "community_count" in data
        assert "communities" in data

        # 2. Copilot Query endpoint
        res = await client.post(
            f"/api/v1/investigations/{session_id}/copilot/query",
            json={"query": "find cloud buckets"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["matched_count"] >= 1
        assert "interpretation" in data

        # 3. Copilot Briefing endpoint
        res = await client.get(f"/api/v1/investigations/{session_id}/copilot/briefing")
        assert res.status_code == 200
        data = res.json()
        assert "briefing" in data
        assert "posture_rating" in data["briefing"]

        # 4. Report HTML endpoint
        res = await client.get(f"/api/v1/investigations/{session_id}/report/html")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "Heimdall Threat Intelligence Report" in res.text

        # 5. Report Markdown endpoint
        res = await client.get(f"/api/v1/investigations/{session_id}/report/md")
        assert res.status_code == 200
        assert "text/markdown" in res.headers["content-type"]
        assert "# Executive Threat Intelligence Assessment" in res.text
