"""
Integration tests for Heimdall FastAPI endpoints.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from heimdall.api.app import app


@pytest.mark.asyncio
async def test_api_health_and_transforms():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Health check
        res = await ac.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["engine"] == "Heimdall"
        assert data["registered_transforms"] >= 8

        # Transforms list
        res_t = await ac.get("/api/v1/transforms")
        assert res_t.status_code == 200
        t_data = res_t.json()
        assert "transforms" in t_data
        names = [t["name"] for t in t_data["transforms"]]
        assert "dns_resolve" in names
        assert "crtsh_subdomains" in names
        assert "rdap_domain" in names
        assert "shodan_internetdb" in names


@pytest.mark.asyncio
async def test_api_run_single_transform():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "transform_name": "dns_resolve",
            "entity_urn": "Domain:example.com",
            "kwargs": {},
        }
        res = await ac.post("/api/v1/transforms/run", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["transform_name"] == "dns_resolve"
        assert len(data["edges"]) > 0


@pytest.mark.asyncio
async def test_api_investigation_and_sse_events():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "seed": "example.com",
            "max_depth": 1,
            "allowed_transforms": [],  # Empty to finish quickly
        }
        res = await ac.post("/api/v1/investigations/start", json=payload)
        assert res.status_code == 200
        start_data = res.json()
        assert "session_id" in start_data
        session_id = start_data["session_id"]
        assert start_data["stream_url"] == f"/api/v1/investigations/{session_id}/events"

        # Read SSE events stream
        sse_res = await ac.get(f"/api/v1/investigations/{session_id}/events")
        assert sse_res.status_code == 200
        assert "text/event-stream" in sse_res.headers["content-type"]
        body_text = sse_res.text
        assert "event: INVESTIGATION_STARTED" in body_text
        assert "event: INVESTIGATION_COMPLETED" in body_text


@pytest.mark.asyncio
async def test_api_plugins_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # GET /api/v1/plugins
        res = await ac.get("/api/v1/plugins")
        assert res.status_code == 200
        data = res.json()
        assert "loaded_plugins" in data
        assert "plugin_directory" in data

        # POST /api/v1/plugins/reload
        reload_res = await ac.post("/api/v1/plugins/reload")
        assert reload_res.status_code == 200
        assert reload_res.json()["status"] == "reloaded"


@pytest.mark.asyncio
async def test_api_monitoring_and_diff_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Create a monitoring schedule
        sched_payload = {
            "seed_urn": "Domain:sweep-test.org",
            "cron_expr": "0 9 * * 1",
            "max_depth": 2,
            "alert_on_new_nodes": True,
            "alert_on_threat_increase": True,
        }
        res_post = await ac.post("/api/v1/monitor", json=sched_payload)
        assert res_post.status_code == 200
        sched_data = res_post.json()["schedule"]
        sched_id = sched_data["id"]
        assert sched_data["seed_urn"] == "Domain:sweep-test.org"

        # 2. List schedules
        res_list = await ac.get("/api/v1/monitor")
        assert res_list.status_code == 200
        schedules = res_list.json()["schedules"]
        assert any(s["id"] == sched_id for s in schedules)

        # 3. Delete schedule
        res_del = await ac.delete(f"/api/v1/monitor/{sched_id}")
        assert res_del.status_code == 200

        # 4. Test Graph Diff endpoint
        # Start two empty investigations to generate valid session IDs
        inv_a = await ac.post("/api/v1/investigations/start", json={"seed": "a.org", "allowed_transforms": []})
        inv_b = await ac.post("/api/v1/investigations/start", json={"seed": "b.org", "allowed_transforms": []})
        sess_a = inv_a.json()["session_id"]
        sess_b = inv_b.json()["session_id"]

        diff_res = await ac.get(f"/api/v1/diff/{sess_a}/{sess_b}")
        assert diff_res.status_code == 200
        diff_data = diff_res.json()
        assert "session_a" in diff_data
        assert "added_nodes" in diff_data
        assert "summary" in diff_data


@pytest.mark.asyncio
async def test_api_pivot_agent_rules():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/v1/agents/rules")
        assert res.status_code == 200
        data = res.json()
        assert "rules" in data
        assert "top_k" in data
        assert len(data["rules"]) > 0
