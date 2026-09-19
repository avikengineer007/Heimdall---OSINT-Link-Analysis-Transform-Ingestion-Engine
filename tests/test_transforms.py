"""
Unit tests for OSINT transforms with mock transport payloads.
"""

import pytest
import httpx
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.dns_doh import DNSResolutionTransform
from heimdall.transforms.crtsh import CrtshSubdomainTransform
from heimdall.transforms.whois_rdap import DomainRDAPTransform
from heimdall.transforms.shodan import ShodanInternetDBTransform


@pytest.mark.asyncio
async def test_dns_resolution_transform():
    doh_data = {
        "Answer": [
            {"name": "example.com", "type": 1, "TTL": 300, "data": "93.184.216.34"},
            {"name": "example.com", "type": 15, "TTL": 3600, "data": "10 mail.example.com."},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=doh_data)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = ResilientAsyncTransport(client=client)

    transform = DNSResolutionTransform()
    res = await transform.run_safe("Domain:example.com", transport)

    assert res.status == "SUCCESS"
    assert len(res.edges) >= 2

    edge_types = {e.rel for e in res.edges}
    assert "RESOLVES_TO" in edge_types
    assert "HAS_MX" in edge_types
    await client.aclose()


@pytest.mark.asyncio
async def test_crtsh_transform():
    crtsh_data = [
        {"name_value": "api.example.com\nadmin.example.com", "common_name": "*.example.com"},
        {"name_value": "vpn.example.com", "common_name": "vpn.example.com"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=crtsh_data)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = ResilientAsyncTransport(client=client)

    transform = CrtshSubdomainTransform()
    res = await transform.run_safe("Domain:example.com", transport)

    assert res.status == "SUCCESS"
    targets = {e.target for e in res.edges}
    assert "Subdomain:api.example.com" in targets
    assert "Subdomain:admin.example.com" in targets
    assert "Subdomain:vpn.example.com" in targets
    await client.aclose()


@pytest.mark.asyncio
async def test_rdap_transform():
    rdap_data = {
        "handle": "example.com",
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "REG-123",
                "vcardArray": ["vcard", [["fn", {}, "text", "ICANN Registrar Inc."]]],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=rdap_data)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = ResilientAsyncTransport(client=client)

    transform = DomainRDAPTransform()
    res = await transform.run_safe("Domain:example.com", transport)

    assert res.status == "SUCCESS"
    assert len(res.edges) == 1
    assert res.edges[0].target == "Registrar:ICANN Registrar Inc."
    assert res.edges[0].rel == "REGISTERED_WITH"
    await client.aclose()


@pytest.mark.asyncio
async def test_shodan_internetdb_transform():
    shodan_data = {
        "ip": "1.1.1.1",
        "ports": [53, 80, 443, 853],
        "hostnames": ["one.one.one.one"],
        "tags": ["dns"],
        "vulns": [],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=shodan_data)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = ResilientAsyncTransport(client=client)

    transform = ShodanInternetDBTransform()
    res = await transform.run_safe("IPv4:1.1.1.1", transport)

    assert res.status == "SUCCESS"
    assert len(res.edges) == 5  # 4 ports + 1 hostname
    rels = {e.rel for e in res.edges}
    assert "EXPOSES_SERVICE" in rels
    assert "ASSOCIATED_WITH" in rels
    await client.aclose()
