"""
Tests for advanced Phase 3 OSINT transforms.
All external HTTP calls are mocked via pytest-httpx / unittest.mock.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_transport(json_response=None, text_response=None):
    transport = MagicMock(spec=ResilientAsyncTransport)
    transport.get_json = AsyncMock(return_value=json_response)
    transport.get_text = AsyncMock(return_value=text_response)
    return transport


# ─── VirusTotal ────────────────────────────────────────────────────────────────

class TestVirusTotalTransform:
    def setup_method(self):
        from heimdall.transforms.virustotal import VirusTotalTransform
        self.transform = VirusTotalTransform()

    @pytest.mark.asyncio
    async def test_skipped_when_no_api_key(self):
        """Transform should return SKIPPED (not FAILED) when API key is absent."""
        transport = make_transport()
        with patch("heimdall.transforms.virustotal.settings") as mock_settings:
            mock_settings.virustotal_api_key = None
            result = await self.transform.run_safe("Domain:example.com", transport)
        assert result.status == "SKIPPED"
        assert len(result.edges) == 0

    @pytest.mark.asyncio
    async def test_extracts_malicious_detection(self):
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5, "suspicious": 2, "undetected": 60, "harmless": 10
                    },
                    "reputation": -15,
                    "last_dns_records": [],
                }
            }
        }
        transport = make_transport(json_response=vt_response)
        result = await self.transform.execute(
            "Domain:evil.com", "evil.com", transport, virustotal_api_key="fake_key"
        )
        assert len(result) >= 1
        rels = [e.rel for e in result]
        assert "DETECTED_BY_VIRUSTOTAL" in rels

    @pytest.mark.asyncio
    async def test_no_edges_for_clean_domain(self):
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 10},
                    "last_dns_records": [],
                }
            }
        }
        transport = make_transport(json_response=vt_response)
        result = await self.transform.execute(
            "Domain:clean.com", "clean.com", transport, virustotal_api_key="fake_key"
        )
        assert len(result) == 0


# ─── BGP Routing ───────────────────────────────────────────────────────────────

class TestBGPRoutingTransform:
    def setup_method(self):
        from heimdall.transforms.bgp_routing import BGPRoutingTransform
        self.transform = BGPRoutingTransform()

    @pytest.mark.asyncio
    async def test_asn_to_prefixes(self):
        prefix_response = {
            "status": "ok",
            "data": {
                "ipv4_prefixes": [
                    {"prefix": "104.16.0.0/12", "name": "Cloudflare", "description": "CF net", "country_code": "US"},
                    {"prefix": "198.41.128.0/17", "name": "Cloudflare-2", "description": "", "country_code": "US"},
                ]
            }
        }
        peer_response = {"status": "ok", "data": {"ipv4_peers": []}}
        upstream_response = {"status": "ok", "data": {"ipv4_upstreams": []}}
        ix_response = {"status": "ok", "data": []}

        call_count = 0
        responses = [prefix_response, peer_response, upstream_response, ix_response]

        async def side_effect(url, **kwargs):
            nonlocal call_count
            resp = responses[call_count % len(responses)]
            call_count += 1
            return resp

        transport = MagicMock(spec=ResilientAsyncTransport)
        transport.get_json = AsyncMock(side_effect=side_effect)

        result = await self.transform.execute("ASNumber:13335", "13335", transport)
        assert any(e.rel == "ANNOUNCES_PREFIX" for e in result)
        targets = [e.target for e in result if e.rel == "ANNOUNCES_PREFIX"]
        assert any("104.16.0.0" in t for t in targets)

    @pytest.mark.asyncio
    async def test_internet_exchange_edges(self):
        prefix_response = {"status": "ok", "data": {"ipv4_prefixes": []}}
        peer_response   = {"status": "ok", "data": {"ipv4_peers": []}}
        upstream_response = {"status": "ok", "data": {"ipv4_upstreams": []}}
        ix_response = {
            "status": "ok",
            "data": [{"ix_id": 1, "name": "AMS-IX", "name_long": "Amsterdam Internet Exchange", "city": "Amsterdam", "country_code": "NL"}]
        }
        responses = [prefix_response, peer_response, upstream_response, ix_response]
        call_count = 0

        async def side_effect(url, **kwargs):
            nonlocal call_count
            resp = responses[call_count % len(responses)]
            call_count += 1
            return resp

        transport = MagicMock(spec=ResilientAsyncTransport)
        transport.get_json = AsyncMock(side_effect=side_effect)
        result = await self.transform.execute("ASNumber:1200", "1200", transport)
        assert any(e.rel == "MEMBER_OF_IX" for e in result)


# ─── AbuseIPDB ─────────────────────────────────────────────────────────────────

class TestAbuseIPDBTransform:
    def setup_method(self):
        from heimdall.transforms.abuse_ipdb import AbuseIPDBTransform
        self.transform = AbuseIPDBTransform()

    @pytest.mark.asyncio
    async def test_skipped_when_no_api_key(self):
        transport = make_transport()
        with patch("heimdall.transforms.abuse_ipdb.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = None
            result = await self.transform.run_safe("IPv4:1.2.3.4", transport)
        assert result.status == "SKIPPED"

    @pytest.mark.asyncio
    async def test_high_confidence_score_emits_edge(self):
        abuse_response = {
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 45,
                "countryCode": "CN",
                "isp": "China Telecom",
                "usageType": "Data Center",
                "isTor": False,
                "isWhitelisted": False,
            }
        }
        transport = make_transport(json_response=abuse_response)
        result = await self.transform.execute(
            "IPv4:1.2.3.4", "1.2.3.4", transport, abuseipdb_api_key="fake"
        )
        rels = [e.rel for e in result]
        assert "HAS_ABUSE_REPORT" in rels
        abuse_edge = next(e for e in result if e.rel == "HAS_ABUSE_REPORT")
        assert abuse_edge.properties["confidence_score"] == 87


# ─── MX Security ───────────────────────────────────────────────────────────────

class TestMXSecurityTransform:
    def setup_method(self):
        from heimdall.transforms.mx_security import MXSecurityTransform
        self.transform = MXSecurityTransform()

    @pytest.mark.asyncio
    async def test_spf_softfail_detected(self):
        spf_txt_response = {
            "Status": 0,
            "Answer": [{"type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'}]
        }

        async def doh_side_effect(url, headers=None, **kwargs):
            if "_dmarc" in url:
                return {"Status": 0, "Answer": []}
            if "type=MX" in url:
                return {"Status": 0, "Answer": []}
            if "type=TXT" in url and "_domainkey" not in url:
                return spf_txt_response
            return {"Status": 0, "Answer": []}

        transport = MagicMock(spec=ResilientAsyncTransport)
        transport.get_json = AsyncMock(side_effect=doh_side_effect)

        result = await self.transform.execute("Domain:example.com", "example.com", transport)
        spf_edges = [e for e in result if e.rel == "HAS_SPF_RECORD"]
        assert len(spf_edges) >= 1
        assert spf_edges[0].properties["policy"] == "softfail"

    @pytest.mark.asyncio
    async def test_dmarc_policy_extraction(self):
        dmarc_txt_response = {
            "Status": 0,
            "Answer": [{"type": 16, "data": '"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com"'}]
        }

        async def doh_side_effect(url, headers=None, **kwargs):
            if "_dmarc" in url and "_domainkey" not in url and "type=TXT" in url:
                return dmarc_txt_response
            return {"Status": 0, "Answer": []}

        transport = MagicMock(spec=ResilientAsyncTransport)
        transport.get_json = AsyncMock(side_effect=doh_side_effect)

        result = await self.transform.execute("Domain:example.com", "example.com", transport)
        dmarc_edges = [e for e in result if e.rel == "HAS_DMARC_POLICY"]
        assert len(dmarc_edges) >= 1
        assert dmarc_edges[0].properties["policy"] == "reject"


# ─── Reverse WHOIS ─────────────────────────────────────────────────────────────

class TestReverseWhoisTransform:
    def setup_method(self):
        from heimdall.transforms.reverse_whois import ReverseWhoisTransform
        self.transform = ReverseWhoisTransform()

    @pytest.mark.asyncio
    async def test_email_to_domains(self):
        hackertarget_response = "example.com\nexample.org\nexample.net\n"
        transport = make_transport(text_response=hackertarget_response)

        result = await self.transform.execute(
            "Email:owner@example.com", "owner@example.com", transport
        )
        assert len(result) >= 3
        assert all(e.rel == "REGISTERED_BY_EMAIL" for e in result)
        targets = [e.target for e in result]
        assert any("example.com" in t for t in targets)

    @pytest.mark.asyncio
    async def test_empty_response_yields_no_edges(self):
        transport = make_transport(text_response="no records found")
        result = await self.transform.execute(
            "Email:nobody@nope.com", "nobody@nope.com", transport
        )
        assert result == []
