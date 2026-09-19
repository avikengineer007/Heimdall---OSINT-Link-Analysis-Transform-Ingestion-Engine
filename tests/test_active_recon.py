"""
Tests for Active Recon transforms (TLS cert extraction, banner grabbing, HTTP security auditing).
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from heimdall.core.config import settings
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.banner_grab import BannerGrabTransform
from heimdall.transforms.http_security_audit import HTTPSecurityAuditTransform
from heimdall.transforms.tls_cert_extract import TLSCertExtractTransform


@pytest.mark.asyncio
async def test_active_recon_gating_disabled_by_default():
    # Ensure active recon is disabled
    with patch.object(settings, "active_recon", False):
        async with ResilientAsyncTransport() as transport:
            # 1. TLS Cert transform
            t_tls = TLSCertExtractTransform()
            res_tls = await t_tls.run_safe("Domain:example.com", transport)
            assert res_tls.status == "SKIPPED"
            assert "ACTIVE_RECON=true" in (res_tls.error_message or "")

            # 2. Banner Grab transform
            t_bg = BannerGrabTransform()
            res_bg = await t_bg.run_safe("IPv4:1.1.1.1", transport)
            assert res_bg.status == "SKIPPED"
            assert "ACTIVE_RECON=true" in (res_bg.error_message or "")

            # 3. HTTP Security Audit
            t_http = HTTPSecurityAuditTransform()
            res_http = await t_http.run_safe("Domain:example.com", transport)
            assert res_http.status == "SKIPPED"
            assert "ACTIVE_RECON=true" in (res_http.error_message or "")


@pytest.mark.asyncio
async def test_http_security_audit_execution_and_waf():
    with patch.object(settings, "active_recon", True):
        t_http = HTTPSecurityAuditTransform()

        # Mock transport response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "server": "cloudflare",
            "cf-ray": "1234567890abcdef",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            # Note: content-security-policy is intentionally missing
        }

        mock_transport = AsyncMock(spec=ResilientAsyncTransport)
        mock_transport.request.return_value = mock_response

        edges = await t_http.execute("Domain:test-corp.com", "test-corp.com", mock_transport)
        assert len(edges) > 0

        # Verify defensive headers emitted
        hdr_targets = [e.target for e in edges if e.rel == "HAS_SECURITY_HEADER"]
        assert any("strict-transport-security" in t for t in hdr_targets)
        assert any("content-security-policy" in t for t in hdr_targets)

        # Verify CSP status was marked MISSING
        csp_edge = next(e for e in edges if "content-security-policy" in e.target)
        assert csp_edge.properties["status"] == "MISSING"

        # Verify Cloudflare WAF detected
        waf_edges = [e for e in edges if e.rel == "PROTECTED_BY_WAF"]
        assert len(waf_edges) == 1
        assert "cloudflare" in waf_edges[0].target


@pytest.mark.asyncio
async def test_tls_cert_extract_gating():
    with patch.object(settings, "active_recon", False):
        async with ResilientAsyncTransport() as transport:
            res = await TLSCertExtractTransform().run_safe("Domain:example.com", transport)
            assert res.status == "SKIPPED"


@pytest.mark.asyncio
async def test_banner_grab_execution_mocked():
    with patch.object(settings, "active_recon", True):
        t_bg = BannerGrabTransform()
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            async with ResilientAsyncTransport() as transport:
                edges = await t_bg.execute("IPv4:192.0.2.1", "192.0.2.1", transport, ports=[22])
                assert len(edges) == 2
                rel_types = [e.rel for e in edges]
                assert "EXPOSES_PORT" in rel_types
                assert "BANNER_IDENTIFIED" in rel_types
                banner_edge = next(e for e in edges if e.rel == "BANNER_IDENTIFIED")
                assert "SSH-2.0-OpenSSH" in banner_edge.properties["banner"]


@pytest.mark.asyncio
async def test_tls_cert_extract_execution_mocked():
    with patch.object(settings, "active_recon", True):
        t_tls = TLSCertExtractTransform()
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_ssl_obj = MagicMock()
        mock_ssl_obj.getpeercert.side_effect = lambda binary_form=False: (
            b"\x30\x82\x01\x0a"
            if binary_form
            else {
                "subject": [[("commonName", "vault.target.com")]],
                "issuer": [[("organizationName", "Let's Encrypt")]],
                "subjectAltName": [("DNS", "vault.target.com"), ("DNS", "api.target.com")],
                "notAfter": "May 30 12:00:00 2026 GMT",
                "notBefore": "Mar  1 12:00:00 2026 GMT",
                "serialNumber": "04A1B2C3",
            }
        )
        mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_obj)

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            async with ResilientAsyncTransport() as transport:
                edges = await t_tls.execute("Domain:vault.target.com", "vault.target.com", transport)
                assert len(edges) == 2
                rel_types = [e.rel for e in edges]
                assert "HAS_TLS_CERT" in rel_types
                assert "CERT_SAN_DOMAIN" in rel_types
                san_edge = next(e for e in edges if e.rel == "CERT_SAN_DOMAIN")
                assert san_edge.target == "Domain:api.target.com"
