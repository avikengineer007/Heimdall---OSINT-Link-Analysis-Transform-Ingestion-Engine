"""
HTTP Security Audit Transform (Active Recon).

Performs direct HTTP header inspection to identify missing defensive headers
and detects Web Application Firewall (WAF) fingerprints.
Gated behind ACTIVE_RECON=true.
"""

from __future__ import annotations

import logging
from typing import Any, List

from heimdall.core.config import settings
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.http_audit")

DEFENSIVE_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "Clickjacking Defense",
    "x-content-type-options": "MIME Sniffing Defense",
    "referrer-policy": "Referrer Leakage Defense",
    "permissions-policy": "Permissions Boundary",
}

WAF_SIGNATURES = [
    ("cloudflare", lambda h: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
    ("akamai", lambda h: "akamai" in h.get("server", "").lower() or "x-akamai-transformed" in h),
    ("aws_cloudfront", lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower()),
    ("sucuri", lambda h: "x-sucuri-id" in h or "sucuri" in h.get("server", "").lower()),
    ("imperva_incapsula", lambda h: "x-iinfo" in h or "incap_ses" in str(h)),
]


@register_transform
class HTTPSecurityAuditTransform(BaseTransform):
    name = "http_security_audit"
    display_name = "HTTP Security & WAF Audit"
    description = "Audits defensive HTTP headers and detects WAF/CDN infrastructure."
    input_types = {EntityType.DOMAIN.value, EntityType.URL.value}
    output_types = {EntityType.SECURITY_HEADER.value, EntityType.WAF_SIGNATURE.value}

    async def run_safe(
        self,
        node_urn: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> TransformResult:
        if not settings.active_recon:
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="SKIPPED",
                error_message="Active recon is disabled. Set ACTIVE_RECON=true to enable HTTP security auditing.",
            )
        return await super().run_safe(node_urn, transport, **kwargs)

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        target_url = value if value.startswith(("http://", "https://")) else f"https://{value}"
        edges: List[GraphEdge] = []

        try:
            resp = await transport.request("HEAD", target_url, allow_redirects=True, timeout=5.0)
            if not resp:
                resp = await transport.request("GET", target_url, allow_redirects=True, timeout=5.0)

            if not resp:
                return []

            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Defensive headers check
            for header_key, header_title in DEFENSIVE_HEADERS.items():
                is_present = header_key in headers
                hdr_urn = f"{EntityType.SECURITY_HEADER.value}:{value}:{header_key}"
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=hdr_urn,
                        target_type=EntityType.SECURITY_HEADER.value,
                        rel="HAS_SECURITY_HEADER",
                        properties={
                            "header_name": header_key,
                            "title": header_title,
                            "present": is_present,
                            "value": headers.get(header_key, "")[:200],
                            "status": "PASS" if is_present else "MISSING",
                        },
                    )
                )

            # 2. WAF detection
            for waf_name, matcher in WAF_SIGNATURES:
                if matcher(headers):
                    waf_urn = f"{EntityType.WAF_SIGNATURE.value}:{waf_name}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=waf_urn,
                            target_type=EntityType.WAF_SIGNATURE.value,
                            rel="PROTECTED_BY_WAF",
                            properties={
                                "waf": waf_name,
                                "server_header": headers.get("server", ""),
                            },
                        )
                    )

            return edges

        except Exception as e:
            logger.debug(f"HTTP security audit failed on {target_url}: {e}")
            return []
