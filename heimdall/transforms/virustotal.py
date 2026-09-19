"""
VirusTotal Transform — Domain & IP Reputation via VirusTotal API v3.

Zero-key mode: NOT supported — VirusTotal requires an API key.
When VIRUSTOTAL_API_KEY is absent, the transform returns a SKIPPED status with
an informative reason rather than failing the pipeline.

Authenticated mode: Queries /domains/{domain} and /ip_addresses/{ip} endpoints,
extracting reputation scores, detected engines, and passive DNS resolutions.
"""

from __future__ import annotations

import logging
from typing import Any, List

from heimdall.core.config import settings
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.virustotal")

_VT_BASE = "https://www.virustotal.com/api/v3"


@register_transform
class VirusTotalTransform(BaseTransform):
    name = "virustotal_reputation"
    display_name = "VirusTotal Reputation"
    description = (
        "Queries VirusTotal API v3 for domain/IP reputation scores, "
        "malicious detection counts, and passive DNS resolutions. "
        "Requires VIRUSTOTAL_API_KEY."
    )
    input_types = {EntityType.DOMAIN.value, EntityType.IPV4.value}
    output_types = {
        EntityType.MALICIOUS_DETECTION.value,
        EntityType.THREAT_SCORE.value,
        EntityType.IPV4.value,
    }
    requires_api_key = True

    async def run_safe(
        self,
        node_urn: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> TransformResult:
        """Override to emit SKIPPED when API key is missing."""
        api_key = kwargs.get("virustotal_api_key") or settings.virustotal_api_key
        if not api_key:
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="SKIPPED",
                error_message="VIRUSTOTAL_API_KEY not set — skipping VirusTotal transform",
            )
        return await super().run_safe(node_urn, transport, virustotal_api_key=api_key, **kwargs)

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        api_key = kwargs["virustotal_api_key"]
        entity_type = node_urn.split(":", 1)[0]
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        edges: List[GraphEdge] = []

        # Choose endpoint based on entity type
        if entity_type == EntityType.DOMAIN.value:
            url = f"{_VT_BASE}/domains/{value}"
        else:
            url = f"{_VT_BASE}/ip_addresses/{value}"

        data = await transport.get_json(url, headers=headers)
        if not data or "data" not in data:
            return edges

        attrs = data["data"].get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values()) or 1
        detected = malicious + suspicious

        # Emit threat detection node
        if detected > 0:
            edges.append(GraphEdge(
                source=node_urn,
                target=f"{EntityType.MALICIOUS_DETECTION.value}:vt:{value}",
                target_type=EntityType.MALICIOUS_DETECTION.value,
                rel="DETECTED_BY_VIRUSTOTAL",
                properties={
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "total_engines": total,
                    "detection_ratio": f"{detected}/{total}",
                    "reputation": attrs.get("reputation", 0),
                    "source": "VirusTotal",
                },
            ))

        # Passive DNS resolutions (domain only)
        if entity_type == EntityType.DOMAIN.value:
            resolutions = attrs.get("last_dns_records", [])
            for rec in resolutions[:8]:
                if rec.get("type") == "A":
                    ip = rec.get("value", "").strip()
                    if ip:
                        edges.append(GraphEdge(
                            source=node_urn,
                            target=f"{EntityType.IPV4.value}:{ip}",
                            target_type=EntityType.IPV4.value,
                            rel="VT_PASSIVE_DNS",
                            properties={"ttl": rec.get("ttl"), "source": "VirusTotal"},
                        ))

        return edges
