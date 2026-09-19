"""
Reverse WHOIS Transform — Pivot from Email/Org to All Registered Domains.

Zero-key mode: Fully operational via HackerTarget Reverse WHOIS API (free tier).
Pivots from a registrant email address or organization name to discover all
domains registered by the same entity — a key OSINT lateral movement technique.

API: https://api.hackertarget.com/reversewhois/?q=<email_or_org>
"""

from __future__ import annotations

import logging
from typing import Any, List

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.reverse_whois")

_HACKERTARGET_BASE = "https://api.hackertarget.com"


@register_transform
class ReverseWhoisTransform(BaseTransform):
    name = "reverse_whois"
    display_name = "Reverse WHOIS / Registrant Pivot"
    description = (
        "Pivots from a registrant email or organization name to discover "
        "all domains registered by the same entity via HackerTarget Reverse WHOIS. "
        "Runs without any API key."
    )
    input_types = {EntityType.EMAIL.value, EntityType.ORGANIZATION.value}
    output_types = {EntityType.DOMAIN.value}
    requires_api_key = False

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []

        url = f"{_HACKERTARGET_BASE}/reversewhois/?q={value}"
        text = await transport.get_text(url)

        if not text or "error" in text.lower() or "no records" in text.lower():
            return edges

        # HackerTarget returns one domain per line
        domains = [line.strip() for line in text.splitlines() if line.strip()]
        rel = "REGISTERED_BY_EMAIL" if node_urn.split(":", 1)[0] == EntityType.EMAIL.value else "REGISTERED_BY_ORG"

        for raw_domain in domains[:25]:
            normalized = DataSanitizer.domain(raw_domain)
            if not normalized:
                continue
            edges.append(GraphEdge(
                source=node_urn,
                target=f"{EntityType.DOMAIN.value}:{normalized}",
                target_type=EntityType.DOMAIN.value,
                rel=rel,
                properties={"source": "HackerTarget ReverseWHOIS"},
            ))

        return edges
