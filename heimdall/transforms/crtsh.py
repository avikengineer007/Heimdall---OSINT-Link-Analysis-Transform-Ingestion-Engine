"""
Certificate Transparency Log Transforms using crt.sh.
"""

from __future__ import annotations

import logging
from typing import Any, List, Set
from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.crtsh")


@register_transform
class CrtshSubdomainTransform(BaseTransform):
    """Discovers subdomains and certificates via Certificate Transparency logs."""

    name = "crtsh_subdomains"
    display_name = "Certificate Transparency Subdomain Discovery"
    description = "Searches crt.sh CT logs to identify subdomains and SSL certificates."
    input_types: Set[str] = {EntityType.DOMAIN.value}
    output_types: Set[str] = {EntityType.SUBDOMAIN.value, EntityType.DOMAIN.value}

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        domain = DataSanitizer.domain(value)
        if not domain:
            return []

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await transport.get(url, timeout=10.0)
        if not resp or resp.status_code != 200:
            return []

        edges: List[GraphEdge] = []
        discovered_subs: Set[str] = set()

        try:
            records = resp.json()
            if not isinstance(records, list):
                return []

            for record in records:
                # name_value can have newline-delimited SANs
                name_value = str(record.get("name_value", ""))
                common_name = str(record.get("common_name", ""))
                combined = f"{name_value}\n{common_name}"

                for raw_sub in combined.splitlines():
                    clean_entry = raw_sub.strip().lower()
                    if clean_entry.startswith("*."):
                        clean_entry = clean_entry[2:]

                    sub = DataSanitizer.domain(clean_entry)
                    if sub and sub.endswith(f".{domain}") and sub != domain:
                        discovered_subs.add(sub)

            for sub in discovered_subs:
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.SUBDOMAIN.value}:{sub}",
                        target_type=EntityType.SUBDOMAIN.value,
                        rel="HAS_SUBDOMAIN",
                        properties={
                            "provider": "crt.sh",
                            "confidence": 0.95,
                        },
                    )
                )

        except Exception as exc:
            logger.debug(f"crt.sh response parse error for {domain}: {exc}")

        return edges
