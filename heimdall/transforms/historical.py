"""
Historical Reconnaissance & Endpoint Mining Transform.

Queries the Wayback Machine CDX index and AlienVault OTX Passive DNS
to uncover historical subdomains, archived API endpoints, and legacy IP mappings.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.transforms.historical")


class HistoricalReconTransform(BaseTransform):
    """
    Mines historical internet archives (Wayback Machine CDX & AlienVault OTX)
    for forgotten endpoints, legacy IPs, and dormant subdomains.
    """

    name = "historical_recon"
    display_name = "Historical Recon (Wayback & AlienVault OTX)"
    description = "Mines Wayback Machine CDX API and AlienVault OTX for historical subdomains and legacy endpoints."
    input_types: Set[str] = {EntityType.DOMAIN.value}
    output_types: Set[str] = {
        EntityType.SUBDOMAIN.value,
        EntityType.IPV4.value,
        EntityType.HISTORICAL_RECORD.value,
    }
    requires_api_key = False

    async def _query_wayback_cdx(
        self, domain: str, transport: ResilientAsyncTransport
    ) -> List[Dict[str, str]]:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original,mimetype,timestamp&collapse=urlkey&limit=50"
        )
        try:
            resp = await transport.get(url, timeout=4.0)
            if resp and resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    headers = data[0]
                    rows = data[1:]
                    return [dict(zip(headers, r)) for r in rows]
        except Exception as exc:
            logger.debug(f"Wayback CDX lookup skipped for {domain}: {exc}")
        return []

    async def _query_alienvault_otx(
        self, domain: str, transport: ResilientAsyncTransport
    ) -> List[Dict[str, Any]]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            resp = await transport.get(url, timeout=4.0)
            if resp and resp.status_code == 200:
                data = resp.json()
                return data.get("passive_dns", [])
        except Exception as exc:
            logger.debug(f"AlienVault OTX lookup skipped for {domain}: {exc}")
        return []

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

        edges: List[GraphEdge] = []
        discovered_subs: Set[str] = set()
        discovered_ips: Set[str] = set()

        # 1. Query Wayback Machine CDX
        wb_records = await self._query_wayback_cdx(domain, transport)
        for row in wb_records:
            orig_url = row.get("original", "")
            if not orig_url:
                continue

            parsed = urlparse(orig_url)
            host = parsed.netloc.split(":")[0].lower()

            # Check if host is a valid subdomain
            if host != domain and host.endswith(f".{domain}") and host not in discovered_subs:
                discovered_subs.add(host)
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.SUBDOMAIN.value}:{host}",
                        target_type=EntityType.SUBDOMAIN.value,
                        rel="ARCHIVED_SUBDOMAIN",
                        properties={"source": "wayback_cdx", "first_seen": row.get("timestamp", "")},
                    )
                )

            # Check if path indicates sensitive or API endpoint
            path_lower = parsed.path.lower()
            if any(k in path_lower for k in ("/api/", "/v1/", "/v2/", "/admin", "/login", "/swagger", ".json", ".xml", ".env", ".bak")):
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.HISTORICAL_RECORD.value}:{orig_url[:120]}",
                        target_type=EntityType.HISTORICAL_RECORD.value,
                        rel="ARCHIVED_ENDPOINT",
                        properties={
                            "url": orig_url,
                            "mime_type": row.get("mimetype", ""),
                            "timestamp": row.get("timestamp", ""),
                            "source": "wayback_machine",
                        },
                    )
                )

        # 2. Query AlienVault OTX Passive DNS
        otx_records = await self._query_alienvault_otx(domain, transport)
        for rec in otx_records[:20]:
            ip_val = rec.get("address", "")
            rec_type = rec.get("record_type", "")
            clean_ip = DataSanitizer.ipv4(ip_val)

            if clean_ip and clean_ip not in discovered_ips and rec_type in ("A", ""):
                discovered_ips.add(clean_ip)
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.IPV4.value}:{clean_ip}",
                        target_type=EntityType.IPV4.value,
                        rel="HISTORICALLY_RESOLVED_TO",
                        properties={
                            "first_seen": rec.get("first", ""),
                            "last_seen": rec.get("last", ""),
                            "source": "alienvault_otx",
                        },
                    )
                )

        return edges


TransformRegistry.register(HistoricalReconTransform())
