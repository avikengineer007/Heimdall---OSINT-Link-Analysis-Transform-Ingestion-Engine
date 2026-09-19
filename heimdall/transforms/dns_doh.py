"""
DNS over HTTPS (DoH) Transforms for Records Resolution and Reverse DNS.
"""

from __future__ import annotations

import logging
from typing import Any, List, Set
from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.dns")


@register_transform
class DNSResolutionTransform(BaseTransform):
    """Resolves DNS records (A, AAAA, MX, NS, CNAME) via Cloudflare & Google DoH."""

    name = "dns_resolve"
    display_name = "DNS Forward Resolution (DoH)"
    description = "Queries A, AAAA, MX, NS, and CNAME records using secure DNS over HTTPS."
    input_types: Set[str] = {EntityType.DOMAIN.value, EntityType.SUBDOMAIN.value}
    output_types: Set[str] = {
        EntityType.IPV4.value,
        EntityType.IPV6.value,
        EntityType.DOMAIN.value,
    }

    _DOH_ENDPOINTS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    async def _query_doh(
        self,
        name: str,
        rtype: str,
        transport: ResilientAsyncTransport,
    ) -> List[dict]:
        headers = {"accept": "application/dns-json"}
        for url in self._DOH_ENDPOINTS:
            params = {"name": name, "type": rtype}
            resp = await transport.get(url, params=params, headers=headers)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    return data.get("Answer", [])
                except Exception:
                    continue
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
        source_urn = node_urn

        # 1. Query A records (IPv4)
        a_answers = await self._query_doh(domain, "A", transport)
        for ans in a_answers:
            if ans.get("type") == 1:
                ip_clean = DataSanitizer.ipv4(str(ans.get("data", "")))
                if ip_clean:
                    edges.append(
                        GraphEdge(
                            source=source_urn,
                            target=f"{EntityType.IPV4.value}:{ip_clean}",
                            target_type=EntityType.IPV4.value,
                            rel="RESOLVES_TO",
                            properties={"ttl": ans.get("TTL", 300), "record_type": "A"},
                        )
                    )

        # 2. Query AAAA records (IPv6)
        aaaa_answers = await self._query_doh(domain, "AAAA", transport)
        for ans in aaaa_answers:
            if ans.get("type") == 28:
                ip6_clean = DataSanitizer.ipv6(str(ans.get("data", "")))
                if ip6_clean:
                    edges.append(
                        GraphEdge(
                            source=source_urn,
                            target=f"{EntityType.IPV6.value}:{ip6_clean}",
                            target_type=EntityType.IPV6.value,
                            rel="RESOLVES_TO",
                            properties={"ttl": ans.get("TTL", 300), "record_type": "AAAA"},
                        )
                    )

        # 3. Query MX records (Mail Exchanger)
        mx_answers = await self._query_doh(domain, "MX", transport)
        for ans in mx_answers:
            if ans.get("type") == 15:
                raw_data = str(ans.get("data", ""))
                # Format is typically "10 mail.example.com."
                parts = raw_data.strip().split()
                mx_host = parts[-1] if parts else raw_data
                mx_clean = DataSanitizer.domain(mx_host)
                if mx_clean:
                    priority = int(parts[0]) if len(parts) > 1 and parts[0].isdigit() else 10
                    edges.append(
                        GraphEdge(
                            source=source_urn,
                            target=f"{EntityType.DOMAIN.value}:{mx_clean}",
                            target_type=EntityType.DOMAIN.value,
                            rel="HAS_MX",
                            properties={"priority": priority, "record_type": "MX"},
                        )
                    )

        # 4. Query NS records (Nameservers)
        ns_answers = await self._query_doh(domain, "NS", transport)
        for ans in ns_answers:
            if ans.get("type") == 2:
                ns_clean = DataSanitizer.domain(str(ans.get("data", "")))
                if ns_clean:
                    edges.append(
                        GraphEdge(
                            source=source_urn,
                            target=f"{EntityType.DOMAIN.value}:{ns_clean}",
                            target_type=EntityType.DOMAIN.value,
                            rel="HAS_NAMESERVER",
                            properties={"record_type": "NS"},
                        )
                    )

        # 5. Query CNAME records
        cname_answers = await self._query_doh(domain, "CNAME", transport)
        for ans in cname_answers:
            if ans.get("type") == 5:
                cname_clean = DataSanitizer.domain(str(ans.get("data", "")))
                if cname_clean and cname_clean != domain:
                    edges.append(
                        GraphEdge(
                            source=source_urn,
                            target=f"{EntityType.DOMAIN.value}:{cname_clean}",
                            target_type=EntityType.DOMAIN.value,
                            rel="ALIAS_FOR",
                            properties={"record_type": "CNAME"},
                        )
                    )

        return edges


@register_transform
class ReverseDNSTransform(BaseTransform):
    """Resolves Reverse DNS (PTR) for an IPv4 address to hostname."""

    name = "reverse_dns"
    display_name = "Reverse DNS (PTR)"
    description = "Queries PTR records for IPv4 addresses via DoH."
    input_types: Set[str] = {EntityType.IPV4.value}
    output_types: Set[str] = {EntityType.DOMAIN.value}

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        ip_clean = DataSanitizer.ipv4(value)
        if not ip_clean:
            return []

        # Construct in-addr.arpa
        octets = ip_clean.split(".")
        arpa_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"

        url = "https://cloudflare-dns.com/dns-query"
        params = {"name": arpa_name, "type": "PTR"}
        headers = {"accept": "application/dns-json"}

        resp = await transport.get(url, params=params, headers=headers)
        edges: List[GraphEdge] = []
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 12:
                        hostname = DataSanitizer.domain(str(ans.get("data", "")))
                        if hostname:
                            edges.append(
                                GraphEdge(
                                    source=node_urn,
                                    target=f"{EntityType.DOMAIN.value}:{hostname}",
                                    target_type=EntityType.DOMAIN.value,
                                    rel="REVERSE_DNS",
                                    properties={"ttl": ans.get("TTL", 300)},
                                )
                            )
            except Exception as exc:
                logger.debug(f"PTR parse error for {ip_clean}: {exc}")

        return edges
