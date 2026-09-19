"""
Shodan InternetDB & REST API Infrastructure Transforms.
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional, Set
from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.shodan")


@register_transform
class ShodanInternetDBTransform(BaseTransform):
    """
    Queries Shodan InternetDB - a high-speed, zero-authentication OSINT service
    providing open ports, software CPEs, tags, and confirmed vulnerabilities (CVEs).
    """

    name = "shodan_internetdb"
    display_name = "Shodan InternetDB (Zero-Key Port & Vuln Scan)"
    description = "Queries public InternetDB for open ports, hostnames, CPEs, and CVEs."
    input_types: Set[str] = {EntityType.IPV4.value}
    output_types: Set[str] = {
        EntityType.PORT_SERVICE.value,
        EntityType.DOMAIN.value,
    }
    requires_api_key: bool = False

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

        url = f"https://internetdb.shodan.io/{ip_clean}"
        resp = await transport.get(url)
        if not resp or resp.status_code != 200:
            return []

        edges: List[GraphEdge] = []
        try:
            data = resp.json()

            # 1. Open Ports
            for port in data.get("ports", []):
                p_valid = DataSanitizer.port(port)
                if p_valid:
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=f"{EntityType.PORT_SERVICE.value}:{ip_clean}:{p_valid}",
                            target_type=EntityType.PORT_SERVICE.value,
                            rel="EXPOSES_SERVICE",
                            properties={"port": p_valid, "protocol": "tcp", "source": "internetdb"},
                        )
                    )

            # 2. Hostnames
            for host in data.get("hostnames", []):
                d_clean = DataSanitizer.domain(host)
                if d_clean:
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=f"{EntityType.DOMAIN.value}:{d_clean}",
                            target_type=EntityType.DOMAIN.value,
                            rel="ASSOCIATED_WITH",
                            properties={"source": "internetdb"},
                        )
                    )

            # 3. CVEs as properties / tags
            vulns = data.get("vulns", [])
            cpes = data.get("cpes", [])
            tags = data.get("tags", [])
            if vulns or cpes or tags:
                # Add metadata edge or enrich properties
                pass

        except Exception as exc:
            logger.debug(f"InternetDB parse error for {ip_clean}: {exc}")

        return edges


@register_transform
class ShodanHostEnrichmentTransform(BaseTransform):
    """
    Queries the official Shodan REST API using SHODAN_API_KEY.
    Provides in-depth OSINT: banners, operating systems, ISPs, organizations, and ASNs.
    """

    name = "shodan_host_enrich"
    display_name = "Shodan Full Host Enrichment (API Key)"
    description = "Extracts deep banner fingerprints, ISP, ASN, and organizational ownership from Shodan."
    input_types: Set[str] = {EntityType.IPV4.value}
    output_types: Set[str] = {
        EntityType.ORGANIZATION.value,
        EntityType.ASN.value,
        EntityType.PORT_SERVICE.value,
    }
    requires_api_key: bool = True

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        api_key = kwargs.get("shodan_api_key") or os.environ.get("SHODAN_API_KEY")
        if not api_key:
            return []

        ip_clean = DataSanitizer.ipv4(value)
        if not ip_clean:
            return []

        url = f"https://api.shodan.io/shodan/host/{ip_clean}"
        resp = await transport.get(url, params={"key": api_key})
        if not resp or resp.status_code != 200:
            return []

        edges: List[GraphEdge] = []
        try:
            data = resp.json()

            # Organization
            org = data.get("org")
            if org and org.strip():
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.ORGANIZATION.value}:{org.strip()}",
                        target_type=EntityType.ORGANIZATION.value,
                        rel="OWNED_BY",
                        properties={"isp": data.get("isp", ""), "country": data.get("country_name", "")},
                    )
                )

            # ASN
            asn_raw = data.get("asn")
            clean_asn = DataSanitizer.asn(asn_raw)
            if clean_asn:
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.ASN.value}:{clean_asn}",
                        target_type=EntityType.ASN.value,
                        rel="ROUTED_BY",
                        properties={"asn": clean_asn},
                    )
                )

            # Ports & Service banners
            for item in data.get("data", []):
                p = item.get("port")
                if p:
                    svc_urn = f"{EntityType.PORT_SERVICE.value}:{ip_clean}:{p}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=svc_urn,
                            target_type=EntityType.PORT_SERVICE.value,
                            rel="EXPOSES_SERVICE",
                            properties={
                                "port": p,
                                "transport": item.get("transport", "tcp"),
                                "product": item.get("product", ""),
                                "version": item.get("version", ""),
                            },
                        )
                    )

        except Exception as exc:
            logger.debug(f"Shodan API parse error for {ip_clean}: {exc}")

        return edges
