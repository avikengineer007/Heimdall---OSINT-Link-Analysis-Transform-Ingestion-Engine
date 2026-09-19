"""
BGP Routing Transform — ASN Infrastructure via BGPView.io.

Zero-key mode: Fully operational — BGPView public API requires no authentication.
Resolves ASNumbers to CIDR prefixes, peer ASNs, upstream providers, and
Internet Exchange points.

API Docs: https://bgpview.docs.apiary.io/
"""

from __future__ import annotations

import logging
from typing import Any, List

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.bgp_routing")

_BGPVIEW_BASE = "https://api.bgpview.io"


@register_transform
class BGPRoutingTransform(BaseTransform):
    name = "bgp_routing"
    display_name = "BGP Routing (BGPView)"
    description = (
        "Resolves ASNumbers to announced CIDR prefixes, peer ASNs, "
        "upstream providers, and Internet Exchange points via BGPView.io. "
        "Runs without any API key."
    )
    input_types = {EntityType.ASN.value, EntityType.IPV4.value}
    output_types = {
        EntityType.CIDR_BLOCK.value,
        EntityType.ASN.value,
        EntityType.ORGANIZATION.value,
        EntityType.INTERNET_EXCHANGE.value,
    }
    requires_api_key = False

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        entity_type = node_urn.split(":", 1)[0]
        edges: List[GraphEdge] = []

        if entity_type == EntityType.IPV4.value:
            # IP → ASN lookup first
            data = await transport.get_json(f"{_BGPVIEW_BASE}/ip/{value}")
            prefixes = (data or {}).get("data", {}).get("prefixes", [])
            for p in prefixes[:5]:
                asn_data = p.get("asn", {})
                asn_num = asn_data.get("asn")
                asn_org  = asn_data.get("name", "")
                network  = p.get("prefix", "")
                if asn_num:
                    asn_urn = f"{EntityType.ASN.value}:{asn_num}"
                    edges.append(GraphEdge(
                        source=node_urn,
                        target=asn_urn,
                        target_type=EntityType.ASN.value,
                        rel="ANNOUNCED_BY_ASN",
                        properties={"org": asn_org, "network": network},
                    ))
                    # Recurse to get full ASN data
                    edges.extend(await self._resolve_asn(str(asn_num), asn_urn, transport))
            return edges

        # ASN → Full routing data
        asn_num = value.lstrip("ASas")
        return await self._resolve_asn(asn_num, node_urn, transport)

    async def _resolve_asn(
        self,
        asn_num: str,
        asn_urn: str,
        transport: ResilientAsyncTransport,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []

        # 1. Prefixes announced by this ASN
        prefix_data = await transport.get_json(f"{_BGPVIEW_BASE}/asn/{asn_num}/prefixes")
        if prefix_data and prefix_data.get("status") == "ok":
            ipv4_prefixes = prefix_data.get("data", {}).get("ipv4_prefixes", [])
            for p in ipv4_prefixes[:10]:
                cidr = p.get("prefix", "")
                if cidr:
                    edges.append(GraphEdge(
                        source=asn_urn,
                        target=f"{EntityType.CIDR_BLOCK.value}:{cidr}",
                        target_type=EntityType.CIDR_BLOCK.value,
                        rel="ANNOUNCES_PREFIX",
                        properties={
                            "name": p.get("name", ""),
                            "description": p.get("description", ""),
                            "country": p.get("country_code", ""),
                        },
                    ))

        # 2. Peers
        peer_data = await transport.get_json(f"{_BGPVIEW_BASE}/asn/{asn_num}/peers")
        if peer_data and peer_data.get("status") == "ok":
            peers = peer_data.get("data", {}).get("ipv4_peers", [])
            for peer in peers[:6]:
                peer_asn = peer.get("asn")
                if peer_asn:
                    edges.append(GraphEdge(
                        source=asn_urn,
                        target=f"{EntityType.ASN.value}:{peer_asn}",
                        target_type=EntityType.ASN.value,
                        rel="BGP_PEER",
                        properties={"peer_name": peer.get("name", "")},
                    ))

        # 3. Upstreams
        upstream_data = await transport.get_json(f"{_BGPVIEW_BASE}/asn/{asn_num}/upstreams")
        if upstream_data and upstream_data.get("status") == "ok":
            upstreams = upstream_data.get("data", {}).get("ipv4_upstreams", [])
            for up in upstreams[:4]:
                up_asn = up.get("asn")
                if up_asn:
                    edges.append(GraphEdge(
                        source=asn_urn,
                        target=f"{EntityType.ASN.value}:{up_asn}",
                        target_type=EntityType.ASN.value,
                        rel="UPSTREAM_PROVIDER",
                        properties={"provider_name": up.get("name", "")},
                    ))

        # 4. Internet Exchange membership
        ix_data = await transport.get_json(f"{_BGPVIEW_BASE}/asn/{asn_num}/ixs")
        if ix_data and ix_data.get("status") == "ok":
            exchanges = ix_data.get("data", [])
            for ix in exchanges[:6]:
                ix_name = ix.get("name_long") or ix.get("name", "")
                ix_id   = ix.get("ix_id") or ix.get("name", "").replace(" ", "_").lower()
                if ix_name:
                    edges.append(GraphEdge(
                        source=asn_urn,
                        target=f"{EntityType.INTERNET_EXCHANGE.value}:{ix_id}",
                        target_type=EntityType.INTERNET_EXCHANGE.value,
                        rel="MEMBER_OF_IX",
                        properties={
                            "ix_name": ix_name,
                            "city": ix.get("city", ""),
                            "country": ix.get("country_code", ""),
                        },
                    ))

        return edges
