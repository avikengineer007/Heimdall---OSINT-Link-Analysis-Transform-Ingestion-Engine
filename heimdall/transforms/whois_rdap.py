"""
Registration Data Access Protocol (RDAP) Modern WHOIS Transforms.
"""

from __future__ import annotations

import logging
from typing import Any, List, Set
from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.rdap")


def _extract_vcard_fn(entity: dict) -> str:
    """Extracts formatted name (FN) or org name from jCard/vCard structure."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) > 3:
                if prop[0] in ("fn", "org"):
                    val = str(prop[3]).strip()
                    if val:
                        return val
    handle = entity.get("handle")
    return str(handle).strip() if handle else ""


def _extract_vcard_email(entity: dict) -> str:
    """Extracts email from jCard/vCard structure."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) > 3:
                if prop[0] == "email":
                    val = str(prop[3]).strip()
                    if val:
                        return val
    return ""


@register_transform
class DomainRDAPTransform(BaseTransform):
    """Resolves Domain WHOIS/RDAP metadata into Registrar, Org, and Email entities."""

    name = "rdap_domain"
    display_name = "Domain RDAP / WHOIS Lookup"
    description = "Queries official RDAP servers to extract registrar, registrant, and technical contacts."
    input_types: Set[str] = {EntityType.DOMAIN.value}
    output_types: Set[str] = {
        EntityType.REGISTRAR.value,
        EntityType.ORGANIZATION.value,
        EntityType.EMAIL.value,
    }

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

        url = f"https://rdap.org/domain/{domain}"
        resp = await transport.get(url)
        if not resp or resp.status_code != 200:
            return []

        edges: List[GraphEdge] = []
        try:
            data = resp.json()
            entities = data.get("entities", [])

            for ent in entities:
                roles = ent.get("roles", [])
                name = _extract_vcard_fn(ent)
                email = _extract_vcard_email(ent)
                clean_email = DataSanitizer.email(email)

                # Registrar identification
                if "registrar" in roles and name:
                    reg_urn = f"{EntityType.REGISTRAR.value}:{name}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=reg_urn,
                            target_type=EntityType.REGISTRAR.value,
                            rel="REGISTERED_WITH",
                            properties={"roles": ",".join(roles), "handle": ent.get("handle", "")},
                        )
                    )
                    if clean_email:
                        edges.append(
                            GraphEdge(
                                source=reg_urn,
                                target=f"{EntityType.EMAIL.value}:{clean_email}",
                                target_type=EntityType.EMAIL.value,
                                rel="HAS_CONTACT",
                                properties={"type": "abuse_or_registrar"},
                            )
                        )

                # Registrant / Org identification
                elif ("registrant" in roles or "administrative" in roles) and name:
                    org_urn = f"{EntityType.ORGANIZATION.value}:{name}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=org_urn,
                            target_type=EntityType.ORGANIZATION.value,
                            rel="MANAGED_BY",
                            properties={"roles": ",".join(roles)},
                        )
                    )
                    if clean_email:
                        edges.append(
                            GraphEdge(
                                source=org_urn,
                                target=f"{EntityType.EMAIL.value}:{clean_email}",
                                target_type=EntityType.EMAIL.value,
                                rel="HAS_CONTACT",
                                properties={"type": "registrant_contact"},
                            )
                        )

        except Exception as exc:
            logger.debug(f"RDAP domain parsing error for {domain}: {exc}")

        return edges


@register_transform
class IPV4RDAPTransform(BaseTransform):
    """Resolves IP WHOIS/RDAP to identify owning Organizations, ASNs, and Networks."""

    name = "rdap_ip"
    display_name = "IP RDAP / NetRange Lookup"
    description = "Queries IP RDAP directories to resolve network ownership and ASN."
    input_types: Set[str] = {EntityType.IPV4.value}
    output_types: Set[str] = {EntityType.ORGANIZATION.value, EntityType.ASN.value}

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

        url = f"https://rdap.org/ip/{ip_clean}"
        resp = await transport.get(url)
        if not resp or resp.status_code != 200:
            return []

        edges: List[GraphEdge] = []
        try:
            data = resp.json()
            net_name = data.get("name")
            if net_name:
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.ORGANIZATION.value}:{net_name.strip()}",
                        target_type=EntityType.ORGANIZATION.value,
                        rel="HOSTED_ON_NETWORK",
                        properties={
                            "handle": data.get("handle", ""),
                            "start_address": data.get("startAddress", ""),
                            "end_address": data.get("endAddress", ""),
                        },
                    )
                )

            # Check entities inside IP RDAP
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                fn = _extract_vcard_fn(ent)
                if ("registrant" in roles or "administrative" in roles) and fn:
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=f"{EntityType.ORGANIZATION.value}:{fn}",
                            target_type=EntityType.ORGANIZATION.value,
                            rel="OWNED_BY",
                            properties={"roles": ",".join(roles)},
                        )
                    )

        except Exception as exc:
            logger.debug(f"RDAP IP parsing error for {ip_clean}: {exc}")

        return edges
