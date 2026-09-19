"""
MX Security Transform — SPF, DMARC, DKIM, and MX Server Discovery.

Zero-key mode: Fully operational — uses DNS over HTTPS (DoH) TXT record lookups
directly. No API key required.

For a given domain, this transform:
  1. Resolves MX records → MXServer nodes
  2. Fetches TXT records from @ apex → extracts SPF policy
  3. Fetches TXT records from _dmarc.<domain> → extracts DMARC policy
  4. Probes common DKIM selectors (google, default, selector1, selector2, mail,
     k1, s1) → discovers DKIMSelector nodes for valid keys
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, List

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.mx_security")

_DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
_DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "mail", "k1", "s1", "s2", "dkim", "smtp"]


@register_transform
class MXSecurityTransform(BaseTransform):
    name = "mx_security"
    display_name = "MX & Email Security (SPF/DMARC/DKIM)"
    description = (
        "Discovers MX servers and validates email security posture: "
        "SPF policy extraction, DMARC policy inspection, and DKIM selector "
        "discovery via DNS over HTTPS. No API key required."
    )
    input_types = {EntityType.DOMAIN.value}
    output_types = {
        EntityType.MX_SERVER.value,
        EntityType.SPF_RECORD.value,
        EntityType.DMARC_POLICY.value,
        EntityType.DKIM_SELECTOR.value,
    }
    requires_api_key = False

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []

        # Run all DNS queries concurrently
        mx_edges, spf_edges, dmarc_edges, dkim_edges = await asyncio.gather(
            self._resolve_mx(node_urn, value, transport),
            self._resolve_spf(node_urn, value, transport),
            self._resolve_dmarc(node_urn, value, transport),
            self._probe_dkim(node_urn, value, transport),
        )

        edges.extend(mx_edges)
        edges.extend(spf_edges)
        edges.extend(dmarc_edges)
        edges.extend(dkim_edges)
        return edges

    async def _doh_txt(
        self,
        transport: ResilientAsyncTransport,
        name: str,
    ) -> List[str]:
        """Fetches TXT records for `name` via Cloudflare DoH JSON API."""
        params = f"?name={name}&type=TXT"
        data = await transport.get_json(
            f"{_DOH_CLOUDFLARE}{params}",
            headers={"Accept": "application/dns-json"},
        )
        records = []
        if data and data.get("Status") == 0:
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:  # TXT
                    txt = ans.get("data", "").strip('"').replace('" "', "")
                    records.append(txt)
        return records

    async def _doh_mx(
        self,
        transport: ResilientAsyncTransport,
        name: str,
    ) -> List[dict]:
        """Fetches MX records for `name` via Cloudflare DoH."""
        params = f"?name={name}&type=MX"
        data = await transport.get_json(
            f"{_DOH_CLOUDFLARE}{params}",
            headers={"Accept": "application/dns-json"},
        )
        records = []
        if data and data.get("Status") == 0:
            for ans in data.get("Answer", []):
                if ans.get("type") == 15:  # MX
                    raw = ans.get("data", "")
                    parts = raw.split(maxsplit=1)
                    if len(parts) == 2:
                        try:
                            records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                        except ValueError:
                            pass
        return records

    async def _resolve_mx(
        self,
        node_urn: str,
        domain: str,
        transport: ResilientAsyncTransport,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        mx_records = await self._doh_mx(transport, domain)
        for rec in mx_records:
            host = rec["host"]
            if host:
                edges.append(GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.MX_SERVER.value}:{host}",
                    target_type=EntityType.MX_SERVER.value,
                    rel="HAS_MX_SERVER",
                    properties={"priority": rec["priority"], "host": host},
                ))
        return edges

    async def _resolve_spf(
        self,
        node_urn: str,
        domain: str,
        transport: ResilientAsyncTransport,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        txt_records = await self._doh_txt(transport, domain)
        for txt in txt_records:
            if txt.startswith("v=spf1"):
                # Parse policy strictness
                policy = "unknown"
                if "~all" in txt:
                    policy = "softfail"
                elif "-all" in txt:
                    policy = "fail"
                elif "+all" in txt:
                    policy = "pass_all"  # Dangerous
                elif "?all" in txt:
                    policy = "neutral"
                elif txt.strip().endswith("v=spf1"):
                    policy = "no_all"

                edges.append(GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.SPF_RECORD.value}:{domain}",
                    target_type=EntityType.SPF_RECORD.value,
                    rel="HAS_SPF_RECORD",
                    properties={
                        "policy": policy,
                        "record": txt[:200],
                        "has_spf": True,
                    },
                ))
                break
        return edges

    async def _resolve_dmarc(
        self,
        node_urn: str,
        domain: str,
        transport: ResilientAsyncTransport,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        dmarc_host = f"_dmarc.{domain}"
        txt_records = await self._doh_txt(transport, dmarc_host)

        for txt in txt_records:
            if "v=DMARC1" in txt:
                # Parse policy
                policy_match = re.search(r"\bp=(\w+)", txt)
                sp_match     = re.search(r"\bsp=(\w+)", txt)
                pct_match    = re.search(r"\bpct=(\d+)", txt)
                rua_match    = re.search(r"\brua=([^;]+)", txt)

                edges.append(GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.DMARC_POLICY.value}:{domain}",
                    target_type=EntityType.DMARC_POLICY.value,
                    rel="HAS_DMARC_POLICY",
                    properties={
                        "policy": policy_match.group(1) if policy_match else "none",
                        "subdomain_policy": sp_match.group(1) if sp_match else "inherit",
                        "pct": int(pct_match.group(1)) if pct_match else 100,
                        "rua": rua_match.group(1).strip() if rua_match else "",
                        "record": txt[:200],
                    },
                ))
                break
        return edges

    async def _probe_dkim(
        self,
        node_urn: str,
        domain: str,
        transport: ResilientAsyncTransport,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []

        async def probe_selector(sel: str) -> GraphEdge | None:
            dkim_host = f"{sel}._domainkey.{domain}"
            records = await self._doh_txt(transport, dkim_host)
            for txt in records:
                if "p=" in txt or "v=DKIM1" in txt:
                    return GraphEdge(
                        source=node_urn,
                        target=f"{EntityType.DKIM_SELECTOR.value}:{sel}.{domain}",
                        target_type=EntityType.DKIM_SELECTOR.value,
                        rel="HAS_DKIM_SELECTOR",
                        properties={
                            "selector": sel,
                            "has_public_key": "p=" in txt and 'p=""' not in txt,
                            "version": "DKIM1" if "v=DKIM1" in txt else "unknown",
                        },
                    )
            return None

        # Probe all selectors concurrently
        results = await asyncio.gather(*[probe_selector(s) for s in _DKIM_SELECTORS])
        edges.extend(r for r in results if r is not None)
        return edges
