"""
Heimdall Smart Pivot Agent.

Dynamically scores and selects high-signal transforms for frontier entities
using deterministic heuristic rules with an optional generic OpenAI-compatible LLM hook.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from heimdall.core.config import settings
from heimdall.core.models import EntityType
from heimdall.transforms.base import BaseTransform

logger = logging.getLogger("heimdall.pipeline.smart_agent")

CDN_ORGS = {"cloudflare", "fastly", "akamai", "incapsula", "amazon cloudfront", "edgecast"}

# Built-in heuristic priority rules (used when config file is missing or extended)
DEFAULT_RULES = [
    {
        "id": "mail_port_priority",
        "entity_type": "PortService",
        "ports": [25, 465, 587, 110, 143],
        "preferred_transforms": ["mx_security"],
        "boost": 10,
    },
    {
        "id": "multi_port_ipv4",
        "entity_type": "IPv4",
        "min_ports": 3,
        "preferred_transforms": ["abuseipdb_check", "shodan_host_enrichment"],
        "boost": 8,
    },
    {
        "id": "subdomain_resolution",
        "entity_type": "Domain",
        "preferred_transforms": ["dns_resolve", "web_surface"],
        "boost": 6,
    },
    {
        "id": "asn_bgp_priority",
        "entity_type": "ASNumber",
        "preferred_transforms": ["bgp_routing"],
        "boost": 9,
    },
    {
        "id": "email_reverse_whois",
        "entity_type": "Email",
        "preferred_transforms": ["reverse_whois"],
        "boost": 7,
    },
    {
        "id": "cdn_ip_suppression",
        "entity_type": "IPv4",
        "cdn_orgs": list(CDN_ORGS),
        "suppressed_transforms": ["crtsh_subdomain", "shodan_host_enrichment", "tls_cert_extract"],
        "boost": -10,
    },
]


class PivotAgent:
    """
    Intelligent transform selector.

    Replaces flat BFS crawls with heuristic/LLM-prioritized transform execution.
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        top_k: Optional[int] = None,
        llm_ranker: Optional[Callable] = None,
    ):
        self.top_k = top_k if top_k is not None else settings.smart_pivot_top_k
        self.rules_path = rules_path or settings.pivot_rules_path
        self.llm_ranker = llm_ranker
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        path = Path(self.rules_path)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "rules" in data:
                        return data["rules"]
            except Exception as e:
                logger.warning(f"Failed to parse custom pivot rules at {path}: {e}")
        return DEFAULT_RULES

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Returns the loaded rules for API and UI inspection."""
        return self.rules

    def score_transforms(
        self,
        node_urn: str,
        properties: Dict[str, Any],
        candidate_transforms: List[BaseTransform],
    ) -> List[Tuple[BaseTransform, int]]:
        """
        Scores candidate transforms based on entity attributes and heuristics.

        Returns a list of (transform, score) sorted highest-score first.
        """
        if not candidate_transforms:
            return []

        # Parse entity type from URN (e.g. "IPv4:1.1.1.1" -> "IPv4")
        urn_type = node_urn.split(":", 1)[0] if ":" in node_urn else ""

        scored: List[Tuple[BaseTransform, int]] = []

        for transform in candidate_transforms:
            score = 10  # Base priority score

            for rule in self.rules:
                rule_type = rule.get("entity_type", "")
                if rule_type and rule_type.lower() != urn_type.lower():
                    continue

                # Check port match rule
                if "ports" in rule:
                    port_val = properties.get("port")
                    if port_val:
                        try:
                            if int(port_val) in rule["ports"]:
                                if transform.name in rule.get("preferred_transforms", []):
                                    score += rule.get("boost", 5)
                        except (ValueError, TypeError):
                            pass

                # Check multi-port match rule
                if "min_ports" in rule:
                    ports = properties.get("ports", [])
                    if isinstance(ports, list) and len(ports) >= rule["min_ports"]:
                        if transform.name in rule.get("preferred_transforms", []):
                            score += rule.get("boost", 5)

                # Check CDN organization match
                if "cdn_orgs" in rule:
                    org = str(properties.get("org", "")).lower()
                    asn_desc = str(properties.get("as_name", "")).lower()
                    target_orgs = [o.lower() for o in rule.get("cdn_orgs", [])]
                    is_cdn = any(c in org or c in asn_desc for c in target_orgs)
                    if is_cdn:
                        if transform.name in rule.get("suppressed_transforms", []):
                            score += rule.get("boost", -10)

                # General preferred transforms for type
                preferred = rule.get("preferred_transforms", [])
                if transform.name in preferred and "ports" not in rule and "min_ports" not in rule:
                    score += rule.get("boost", 5)

            scored.append((transform, score))

        # Sort descending by priority score
        scored.sort(key=lambda item: item[1], reverse=True)

        # Apply top_k limiting if configured
        if self.top_k > 0:
            return scored[: self.top_k]
        return scored

    def filter_frontier(self, frontier: Set[str], graph_store: Any) -> Set[str]:
        """
        Prunes frontier nodes that match suppression criteria (e.g., CDN IPs).
        """
        filtered: Set[str] = set()
        for urn in frontier:
            if not urn.startswith("IPv4:"):
                filtered.add(urn)
                continue

            node = graph_store.get_node(urn)
            if not node:
                filtered.add(urn)
                continue

            org = str(node.properties.get("org", "")).lower()
            as_name = str(node.properties.get("as_name", "")).lower()
            if any(cdn in org or cdn in as_name for cdn in CDN_ORGS):
                # Suppress crawling deep into CDN infrastructure
                logger.debug(f"SmartAgent: Suppressed CDN frontier node {urn} ({org or as_name})")
                continue

            filtered.add(urn)
        return filtered

    async def rank_with_llm(
        self,
        node_urn: str,
        properties: Dict[str, Any],
        candidate_transforms: List[BaseTransform],
    ) -> List[Tuple[BaseTransform, int]]:
        """
        Optional LLM-assisted ranker via generic OpenAI-compatible endpoint.
        Gracefully falls back to deterministic heuristic score_transforms on failure or missing endpoint.
        """
        if not settings.llm_base_url or not candidate_transforms:
            return self.score_transforms(node_urn, properties, candidate_transforms)

        try:
            import httpx

            client_kwargs = {
                "base_url": settings.llm_base_url.rstrip("/"),
                "timeout": 8.0,
            }
            headers = {"Content-Type": "application/json"}
            if settings.llm_api_key:
                headers["Authorization"] = f"Bearer {settings.llm_api_key}"

            prompt = (
                f"Given target entity URN '{node_urn}' with properties {json.dumps(properties)}, "
                f"rank the following available OSINT transforms in order of highest tactical intelligence yield: "
                f"{[t.name for t in candidate_transforms]}. "
                f"Respond only with a JSON array of transform names."
            )

            async with httpx.AsyncClient(**client_kwargs) as client:
                res = await client.post(
                    "/chat/completions",
                    headers=headers,
                    json={
                        "model": settings.llm_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.2,
                    },
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    # Extract list from json
                    raw_names = json.loads(content[content.find("[") : content.rfind("]") + 1])
                    t_map = {t.name: t for t in candidate_transforms}
                    ranked: List[Tuple[BaseTransform, int]] = []
                    score = 20
                    for name in raw_names:
                        if name in t_map:
                            ranked.append((t_map[name], score))
                            score -= 2
                    # Append any remaining unranked transforms
                    for t in candidate_transforms:
                        if t not in [r[0] for r in ranked]:
                            ranked.append((t, 5))
                    return ranked[: self.top_k] if self.top_k > 0 else ranked
        except Exception as e:
            logger.debug(f"LLM ranking failed ({e}), falling back to deterministic heuristics")

        return self.score_transforms(node_urn, properties, candidate_transforms)
