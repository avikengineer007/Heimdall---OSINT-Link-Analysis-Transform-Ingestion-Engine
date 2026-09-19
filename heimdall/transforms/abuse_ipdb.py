"""
AbuseIPDB Transform — IP Abuse Confidence Scores & Report Categories.

Zero-key mode: NOT supported — AbuseIPDB v2 requires an API key.
Free tier available at https://www.abuseipdb.com/register (1,000 checks/day).
When ABUSEIPDB_API_KEY is absent, returns SKIPPED status.

Authenticated mode: Queries /check endpoint for abuse confidence score (0–100),
report categories (port scan, spam, brute-force, etc.), country, and usage type.
"""

from __future__ import annotations

import logging
from typing import Any, List

from heimdall.core.config import settings
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.abuse_ipdb")

_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

# AbuseIPDB category codes → human-readable labels
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


@register_transform
class AbuseIPDBTransform(BaseTransform):
    name = "abuseipdb_check"
    display_name = "AbuseIPDB Reputation Check"
    description = (
        "Queries AbuseIPDB v2 for IP abuse confidence score (0–100), "
        "report categories (port scan, spam, SSH brute-force, etc.), "
        "country of origin, and ISP. Requires ABUSEIPDB_API_KEY."
    )
    input_types = {EntityType.IPV4.value}
    output_types = {
        EntityType.ABUSE_REPORT.value,
        EntityType.ORGANIZATION.value,
    }
    requires_api_key = True

    async def run_safe(
        self,
        node_urn: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> TransformResult:
        api_key = kwargs.get("abuseipdb_api_key") or settings.abuseipdb_api_key
        if not api_key:
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="SKIPPED",
                error_message="ABUSEIPDB_API_KEY not set — skipping AbuseIPDB transform",
            )
        return await super().run_safe(node_urn, transport, abuseipdb_api_key=api_key, **kwargs)

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        api_key = kwargs["abuseipdb_api_key"]
        edges: List[GraphEdge] = []
        headers = {"Key": api_key, "Accept": "application/json"}

        params = f"?ipAddress={value}&maxAgeInDays=90&verbose=false"
        data = await transport.get_json(f"{_ABUSE_BASE}/check{params}", headers=headers)
        if not data or "data" not in data:
            return edges

        d = data["data"]
        confidence = d.get("abuseConfidenceScore", 0)
        total_reports = d.get("totalReports", 0)
        categories = d.get("reports", []) if isinstance(d.get("reports"), list) else []

        # Build unique category set from recent reports
        cat_ids: set = set()
        # AbuseIPDB /check returns categories array on the top-level data
        raw_cats = d.get("usageType", "")

        if confidence > 0 or total_reports > 0:
            abuse_urn = f"{EntityType.ABUSE_REPORT.value}:abuseipdb:{value}"
            cat_labels = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in sorted(cat_ids)]

            edges.append(GraphEdge(
                source=node_urn,
                target=abuse_urn,
                target_type=EntityType.ABUSE_REPORT.value,
                rel="HAS_ABUSE_REPORT",
                properties={
                    "confidence_score": confidence,
                    "total_reports": total_reports,
                    "country_code": d.get("countryCode", ""),
                    "usage_type": raw_cats or "Unknown",
                    "isp": d.get("isp", ""),
                    "is_tor": d.get("isTor", False),
                    "is_whitelisted": d.get("isWhitelisted", False),
                    "source": "AbuseIPDB",
                },
            ))

        # Organization from ISP
        isp = d.get("isp") or d.get("domain", "")
        if isp:
            edges.append(GraphEdge(
                source=node_urn,
                target=f"{EntityType.ORGANIZATION.value}:{isp}",
                target_type=EntityType.ORGANIZATION.value,
                rel="HOSTED_BY_ISP",
                properties={
                    "isp": isp,
                    "country_code": d.get("countryCode", ""),
                    "domain": d.get("domain", ""),
                },
            ))

        return edges
