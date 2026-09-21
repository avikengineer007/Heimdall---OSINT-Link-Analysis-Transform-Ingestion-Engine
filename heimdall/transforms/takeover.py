"""
Subdomain Takeover & Dangling DNS Intelligence Transform.

Inspects DNS CNAME delegations and fingerprint matches against known vulnerable
cloud and SaaS providers (AWS S3, GitHub Pages, Heroku, Shopify, Zendesk, Azure, Fastly).
Flags actionable takeover vulnerabilities with high threat score assignments.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.transforms.takeover")

# Fingerprints for Subdomain Takeovers
# Format: (service_name, cname_pattern, body_fingerprint, severity_score)
TAKEOVER_FINGERPRINTS: List[Tuple[str, str, str, float]] = [
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here", 95.0),
    ("AWS S3", "s3.amazonaws.com", "NoSuchBucket", 95.0),
    ("AWS S3 Website", "s3-website", "The specified bucket does not exist", 95.0),
    ("Heroku", "herokudns.com", "No such app", 90.0),
    ("Heroku App", "herokuapp.com", "herokucdn.com/error-pages/no-such-app.html", 90.0),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable", 85.0),
    ("Zendesk", "zendesk.com", "Help Center Closed", 85.0),
    ("Bitbucket", "bitbucket.io", "Repository not found", 90.0),
    ("Fastly", "fastly.net", "Fastly error: unknown domain", 85.0),
    ("Ghost", "ghost.io", "The thing you were looking for is no longer here", 85.0),
    ("WordPress", "wordpress.com", "Do you want to register", 80.0),
    ("Azure WebApp", "azurewebsites.net", "404 Web Site not found", 95.0),
    ("Azure CloudApp", "cloudapp.net", "404 Web Site not found", 95.0),
    ("Webflow", "webflow.io", "The page you are looking for doesn't exist", 80.0),
    ("Readme.io", "readme.io", "Project doesnt exist", 85.0),
    ("Surge.sh", "surge.sh", "project not found", 85.0),
    ("Fly.io", "fly.dev", "404 Not Found", 80.0),
    ("Cargo Collective", "cargocollective.com", "404 Not Found", 80.0),
]


class SubdomainTakeoverTransform(BaseTransform):
    """
    Scans domains and subdomains for dangling DNS CNAME records vulnerable to takeover.
    """

    name = "subdomain_takeover"
    display_name = "Subdomain Takeover & Dangling DNS"
    description = "Checks CNAME delegations for dangling pointers to unclaimed cloud services (AWS S3, GitHub Pages, Heroku, Azure)."
    input_types: Set[str] = {EntityType.DOMAIN.value, EntityType.SUBDOMAIN.value}
    output_types: Set[str] = {EntityType.TAKEOVER_VULNERABILITY.value, EntityType.DOMAIN.value}
    requires_api_key = False

    def check_cname_signatures(self, cname: str) -> Optional[Dict[str, Any]]:
        """Checks if a CNAME destination matches a known vulnerable service."""
        cname_lower = cname.lower()
        for service, pattern, fingerprint, severity in TAKEOVER_FINGERPRINTS:
            if pattern in cname_lower:
                return {
                    "service": service,
                    "pattern": pattern,
                    "fingerprint": fingerprint,
                    "severity": severity,
                }
        return None

    def check_body_signatures(self, body: str) -> Optional[Dict[str, Any]]:
        """Checks if an HTTP response body matches a vulnerable takeover signature."""
        body_lower = body.lower()
        for service, pattern, fingerprint, severity in TAKEOVER_FINGERPRINTS:
            if fingerprint.lower() in body_lower:
                return {
                    "service": service,
                    "pattern": pattern,
                    "fingerprint": fingerprint,
                    "severity": severity,
                }
        return None

    _DOH_URLS = [

        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    async def _query_cname(self, domain: str, transport: ResilientAsyncTransport) -> List[str]:
        headers = {"accept": "application/dns-json"}
        for url in self._DOH_URLS:
            params = {"name": domain, "type": "CNAME"}
            resp = await transport.get(url, params=params, headers=headers)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    cnames = []
                    for ans in data.get("Answer", []):
                        if ans.get("type") == 5:  # CNAME
                            target = str(ans.get("data", "")).strip().rstrip(".")
                            if target:
                                cnames.append(target)
                    return cnames
                except Exception:
                    continue
        return []

    async def _check_service_fingerprint(
        self, domain: str, body_fingerprint: str, transport: ResilientAsyncTransport
    ) -> bool:
        """Sends non-destructive HTTP request to detect service-specific error page."""
        try:
            resp = await transport.get(f"http://{domain}", timeout=3.0)
            if resp and body_fingerprint.lower() in resp.text.lower():
                return True
        except Exception:
            pass

        try:
            resp = await transport.get(f"https://{domain}", timeout=3.0)
            if resp and body_fingerprint.lower() in resp.text.lower():
                return True
        except Exception:
            pass

        return False

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
        cnames = await self._query_cname(domain, transport)

        for cname in cnames:
            # Emit CNAME target link
            edges.append(
                GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.DOMAIN.value}:{cname}",
                    target_type=EntityType.DOMAIN.value,
                    rel="DELEGATES_CNAME",
                    properties={"cname_target": cname},
                )
            )

            # Match against vulnerable cloud service signatures
            for service, pattern, fingerprint, severity in TAKEOVER_FINGERPRINTS:
                if pattern in cname.lower():
                    is_confirmed = await self._check_service_fingerprint(domain, fingerprint, transport)
                    confidence = "CONFIRMED" if is_confirmed else "POTENTIAL"
                    threat_val = severity if is_confirmed else (severity - 15.0)

                    target_urn = f"{EntityType.TAKEOVER_VULNERABILITY.value}:{service}:{domain}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=target_urn,
                            target_type=EntityType.TAKEOVER_VULNERABILITY.value,
                            rel="VULNERABLE_TO_TAKEOVER",
                            properties={
                                "service": service,
                                "dangling_cname": cname,
                                "status": confidence,
                                "fingerprint": fingerprint,
                                "threat_score": threat_val,
                                "remediation": f"Claim {cname} on {service} or delete dangling DNS CNAME record.",
                            },
                        )
                    )

        return edges


TransformRegistry.register(SubdomainTakeoverTransform())
