"""
Web Surface, Security.txt, and Email Harvesting Transforms.
"""

from __future__ import annotations

import logging
import re
from typing import Any, List, Set
from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.web")


@register_transform
class WebSurfaceTransform(BaseTransform):
    """Probes web endpoints for tech signatures, security.txt, and contact emails."""

    name = "web_surface"
    display_name = "Web Surface & Contact Discovery"
    description = "Probes HTTP/HTTPS headers, security.txt, and public markup to extract emails and technologies."
    input_types: Set[str] = {EntityType.DOMAIN.value, EntityType.SUBDOMAIN.value}
    output_types: Set[str] = {
        EntityType.EMAIL.value,
        EntityType.PORT_SERVICE.value,
    }

    _EMAIL_REGEX = re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.IGNORECASE
    )

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
        schemes = ["https", "http"]
        found_emails: Set[str] = set()

        for scheme in schemes:
            url = f"{scheme}://{domain}"
            resp = await transport.get(url, timeout=4.0)
            if not resp:
                continue

            port = 443 if scheme == "https" else 80
            server_header = resp.headers.get("server", "")
            x_powered_by = resp.headers.get("x-powered-by", "")

            # Expose web service
            edges.append(
                GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.PORT_SERVICE.value}:{domain}:{port}",
                    target_type=EntityType.PORT_SERVICE.value,
                    rel="EXPOSES_SERVICE",
                    properties={
                        "protocol": scheme,
                        "server": server_header,
                        "powered_by": x_powered_by,
                        "status_code": resp.status_code,
                    },
                )
            )

            # Extract emails from body
            body_text = resp.text[:100000]  # limit to first 100kb
            matches = self._EMAIL_REGEX.findall(body_text)
            for m in matches:
                clean_email = DataSanitizer.email(m)
                # Filter out image/asset false positives like user@2x.png
                if clean_email and not clean_email.endswith((".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp")):
                    found_emails.add(clean_email)

            # Check security.txt
            sec_url = f"{scheme}://{domain}/.well-known/security.txt"
            sec_resp = await transport.get(sec_url, timeout=3.0)
            if sec_resp and sec_resp.status_code == 200:
                sec_matches = self._EMAIL_REGEX.findall(sec_resp.text)
                for sm in sec_matches:
                    clean_sm = DataSanitizer.email(sm)
                    if clean_sm:
                        found_emails.add(clean_sm)

            # If we connected on HTTPS, don't bother probing HTTP
            if resp.status_code < 400:
                break

        for email in list(found_emails)[:10]:  # Limit top 10 unique emails
            edges.append(
                GraphEdge(
                    source=node_urn,
                    target=f"{EntityType.EMAIL.value}:{email}",
                    target_type=EntityType.EMAIL.value,
                    rel="EXPOSES_EMAIL",
                    properties={"discovery_source": "web_probe"},
                )
            )

        return edges
