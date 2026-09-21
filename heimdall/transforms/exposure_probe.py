"""
Lightweight Vulnerability & Sensitive File Exposure Probe.

Conducts non-intrusive, passive HTTP probes to identify publicly accessible
sensitive files (.env, .git/HEAD, docker-compose.yml, Swagger UI, phpinfo).
Assigns high threat scores to critical security oversights.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.transforms.exposure_probe")

# Signatures for high-risk sensitive file exposures
EXPOSURE_PROBES: List[Tuple[str, str, float, str]] = [
    ("/.env", "DB_PASSWORD", 95.0, "Exposed environment configuration containing database/API credentials"),
    ("/.git/HEAD", "ref: refs/heads/", 95.0, "Exposed Git repository source code directory"),
    ("/docker-compose.yml", "version:", 85.0, "Exposed Docker container deployment blueprint"),
    ("/openapi.json", "openapi", 75.0, "Exposed interactive OpenAPI specification schema"),
    ("/swagger.json", "swagger", 75.0, "Exposed Swagger REST API definition"),
    ("/phpinfo.php", "PHP Version", 80.0, "Exposed PHP runtime configuration and server environment"),
    ("/server-status", "Apache Server Status", 75.0, "Exposed Apache server status and active connections"),
    ("/actuator/env", "activeProfiles", 90.0, "Exposed Spring Boot Actuator environment dump"),
    ("/metrics", "process_cpu", 65.0, "Exposed Prometheus application metrics"),
    ("/wp-config.php.bak", "DB_NAME", 95.0, "WordPress backup configuration database credentials"),
    ("/config.json", "database", 80.0, "Web application configuration file"),
]


class ExposureProbeTransform(BaseTransform):
    """
    Non-destructive security exposure scanner testing for common configuration leaks.
    """

    name = "exposure_probe"
    display_name = "Vulnerability & Sensitive Exposure Probe"
    description = "Conducts non-intrusive HTTP checks for exposed credentials, .git repositories, and configuration dumps."
    input_types: Set[str] = {EntityType.DOMAIN.value, EntityType.SUBDOMAIN.value, EntityType.IPV4.value}
    output_types: Set[str] = {EntityType.EXPOSURE_LEAK.value}
    requires_api_key = False

    PROBE_PATHS: List[Dict[str, Any]] = [
        {"path": path, "match": match, "severity": sev, "desc": desc}
        for path, match, sev, desc in EXPOSURE_PROBES
    ]


    async def _probe_path(
        self, target: str, path: str, match_text: str, severity: float, desc: str, transport: ResilientAsyncTransport
    ) -> Optional[Dict[str, Any]]:
        for proto in ("https", "http"):
            url = f"{proto}://{target}{path}"
            try:
                resp = await transport.get(url, timeout=3.0)
                if resp and resp.status_code == 200 and match_text in resp.text:
                    return {
                        "path": path,
                        "url": url,
                        "status_code": 200,
                        "threat_score": severity,
                        "description": desc,
                    }
            except Exception:
                pass
        return None

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        target = DataSanitizer.domain(value) or DataSanitizer.ipv4(value)
        if not target:
            return []

        edges: List[GraphEdge] = []
        tasks = [
            self._probe_path(target, path, match, sev, desc, transport)
            for path, match, sev, desc in EXPOSURE_PROBES
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                leak_urn = f"{EntityType.EXPOSURE_LEAK.value}:{r['path']}:{target}"
                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=leak_urn,
                        target_type=EntityType.EXPOSURE_LEAK.value,
                        rel="EXPOSES_SENSITIVE_RESOURCE",
                        properties={
                            "url": r["url"],
                            "path": r["path"],
                            "status_code": r["status_code"],
                            "threat_score": r["threat_score"],
                            "remediation": f"Block public access to {r['path']} immediately at WAF or web server configuration level.",
                            "description": r["description"],
                        },
                    )
                )

        return edges


TransformRegistry.register(ExposureProbeTransform())
