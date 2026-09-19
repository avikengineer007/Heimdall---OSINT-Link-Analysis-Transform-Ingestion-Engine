"""
Service Banner Grabber Transform (Active Recon).

Probes target IP/Domain on standard operational ports (SSH, HTTP, SMTP, FTP)
and extracts service identification banners.
Gated behind ACTIVE_RECON=true.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List

from heimdall.core.config import settings
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.banner_grab")


@register_transform
class BannerGrabTransform(BaseTransform):
    name = "banner_grab"
    display_name = "TCP Banner Grabbing"
    description = "Probes open ports and grabs service identification banners."
    input_types = {EntityType.IPV4.value, EntityType.DOMAIN.value}
    output_types = {EntityType.SERVICE_BANNER.value, EntityType.PORT_SERVICE.value}

    async def run_safe(
        self,
        node_urn: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> TransformResult:
        if not settings.active_recon:
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="SKIPPED",
                error_message="Active recon is disabled. Set ACTIVE_RECON=true to enable direct port probing.",
            )
        return await super().run_safe(node_urn, transport, **kwargs)

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        target_ports = kwargs.get("ports", settings.active_recon_ports[:5])
        edges: List[GraphEdge] = []

        async def _probe_port(port: int) -> None:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(value, port),
                    timeout=2.0,
                )

                if port in (80, 8080, 8000):
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {value}\r\n\r\n".encode("utf-8"))
                    await writer.drain()

                banner_data = await asyncio.wait_for(reader.read(512), timeout=1.5)
                writer.close()
                await writer.wait_closed()

                raw_text = banner_data.decode("utf-8", errors="ignore").strip()
                first_line = raw_text.splitlines()[0] if raw_text else "Open (No Banner)"

                port_urn = f"{EntityType.PORT_SERVICE.value}:{value}:{port}"
                banner_urn = f"{EntityType.SERVICE_BANNER.value}:{value}:{port}"

                edges.append(
                    GraphEdge(
                        source=node_urn,
                        target=port_urn,
                        target_type=EntityType.PORT_SERVICE.value,
                        rel="EXPOSES_PORT",
                        properties={"port": port, "protocol": "tcp"},
                    )
                )

                edges.append(
                    GraphEdge(
                        source=port_urn,
                        target=banner_urn,
                        target_type=EntityType.SERVICE_BANNER.value,
                        rel="BANNER_IDENTIFIED",
                        properties={
                            "banner": first_line[:200],
                            "full_length": len(raw_text),
                            "port": port,
                        },
                    )
                )
            except Exception:
                pass

        for p in target_ports:
            await _probe_port(p)
            await asyncio.sleep(1.0 / max(settings.active_recon_rate_limit, 0.1))

        return edges
