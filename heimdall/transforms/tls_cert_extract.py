"""
TLS Certificate Extractor Transform (Active Recon).

Connects directly via TLS handshake to extract active certificate metadata,
issuer details, validity dates, and Subject Alternative Names (SANs).
Gated behind ACTIVE_RECON=true.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from typing import Any, List

from heimdall.core.config import settings
from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import register_transform

logger = logging.getLogger("heimdall.transforms.tls_cert")


@register_transform
class TLSCertExtractTransform(BaseTransform):
    name = "tls_cert_extract"
    display_name = "TLS Certificate Extraction"
    description = "Extracts live certificate details and SAN hostnames via direct TLS handshake."
    input_types = {EntityType.DOMAIN.value, EntityType.IPV4.value}
    output_types = {EntityType.TLS_CERTIFICATE.value, EntityType.DOMAIN.value}

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
                error_message="Active recon is disabled. Set ACTIVE_RECON=true to enable direct TLS probing.",
            )
        return await super().run_safe(node_urn, transport, **kwargs)

    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        port = int(kwargs.get("port", 443))

        try:
            # Build SSL context without hostname verification to inspect self-signed/untrusted certs too
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            conn_timeout = float(kwargs.get("timeout", 5.0))
            is_ip = value.replace(".", "").isdigit()
            server_name = None if is_ip else value

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(value, port, ssl=ctx, server_hostname=server_name),
                timeout=conn_timeout,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if not ssl_obj:
                writer.close()
                await writer.wait_closed()
                return []

            peercert_bin = ssl_obj.getpeercert(binary_form=True)
            peercert_dict = ssl_obj.getpeercert(binary_form=False) or {}
            cert_sha256 = hashlib.sha256(peercert_bin).hexdigest() if peercert_bin else "unknown"

            writer.close()
            await writer.wait_closed()

            subject_dict = {}
            for rdn in peercert_dict.get("subject", ()):
                for attr in rdn:
                    if isinstance(attr, (list, tuple)) and len(attr) == 2:
                        subject_dict[attr[0]] = attr[1]

            issuer_dict = {}
            for rdn in peercert_dict.get("issuer", ()):
                for attr in rdn:
                    if isinstance(attr, (list, tuple)) and len(attr) == 2:
                        issuer_dict[attr[0]] = attr[1]

            cn = subject_dict.get("commonName", value)

            cert_urn = f"{EntityType.TLS_CERTIFICATE.value}:{cert_sha256[:16]}"
            edges.append(
                GraphEdge(
                    source=node_urn,
                    target=cert_urn,
                    target_type=EntityType.TLS_CERTIFICATE.value,
                    rel="HAS_TLS_CERT",
                    properties={
                        "fingerprint_sha256": cert_sha256,
                        "common_name": cn,
                        "issuer": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown")),
                        "not_after": peercert_dict.get("notAfter", ""),
                        "not_before": peercert_dict.get("notBefore", ""),
                        "serial_number": peercert_dict.get("serialNumber", ""),
                    },
                )
            )

            sans = peercert_dict.get("subjectAltName", ())
            for san_type, san_val in sans:
                if san_type.lower() == "dns" and san_val.lower() != value.lower():
                    san_clean = san_val.lstrip("*.").lower()
                    edges.append(
                        GraphEdge(
                            source=cert_urn,
                            target=f"{EntityType.DOMAIN.value}:{san_clean}",
                            target_type=EntityType.DOMAIN.value,
                            rel="CERT_SAN_DOMAIN",
                            properties={"san_type": san_type, "original": san_val},
                        )
                    )

            await asyncio.sleep(1.0 / max(settings.active_recon_rate_limit, 0.1))
            return edges

        except Exception as exc:
            logger.debug(f"TLS cert extraction failed on {value}:{port} - {exc}")
            return []
