"""
Cloud Storage Bucket Discovery Transform (AWS S3, Azure Blob, Google Cloud Storage).

Generates company and domain name permutations to hunt for exposed, open, or
associated cloud object storage buckets.
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

logger = logging.getLogger("heimdall.transforms.cloud_buckets")

BUCKET_SUFFIXES = [
    "",
    "-assets",
    "-public",
    "-backup",
    "-backups",
    "-static",
    "-media",
    "-files",
    "-data",
    "-dev",
    "-prod",
    "-staging",
]


class CloudBucketDiscoveryTransform(BaseTransform):
    """
    Hunts for exposed AWS S3, Google Cloud Storage, and Azure Blob storage buckets
    associated with the target organization or domain.
    """

    name = "cloud_bucket_discovery"
    display_name = "Cloud Storage Bucket Discovery"
    description = "Searches for exposed or claimed AWS S3, Google Cloud, and Azure Blob buckets."
    input_types: Set[str] = {EntityType.DOMAIN.value, EntityType.ORGANIZATION.value}
    output_types: Set[str] = {EntityType.CLOUD_BUCKET.value}
    requires_api_key = False

    @staticmethod
    def _extract_base_names(raw_value: str) -> List[str]:
        """Extracts clean alphanumeric seed names for bucket permutations."""
        clean = raw_value.strip().lower()
        if "." in clean:
            # E.g. example.com -> ['example', 'example-com']
            root = clean.split(".")[0]
            dashed = clean.replace(".", "-")
            return list({root, dashed})
        words = clean.replace(" ", "-").replace("_", "-")
        return [words]

    async def _probe_s3(self, name: str, transport: ResilientAsyncTransport) -> Optional[Dict[str, Any]]:
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = await transport.get(url, timeout=3.0)
            if resp is None:
                return None
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {"provider": "AWS S3", "status": "OPEN_PUBLIC", "is_public": True, "threat_score": 95.0, "url": url}
            elif resp.status_code == 403:
                return {"provider": "AWS S3", "status": "SECURED_EXISTS", "is_public": False, "threat_score": 35.0, "url": url}
        except Exception:
            pass
        return None

    async def _probe_gcs(self, name: str, transport: ResilientAsyncTransport) -> Optional[Dict[str, Any]]:
        url = f"https://storage.googleapis.com/{name}"
        try:
            resp = await transport.get(url, timeout=3.0)
            if resp is None:
                return None
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {"provider": "Google Cloud Storage", "status": "OPEN_PUBLIC", "is_public": True, "threat_score": 95.0, "url": url}
            elif resp.status_code == 403:
                return {"provider": "Google Cloud Storage", "status": "SECURED_EXISTS", "is_public": False, "threat_score": 35.0, "url": url}
        except Exception:
            pass
        return None

    async def _probe_azure(self, name: str, transport: ResilientAsyncTransport) -> Optional[Dict[str, Any]]:
        url = f"https://{name}.blob.core.windows.net"
        try:
            resp = await transport.get(url, timeout=3.0)
            if resp is None:
                return None
            if resp.status_code in (200, 400) and "InvalidQueryParameterValue" in resp.text:
                return {"provider": "Azure Blob", "status": "SECURED_EXISTS", "is_public": False, "threat_score": 35.0, "url": url}
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
        base_names = self._extract_base_names(value)
        edges: List[GraphEdge] = []
        candidates = []

        for base in base_names:
            for suffix in BUCKET_SUFFIXES:
                candidate = f"{base}{suffix}".replace("--", "-").strip("-")
                if len(candidate) >= 3:
                    candidates.append(candidate)

        # Probe candidate permutations asynchronously with bounded concurrency
        async def _check_bucket(candidate_name: str):
            results = await asyncio.gather(
                self._probe_s3(candidate_name, transport),
                self._probe_gcs(candidate_name, transport),
                self._probe_azure(candidate_name, transport),
                return_exceptions=True,
            )
            found = []
            for r in results:
                if isinstance(r, dict):
                    found.append((candidate_name, r))
            return found

        tasks = [_check_bucket(c) for c in set(candidates)]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in all_results:
            if isinstance(batch, list):
                for b_name, meta in batch:
                    target_urn = f"{EntityType.CLOUD_BUCKET.value}:{meta['provider']}:{b_name}"
                    edges.append(
                        GraphEdge(
                            source=node_urn,
                            target=target_urn,
                            target_type=EntityType.CLOUD_BUCKET.value,
                            rel="ASSOCIATED_STORAGE_BUCKET",
                            properties={
                                "bucket_name": b_name,
                                "provider": meta["provider"],
                                "status": meta["status"],
                                "is_public": meta["is_public"],
                                "threat_score": meta["threat_score"],
                                "url": meta["url"],
                            },
                        )
                    )

        return edges

    def generate_bucket_names(self, raw_value: str) -> List[str]:
        """Generates candidate bucket names for testing and permutations."""

        base_names = self._extract_base_names(raw_value)
        candidates = []
        for base in base_names:
            for suffix in BUCKET_SUFFIXES:
                candidate = f"{base}{suffix}".replace("--", "-").strip("-")
                if len(candidate) >= 3:
                    candidates.append(candidate)
        return candidates


CloudBucketHunterTransform = CloudBucketDiscoveryTransform

TransformRegistry.register(CloudBucketDiscoveryTransform())
hunter_inst = CloudBucketHunterTransform()
hunter_inst.name = "cloud_bucket_hunter"
TransformRegistry.register(hunter_inst)

