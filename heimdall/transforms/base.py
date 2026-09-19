"""
Base Abstract Transform Definition for Heimdall OSINT Pipeline.
"""

from __future__ import annotations

import abc
import time
import traceback
from typing import Any, Dict, List, Set
from heimdall.core.models import GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport


class BaseTransform(abc.ABC):
    """
    Abstract Base Class for modular OSINT transforms.
    Ensures safe execution isolation, typing contracts, and performance tracking.
    """

    name: str = "base_transform"
    display_name: str = "Base Transform"
    description: str = "Abstract base transform."
    input_types: Set[str] = set()
    output_types: Set[str] = set()
    requires_api_key: bool = False

    def can_process(self, entity_type: str) -> bool:
        """Determines whether this transform accepts the given entity type."""
        return entity_type in self.input_types

    async def run_safe(
        self,
        node_urn: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> TransformResult:
        """
        Executes the transform with latency tracking and exception isolation.
        Guarantees that a failing transform never crashes the pipeline.
        """
        parts = node_urn.split(":", 1)
        if len(parts) != 2:
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="FAILED",
                error_message=f"Invalid entity URN format: '{node_urn}'",
            )

        entity_type, value = parts[0], parts[1]
        if not self.can_process(entity_type):
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="FAILED",
                error_message=f"Transform '{self.name}' does not support input type '{entity_type}'",
            )

        start_time = time.perf_counter()
        try:
            # ── Cache check ──────────────────────────────────────────────
            from heimdall.core.cache import cache_get, cache_set
            cached = cache_get(self.name, node_urn)
            if cached is not None:
                return cached

            edges = await self.execute(node_urn, value, transport, **kwargs)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            result = TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="SUCCESS",
                edges=edges,
                duration_ms=round(duration_ms, 2),
            )
            cache_set(self.name, node_urn, result)
            return result
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return TransformResult(
                transform_name=self.name,
                input_entity=node_urn,
                status="FAILED",
                duration_ms=round(duration_ms, 2),
                error_message=f"{type(exc).__name__}: {str(exc)}\n{traceback.format_exc(limit=2)}",
            )

    @abc.abstractmethod
    async def execute(
        self,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        """
        Pure transform logic yielding deterministic GraphEdge contracts.
        """
        pass
