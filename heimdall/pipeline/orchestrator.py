"""
Multi-Hop Recursive Link-Analysis Orchestrator.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Set
from heimdall.core.models import (
    EntityType,
    GraphEdge,
    GraphNode,
    InvestigationSession,
    TransformResult,
)
from heimdall.core.sanitizers import DataSanitizer
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.graph.base import BaseGraphStore
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.pipeline")


class PipelineOrchestrator:
    """
    Coordinates multi-hop OSINT reconnaissance across modular transforms,
    enforcing cycle prevention, deduplication, and streaming event dispatch.
    """

    def __init__(
        self,
        graph_store: Optional[BaseGraphStore] = None,
        transport: Optional[ResilientAsyncTransport] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        use_smart_agent: Optional[bool] = None,
    ):
        self.store = graph_store or MemoryGraphStore()
        self.transport = transport or ResilientAsyncTransport()
        self.event_callback = event_callback
        from heimdall.core.config import settings
        self.use_smart_agent = use_smart_agent if use_smart_agent is not None else settings.smart_pivot
        if self.use_smart_agent:
            from heimdall.pipeline.smart_agent import PivotAgent
            self.smart_agent = PivotAgent()
        else:
            self.smart_agent = None

    @staticmethod
    def infer_and_normalize_seed(seed: str) -> Optional[str]:
        """Automatically infers entity type if not provided with a prefix."""
        cleaned = seed.strip()

        # Handle URL inputs like https://example.com/path
        if cleaned.lower().startswith(("http://", "https://")):
            domain = DataSanitizer.domain(cleaned)
            if domain:
                return f"{EntityType.DOMAIN.value}:{domain}"

        if ":" in cleaned and not cleaned.startswith(("[", "/")):
            parts = cleaned.split(":", 1)
            e_type, e_val = parts[0], parts[1]
            if e_type.lower() in ("domain", "subdomain"):
                norm = DataSanitizer.domain(e_val)
                return f"{EntityType.DOMAIN.value}:{norm}" if norm else None
            elif e_type.lower() in ("ipv4", "ip"):
                norm = DataSanitizer.ipv4(e_val)
                return f"{EntityType.IPV4.value}:{norm}" if norm else None
            elif e_type.lower() == "email":
                norm = DataSanitizer.email(e_val)
                return f"{EntityType.EMAIL.value}:{norm}" if norm else None
            elif e_type in [e.value for e in EntityType]:
                return f"{e_type}:{e_val}"

        # Try IPv4
        ip = DataSanitizer.ipv4(cleaned)
        if ip:
            return f"{EntityType.IPV4.value}:{ip}"

        # Try Email
        email = DataSanitizer.email(cleaned)
        if email:
            return f"{EntityType.EMAIL.value}:{email}"

        # Fallback to Domain
        domain = DataSanitizer.domain(cleaned)
        if domain:
            return f"{EntityType.DOMAIN.value}:{domain}"

        return None

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        payload = {"type": event_type, "data": data}
        if self.event_callback:
            if asyncio.iscoroutinefunction(self.event_callback):
                await self.event_callback(payload)
            else:
                self.event_callback(payload)

    async def run_investigation(
        self,
        seed: str,
        max_depth: int = 2,
        allowed_transforms: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        **transform_kwargs: Any,
    ) -> InvestigationSession:
        """
        Executes a recursive breadth-first graph expansion starting from the seed.
        """
        seed_urn = self.infer_and_normalize_seed(seed)
        if not seed_urn:
            raise ValueError(f"Could not parse valid OSINT seed from: '{seed}'")

        sid = session_id or str(uuid.uuid4())
        session = InvestigationSession(session_id=sid, seed_urn=seed_urn, max_depth=max_depth)

        # Seed node registration
        seed_node = GraphNode.from_urn(seed_urn)
        self.store.add_node(seed_node)
        session.visited_urns.add(seed_urn)

        await self._emit_event("INVESTIGATION_STARTED", {"session_id": sid, "seed": seed_urn})

        current_frontier: Set[str] = {seed_urn}

        for current_depth in range(1, max_depth + 1):
            if not current_frontier:
                logger.info(f"Frontier exhausted at depth {current_depth - 1}")
                break

            if self.smart_agent:
                current_frontier = self.smart_agent.filter_frontier(current_frontier, self.store)
                if not current_frontier:
                    break

            logger.info(f"Processing Depth {current_depth}/{max_depth} with {len(current_frontier)} entities")
            await self._emit_event("DEPTH_STARTED", {"depth": current_depth, "frontier_size": len(current_frontier)})

            next_frontier: Set[str] = set()
            tasks = []

            for urn in current_frontier:
                entity_type = urn.split(":", 1)[0]
                transforms = TransformRegistry.find_for_type(entity_type)

                if allowed_transforms:
                    transforms = [t for t in transforms if t.name in allowed_transforms]

                if self.smart_agent:
                    node = self.store.get_node(urn)
                    props = node.properties if node else {}
                    scored = self.smart_agent.score_transforms(urn, props, transforms)
                    selected_transforms = [t for t, _ in scored]
                else:
                    selected_transforms = transforms

                for transform in selected_transforms:
                    tasks.append((urn, transform))

            if not tasks:
                break

            lock = asyncio.Lock()

            # Execute transform tasks concurrently
            async def _run_task(u: str, t: Any) -> TransformResult:
                try:
                    res = await t.run_safe(u, self.transport, **transform_kwargs)
                    await self._emit_event(
                        "TRANSFORM_COMPLETED",
                        {
                            "transform": t.name,
                            "entity": u,
                            "edges_count": len(res.edges),
                            "status": res.status,
                        },
                    )
                    if res.status == "SUCCESS" and res.edges:
                        self.store.add_edges(res.edges)
                        for edge in res.edges:
                            await self._emit_event("EDGE_DISCOVERED", edge.to_contract_dict())
                            async with lock:
                                if edge.target not in session.visited_urns:
                                    next_frontier.add(edge.target)
                                    session.visited_urns.add(edge.target)
                    return res
                except Exception as exc:
                    logger.error(f"Error running transform {t.name} on {u}: {exc}")
                    return TransformResult(transform_name=t.name, input_entity=u, status="FAILED", error=str(exc))

            results: List[TransformResult] = await asyncio.gather(
                *[_run_task(u, t) for u, t in tasks],
                return_exceptions=False,
            )

            current_frontier = next_frontier

        stats = self.store.get_stats()
        session.total_nodes = stats.get("total_nodes", 0)
        session.total_edges = stats.get("total_edges", 0)

        await self._emit_event("INVESTIGATION_COMPLETED", {"session_id": session_id, "stats": stats})
        return session
