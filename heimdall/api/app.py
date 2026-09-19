"""
Production FastAPI Application for Heimdall OSINT Engine.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from heimdall import __version__
from heimdall.core.config import settings
from heimdall.core.models import GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.graph.exporters import GraphExporter
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.pipeline.orchestrator import PipelineOrchestrator
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.api")
scheduler_daemon = None


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    global scheduler_daemon
    # 1. Discover plugins from transforms/plugins
    try:
        from heimdall.core.plugin_loader import PluginLoader
        PluginLoader().discover()
    except Exception as exc:
        logger.warning(f"Plugin discovery on startup: {exc}")

    # 2. Start monitoring scheduler if enabled
    if settings.monitor_enabled and settings.heimdall_persist:
        try:
            from heimdall.pipeline.scheduler import SchedulerDaemon
            scheduler_daemon = SchedulerDaemon()
            await scheduler_daemon.start()
        except Exception as exc:
            logger.warning(f"Failed to start scheduler daemon: {exc}")
    yield
    if scheduler_daemon:
        await scheduler_daemon.stop()


# ─── FastAPI App Setup ────────────────────────────────────────────────────────
app = FastAPI(
    title="Heimdall OSINT Link-Analysis API",
    description="Next-generation asynchronous graph link-analysis engine.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static directory path for Heimdall UI
_ui_dir = Path(__file__).parent.parent / "ui"
if _ui_dir.exists() and settings.ui_enabled:
    app.mount("/static", StaticFiles(directory=str(_ui_dir)), name="static")

# ─── Auth Dependency ──────────────────────────────────────────────────────────
_http_bearer = HTTPBearer(auto_error=False)


async def verify_auth(
    credentials: HTTPAuthorizationCredentials = Security(_http_bearer),
) -> bool:
    """
    Optional Bearer token gate.

    If ``HEIMDALL_AUTH_TOKEN`` is not set, authentication is disabled and all
    requests are allowed. When set, every protected endpoint must include:
        Authorization: Bearer <token>
    """
    expected = settings.heimdall_auth_token
    if not expected:
        return True  # Auth disabled
    if not credentials or credentials.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


# ─── In-Memory Session Registry ───────────────────────────────────────────────
# When HEIMDALL_PERSIST=true, sessions are backed by SqliteGraphStore instead.
investigation_stores: Dict[str, Any] = {}  # session_id → GraphStore
investigation_events: Dict[str, asyncio.Queue] = {}  # session_id → event queue
investigation_meta: Dict[str, Dict[str, Any]] = {}  # session_id → metadata


def _make_store():
    """Returns the appropriate graph store implementation based on settings."""
    if settings.heimdall_persist:
        try:
            from heimdall.graph.sqlite_store import SqliteGraphStore
            return SqliteGraphStore(settings.sqlite_db_path)
        except ImportError:
            pass
    return MemoryGraphStore()


# ─── Request/Response Schemas ─────────────────────────────────────────────────
class SingleTransformRequest(BaseModel):
    transform_name: str
    entity_urn: str
    kwargs: Dict[str, Any] = Field(default_factory=dict)


class InvestigationRequest(BaseModel):
    seed: str
    max_depth: int = Field(default=2, ge=1, le=5)
    allowed_transforms: Optional[List[str]] = None
    smart_pivot: Optional[bool] = None
    max_transforms_per_node: Optional[int] = None
    kwargs: Dict[str, Any] = Field(default_factory=dict)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
@app.get("/ui/index.html", include_in_schema=False)
async def serve_ui():
    """Serves the Heimdall visual link-analysis workbench."""
    index_file = _ui_dir / "index.html"
    if index_file.exists() and settings.ui_enabled:
        return FileResponse(str(index_file), media_type="text/html")
    return RedirectResponse(url="/docs")


@app.get("/api/v1/health")
async def health_check():
    """Public health probe — no authentication required."""
    from heimdall.core.cache import cache_stats
    return {
        "status": "healthy",
        "engine": "Heimdall",
        "version": __version__,
        "registered_transforms": len(TransformRegistry.list_transforms()),
        "active_sessions": len(investigation_stores),
        "cache": cache_stats(),
        "auth_enabled": bool(settings.heimdall_auth_token),
        "persist_enabled": settings.heimdall_persist,
    }


@app.get("/api/v1/transforms", dependencies=[Depends(verify_auth)])
async def list_transforms():
    """Lists all registered OSINT transforms with input and output schemas."""
    return {"transforms": TransformRegistry.list_transforms()}


@app.post("/api/v1/transforms/run", response_model=TransformResult, dependencies=[Depends(verify_auth)])
async def run_single_transform(req: SingleTransformRequest):
    """Executes a single transform against an entity URN (with cache support)."""
    transform = TransformRegistry.get(req.transform_name)
    if not transform:
        raise HTTPException(status_code=404, detail=f"Transform '{req.transform_name}' not found")

    async with ResilientAsyncTransport() as transport:
        result = await transform.run_safe(req.entity_urn, transport, **req.kwargs)
        return result


@app.get("/api/v1/investigations", dependencies=[Depends(verify_auth)])
async def list_investigations():
    """Lists all active and completed investigation sessions."""
    return {
        "sessions": [
            {
                "session_id": sid,
                **meta,
            }
            for sid, meta in investigation_meta.items()
        ]
    }


@app.post("/api/v1/investigations/start", dependencies=[Depends(verify_auth)])
async def start_investigation(req: InvestigationRequest):
    """Initiates an asynchronous multi-hop investigation."""
    seed_urn = PipelineOrchestrator.infer_and_normalize_seed(req.seed)
    if not seed_urn:
        raise HTTPException(status_code=400, detail=f"Invalid seed indicator: '{req.seed}'")

    session_id = str(uuid.uuid4())
    store = _make_store()
    queue: asyncio.Queue = asyncio.Queue()

    investigation_stores[session_id] = store
    investigation_events[session_id] = queue
    investigation_meta[session_id] = {
        "seed": seed_urn,
        "max_depth": req.max_depth,
        "status": "running",
    }

    async def event_handler(event: Dict[str, Any]):
        await queue.put(event)

    orchestrator = PipelineOrchestrator(
        graph_store=store,
        event_callback=event_handler,
        use_smart_agent=req.smart_pivot,
    )

    async def run_pipeline():
        try:
            await orchestrator.run_investigation(
                seed=req.seed,
                max_depth=req.max_depth,
                allowed_transforms=req.allowed_transforms,
                session_id=session_id,
                **req.kwargs,
            )
            investigation_meta[session_id]["status"] = "completed"
        except Exception as exc:
            await queue.put({"type": "ERROR", "data": {"error": str(exc)}})
            investigation_meta[session_id]["status"] = "error"
        finally:
            await queue.put({"type": "STREAM_END", "data": {}})

    asyncio.create_task(run_pipeline())

    return {
        "message": "Investigation started",
        "session_id": session_id,
        "seed": seed_urn,
        "max_depth": req.max_depth,
        "stream_url": f"/api/v1/investigations/{session_id}/events",
        "graph_url": f"/api/v1/investigations/{session_id}/graph",
    }


@app.get("/api/v1/investigations/{session_id}/events", dependencies=[Depends(verify_auth)])
async def stream_investigation_events(session_id: str):
    """Streams real-time OSINT events via Server-Sent Events (SSE)."""
    queue = investigation_events.get(session_id)
    if not queue:
        raise HTTPException(status_code=404, detail="Investigation event stream not found")

    async def event_generator():
        while True:
            event = await queue.get()
            event_type = event.get("type", "message")
            data_str = json.dumps(event.get("data", {}))
            # Emit as named SSE event + fallback message
            yield f"event: {event_type}\ndata: {data_str}\n\n"
            if event_type in ("STREAM_END", "INVESTIGATION_COMPLETED", "ERROR"):
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@app.get("/api/v1/investigations/{session_id}/graph", dependencies=[Depends(verify_auth)])
async def get_investigation_graph(session_id: str):
    """Returns the full investigation graph as JSON."""
    store = investigation_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Investigation session not found")
    return json.loads(GraphExporter.to_json(store))


@app.get("/api/v1/investigations/{session_id}/export/{export_format}", dependencies=[Depends(verify_auth)])
async def export_graph(session_id: str, export_format: str):
    """Exports graph as json, graphml, or mtgx (Maltego) formats."""
    store = investigation_stores.get(session_id)
    if not store:
        raise HTTPException(status_code=404, detail="Investigation session not found")

    fmt = export_format.lower()
    if fmt == "json":
        content = GraphExporter.to_json(store)
        return Response(content=content, media_type="application/json")
    elif fmt == "graphml":
        content = GraphExporter.to_graphml(store)
        return Response(content=content, media_type="application/xml")
    elif fmt in ("mtgx", "maltego"):
        zip_bytes = GraphExporter.to_maltego_mtgx(store)
        return Response(
            content=zip_bytes,
            media_type="application/vnd.maltego.mtgx",
            headers={"Content-Disposition": f'attachment; filename="heimdall_{session_id[:8]}.mtgx"'},
        )
    else:
        raise HTTPException(status_code=400, detail="Supported formats: json, graphml, mtgx")


@app.delete("/api/v1/investigations/{session_id}", dependencies=[Depends(verify_auth)])
async def delete_investigation(session_id: str):
    """Removes an investigation session and frees its memory."""
    if session_id not in investigation_stores:
        raise HTTPException(status_code=404, detail="Investigation session not found")
    investigation_stores.pop(session_id, None)
    investigation_events.pop(session_id, None)
    investigation_meta.pop(session_id, None)
    return {"message": f"Session {session_id} deleted"}


# ─── Phase 5: Plugin SDK Endpoints ───────────────────────────────────────────

@app.get("/api/v1/plugins", dependencies=[Depends(verify_auth)])
async def list_plugins():
    """Lists loaded community plugins discovered from transforms/plugins/."""
    from heimdall.core.plugin_loader import PluginLoader
    loader = PluginLoader()
    report = loader.discover()
    return {
        "loaded_plugins": report.loaded,
        "failed_plugins": report.failed,
        "plugin_directory": str(loader.plugin_dir),
    }


@app.post("/api/v1/plugins/reload", dependencies=[Depends(verify_auth)])
async def reload_plugins():
    """Hot-reloads community plugins from transforms/plugins/."""
    from heimdall.core.plugin_loader import PluginLoader
    loader = PluginLoader()
    report = loader.reload()
    return {
        "status": "reloaded",
        "loaded_plugins": report.loaded,
        "failed_plugins": report.failed,
    }


# ─── Phase 5: Graph Temporal Diffing Endpoints ────────────────────────────────

@app.get("/api/v1/diff/{session_a}/{session_b}", dependencies=[Depends(verify_auth)])
async def get_graph_diff(session_a: str, session_b: str):
    """Computes structural and attribute differences between two investigation sessions."""
    from heimdall.graph.diff_engine import diff_sessions
    store_a = investigation_stores.get(session_a)
    store_b = investigation_stores.get(session_b)

    try:
        delta = await diff_sessions(
            session_a=session_a,
            session_b=session_b,
            store_a=store_a,
            store_b=store_b,
        )
        return delta.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to compute graph diff: {exc}")


# ─── Phase 5: Monitoring & Scheduler Endpoints ────────────────────────────────

class CreateScheduleRequest(BaseModel):
    seed_urn: str
    cron_expr: str = "0 9 * * 1"
    max_depth: int = 2
    alert_on_new_nodes: bool = True
    alert_on_threat_increase: bool = True


@app.post("/api/v1/monitor", dependencies=[Depends(verify_auth)])
async def create_monitoring_schedule(req: CreateScheduleRequest):
    """Creates a new automated continuous monitoring schedule."""
    from heimdall.pipeline.scheduler import MonitoringSchedule, ScheduleStore
    store = ScheduleStore()
    sched = MonitoringSchedule(
        seed_urn=req.seed_urn,
        cron_expr=req.cron_expr,
        max_depth=req.max_depth,
        alert_on_new_nodes=req.alert_on_new_nodes,
        alert_on_threat_increase=req.alert_on_threat_increase,
    )
    store.save(sched)
    return {"message": "Monitoring schedule created", "schedule": sched.model_dump()}


@app.get("/api/v1/monitor", dependencies=[Depends(verify_auth)])
async def list_monitoring_schedules():
    """Lists all configured attack surface monitoring schedules."""
    from heimdall.pipeline.scheduler import ScheduleStore
    store = ScheduleStore()
    schedules = store.list_all()
    return {"schedules": [s.model_dump() for s in schedules]}


@app.delete("/api/v1/monitor/{schedule_id}", dependencies=[Depends(verify_auth)])
async def delete_monitoring_schedule(schedule_id: str):
    """Deletes an attack surface monitoring schedule."""
    from heimdall.pipeline.scheduler import ScheduleStore
    store = ScheduleStore()
    deleted = store.delete(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Schedule '{schedule_id}' not found")
    return {"message": f"Schedule {schedule_id} deleted"}


# ─── Phase 5: Smart Pivot Agent Endpoints ─────────────────────────────────────

@app.get("/api/v1/agents/rules", dependencies=[Depends(verify_auth)])
async def get_pivot_rules():
    """Returns active priority rules used by the Smart Pivot Agent."""
    from heimdall.pipeline.smart_agent import PivotAgent
    agent = PivotAgent()
    return {"rules": agent.get_active_rules(), "top_k": agent.top_k}
