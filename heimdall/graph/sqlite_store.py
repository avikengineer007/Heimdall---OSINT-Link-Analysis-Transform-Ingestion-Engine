"""
SQLite-Backed Graph Store for Investigation Persistence.

Provides durable storage of OSINT graph edges and nodes across API server restarts.
Uses aiosqlite for async I/O and enables Write-Ahead Logging (WAL) mode for
safe concurrent reads during active write sessions.

Schema:
  sessions  — id, seed_urn, status, created_at, config_json
  nodes     — session_id, urn, type, value, properties_json, threat_score
  edges     — session_id, source_urn, target_urn, rel, properties_json, discovered_at

Indices:
  Compound (session_id, urn)              on nodes
  Compound (session_id, source_urn, target_urn) on edges
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import aiosqlite
    _AIOSQLITE_AVAILABLE = True
except ImportError:
    _AIOSQLITE_AVAILABLE = False

from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.base import BaseGraphStore
from heimdall.graph.memory_store import MemoryGraphStore

logger = logging.getLogger("heimdall.graph.sqlite_store")

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    seed_urn    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    created_at  TEXT NOT NULL,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS nodes (
    session_id      TEXT NOT NULL,
    urn             TEXT NOT NULL,
    type            TEXT NOT NULL,
    value           TEXT NOT NULL,
    properties_json TEXT,
    threat_score    REAL,
    PRIMARY KEY (session_id, urn),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    source_urn      TEXT NOT NULL,
    target_urn      TEXT NOT NULL,
    rel             TEXT NOT NULL,
    target_type     TEXT NOT NULL,
    properties_json TEXT,
    discovered_at   TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_session_urn
    ON nodes(session_id, urn);

CREATE INDEX IF NOT EXISTS idx_edges_session_src_tgt
    ON edges(session_id, source_urn, target_urn);

CREATE INDEX IF NOT EXISTS idx_edges_session_id
    ON edges(session_id);

CREATE TABLE IF NOT EXISTS monitoring_schedules (
    id                        TEXT PRIMARY KEY,
    seed_urn                  TEXT NOT NULL,
    cron_expr                 TEXT NOT NULL,
    max_depth                 INTEGER NOT NULL DEFAULT 2,
    alert_on_new_nodes        INTEGER DEFAULT 1,
    alert_on_threat_increase  INTEGER DEFAULT 1,
    last_session_id           TEXT,
    last_run                  TEXT,
    created_at                TEXT NOT NULL,
    is_active                 INTEGER DEFAULT 1
);
"""


class SqliteGraphStore(BaseGraphStore):
    """
    Persistent graph store backed by SQLite with WAL mode.

    Falls back gracefully to in-memory mode if aiosqlite is unavailable.
    This allows the server to start even if the optional dependency is missing.
    """

    def __init__(self, db_path: str = "heimdall_investigations.db", session_id: Optional[str] = None):
        if not _AIOSQLITE_AVAILABLE:
            logger.warning("aiosqlite not installed — falling back to in-memory store")
            self._fallback = MemoryGraphStore()
            self._db_path = None
        else:
            self._fallback = None
            self._db_path = db_path
        self._session_id = session_id
        self._memory = MemoryGraphStore()  # Always maintain in-memory mirror for fast reads

    async def _init_db(self):
        """Initializes the database schema on first connection."""
        if not self._db_path:
            return
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_DDL)
            await db.commit()
        logger.info(f"SQLite store initialized: {self._db_path}")

    async def create_session(self, session_id: str, seed_urn: str, config: Optional[Dict[str, Any]] = None):
        """Registers a new investigation session in the database."""
        self._session_id = session_id
        if not self._db_path:
            return
        await self._init_db()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO sessions (id, seed_urn, status, created_at, config_json) VALUES (?,?,?,?,?)",
                (session_id, seed_urn, "running", datetime.now(timezone.utc).isoformat(), json.dumps(config or {})),
            )
            await db.commit()

    async def complete_session(self, session_id: str, status: str = "completed"):
        """Marks a session as completed in the database."""
        if not self._db_path:
            return
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("UPDATE sessions SET status=? WHERE id=?", (status, session_id))
            await db.commit()

    # ── BaseGraphStore Interface ─────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> None:
        """Adds a node to the in-memory mirror (DB writes happen via add_edge)."""
        self._memory.add_node(node)

    def add_edge(self, edge: GraphEdge) -> bool:
        """Adds edge to in-memory store; async DB write is batched via add_edges."""
        return self._memory.add_edge(edge)

    def add_edges(self, edges: List[GraphEdge]) -> int:
        """Adds edges in batch to both memory and SQLite."""
        count = self._memory.add_edges(edges)
        if self._db_path and self._session_id and edges:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self._persist_edges(edges))
        return count

    async def _persist_edges(self, edges: List[GraphEdge]):
        """Persists a batch of edges to SQLite asynchronously."""
        if not self._db_path or not self._session_id:
            return
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                self._session_id,
                e.source,
                e.target,
                e.rel,
                e.target_type,
                json.dumps(e.properties),
                now,
            )
            for e in edges
        ]
        try:
            async with aiosqlite.connect(self._db_path) as db:
                await db.executemany(
                    "INSERT OR IGNORE INTO edges "
                    "(session_id, source_urn, target_urn, rel, target_type, properties_json, discovered_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    rows,
                )
                # Upsert touched nodes
                node_rows = set()
                for e in edges:
                    src_type, src_val = e.source.split(":", 1)
                    tgt_val = e.target.split(":", 1)[1] if ":" in e.target else e.target
                    node_rows.add((self._session_id, e.source, src_type, src_val, None))
                    node_rows.add((self._session_id, e.target, e.target_type, tgt_val, None))
                await db.executemany(
                    "INSERT OR IGNORE INTO nodes (session_id, urn, type, value, properties_json) VALUES (?,?,?,?,?)",
                    list(node_rows),
                )
                await db.commit()
        except Exception as exc:
            logger.error(f"SQLite edge persistence error: {exc}")

    def get_neighbors(self, urn: str, direction: str = "both") -> List[str]:
        return self._memory.get_neighbors(urn, direction)

    def get_edges(self) -> List[GraphEdge]:
        return self._memory.get_edges()

    def get_nodes(self) -> List[GraphNode]:
        return self._memory.get_nodes()

    def get_node(self, urn: str) -> Optional[GraphNode]:
        return self._memory.get_node(urn)

    def get_stats(self) -> Dict[str, Any]:
        stats = self._memory.get_stats()
        stats["backend"] = "sqlite" if self._db_path else "memory_fallback"
        stats["db_path"] = self._db_path
        return stats

    def extract_subgraph(self, center_urn: str, radius: int = 2) -> List[GraphEdge]:
        return self._memory.extract_subgraph(center_urn, radius)

    async def load_session(self, session_id: str) -> bool:
        """
        Loads a persisted session back into memory from SQLite.
        Returns True on success, False if session not found.
        """
        if not self._db_path:
            return False
        try:
            async with aiosqlite.connect(self._db_path) as db:
                db.row_factory = aiosqlite.Row
                # Load edges
                async with db.execute(
                    "SELECT source_urn, target_urn, rel, target_type, properties_json "
                    "FROM edges WHERE session_id=?",
                    (session_id,),
                ) as cursor:
                    rows = await cursor.fetchall()

                if not rows:
                    return False

                edges = [
                    GraphEdge(
                        source=r["source_urn"],
                        target=r["target_urn"],
                        rel=r["rel"],
                        target_type=r["target_type"],
                        properties=json.loads(r["properties_json"] or "{}"),
                    )
                    for r in rows
                ]
                self._memory.add_edges(edges)
                self._session_id = session_id
                logger.info(f"Loaded session {session_id}: {len(edges)} edges")
                return True
        except Exception as exc:
            logger.error(f"Session load failed [{session_id}]: {exc}")
            return False
