"""
Heimdall Monitoring Scheduler Daemon.

Provides continuous attack surface sweeps, temporal change detection,
and automated webhook alerts for monitored assets.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from heimdall.core.config import settings
from heimdall.core.alerting import WebhookDispatcher
from heimdall.graph.diff_engine import diff_sessions
from heimdall.graph.sqlite_store import SqliteGraphStore
from heimdall.pipeline.orchestrator import PipelineOrchestrator

logger = logging.getLogger("heimdall.pipeline.scheduler")


class MonitoringSchedule(BaseModel):
    """Configuration for a scheduled investigation sweep."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    seed_urn: str
    cron_expr: str = "0 9 * * 1"  # Default: Weekly Mondays 09:00 UTC (or "*/60 * * * *")
    max_depth: int = 2
    alert_on_new_nodes: bool = True
    alert_on_threat_increase: bool = True
    last_run: Optional[str] = None
    last_session_id: Optional[str] = None
    is_active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _match_field(field_val: int, pattern: str) -> bool:
    """Matches an integer against a single cron field pattern (e.g. '*', '*/5', '1,2', '10-20')."""
    if pattern == "*":
        return True
    if pattern.startswith("*/"):
        try:
            step = int(pattern[2:])
            return (field_val % step) == 0
        except ValueError:
            return False
    if "," in pattern:
        parts = pattern.split(",")
        return any(_match_field(field_val, p.strip()) for p in parts)
    if "-" in pattern:
        try:
            start, end = map(int, pattern.split("-"))
            return start <= field_val <= end
        except ValueError:
            return False
    try:
        return int(pattern) == field_val
    except ValueError:
        return False


def is_cron_due(cron_expr: str, dt: Optional[datetime] = None) -> bool:
    """
    Checks if standard 5-part cron expression (minute hour dom month dow)
    matches the given UTC datetime (defaulting to current minute).
    """
    dt = dt or datetime.now(timezone.utc)
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        # Fallback support for single interval strings like "60m"
        return False

    c_min, c_hour, c_dom, c_mon, c_dow = parts

    # Python weekday: Monday is 0, Sunday is 6. Cron: Sunday is 0 or 7, Monday is 1.
    cron_dow = (dt.weekday() + 1) % 7

    return (
        _match_field(dt.minute, c_min)
        and _match_field(dt.hour, c_hour)
        and _match_field(dt.day, c_dom)
        and _match_field(dt.month, c_mon)
        and (_match_field(cron_dow, c_dow) or (c_dow == "7" and cron_dow == 0))
    )


class ScheduleStore:
    """SQLite-backed storage manager for monitoring schedules."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.sqlite_db_path
        self._init_db()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            from heimdall.graph.sqlite_store import _DDL
            conn.executescript(_DDL)

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, schedule: MonitoringSchedule) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO monitoring_schedules (
                    id, seed_urn, cron_expr, max_depth,
                    alert_on_new_nodes, alert_on_threat_increase,
                    last_run, last_session_id, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    seed_urn=excluded.seed_urn,
                    cron_expr=excluded.cron_expr,
                    max_depth=excluded.max_depth,
                    alert_on_new_nodes=excluded.alert_on_new_nodes,
                    alert_on_threat_increase=excluded.alert_on_threat_increase,
                    last_run=excluded.last_run,
                    last_session_id=excluded.last_session_id,
                    is_active=excluded.is_active
                """,
                (
                    schedule.id,
                    schedule.seed_urn,
                    schedule.cron_expr,
                    schedule.max_depth,
                    1 if schedule.alert_on_new_nodes else 0,
                    1 if schedule.alert_on_threat_increase else 0,
                    schedule.last_run,
                    schedule.last_session_id,
                    1 if schedule.is_active else 0,
                    schedule.created_at,
                ),
            )

    def list_all(self) -> List[MonitoringSchedule]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM monitoring_schedules ORDER BY created_at DESC")
            schedules = []
            for row in cursor.fetchall():
                schedules.append(
                    MonitoringSchedule(
                        id=row["id"],
                        seed_urn=row["seed_urn"],
                        cron_expr=row["cron_expr"],
                        max_depth=row["max_depth"],
                        alert_on_new_nodes=bool(row["alert_on_new_nodes"]),
                        alert_on_threat_increase=bool(row["alert_on_threat_increase"]),
                        last_run=row["last_run"],
                        last_session_id=row["last_session_id"],
                        is_active=bool(row["is_active"]),
                        created_at=row["created_at"],
                    )
                )
            return schedules

    def get(self, schedule_id: str) -> Optional[MonitoringSchedule]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM monitoring_schedules WHERE id = ?", (schedule_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return MonitoringSchedule(
                id=row["id"],
                seed_urn=row["seed_urn"],
                cron_expr=row["cron_expr"],
                max_depth=row["max_depth"],
                alert_on_new_nodes=bool(row["alert_on_new_nodes"]),
                alert_on_threat_increase=bool(row["alert_on_threat_increase"]),
                last_run=row["last_run"],
                last_session_id=row["last_session_id"],
                is_active=bool(row["is_active"]),
                created_at=row["created_at"],
            )

    def delete(self, schedule_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM monitoring_schedules WHERE id = ?", (schedule_id,))
            return cursor.rowcount > 0

    def update_run_result(self, schedule_id: str, session_id: str, run_timestamp: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE monitoring_schedules
                SET last_run = ?, last_session_id = ?
                WHERE id = ?
                """,
                (run_timestamp, session_id, schedule_id),
            )


class SchedulerDaemon:
    """Background service executing scheduled attack surface sweeps."""

    def __init__(self, db_path: Optional[str] = None, check_interval_seconds: int = 60):
        self.db_path = db_path or settings.sqlite_db_path
        self.check_interval = check_interval_seconds
        self.store = ScheduleStore(self.db_path)
        self.dispatcher = WebhookDispatcher()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("SchedulerDaemon started background monitoring loop")

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("SchedulerDaemon stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._check_and_execute_schedules()
            except Exception as e:
                logger.error(f"Scheduler cycle error: {e}", exc_info=True)
            await asyncio.sleep(self.check_interval)

    async def _check_and_execute_schedules(self) -> None:
        schedules = self.store.list_all()
        now = datetime.now(timezone.utc)
        current_minute_str = now.strftime("%Y-%m-%d %H:%M")

        for sched in schedules:
            if not sched.is_active:
                continue

            # Prevent double execution within the exact same minute
            if sched.last_run and sched.last_run.startswith(current_minute_str):
                continue

            if is_cron_due(sched.cron_expr, now):
                asyncio.create_task(self.run_scheduled_job(sched))

    async def run_scheduled_job(self, sched: MonitoringSchedule) -> Optional[str]:
        """Runs an investigation for a schedule, computes deltas, and dispatches alerts."""
        logger.info(f"Triggering scheduled sweep for {sched.seed_urn} (schedule {sched.id[:8]})")
        new_session_id = str(uuid.uuid4())
        run_ts = datetime.now(timezone.utc).isoformat()

        try:
            graph_store = SqliteGraphStore(self.db_path)
            orchestrator = PipelineOrchestrator(graph_store=graph_store)

            # Execute full investigation crawl
            await orchestrator.run_investigation(
                seed=sched.seed_urn,
                max_depth=sched.max_depth,
                session_id=new_session_id,
            )

            # If a previous run exists, compute temporal delta
            if sched.last_session_id:
                try:
                    delta = await diff_sessions(
                        session_a=sched.last_session_id,
                        session_b=new_session_id,
                        db_path=self.db_path,
                    )
                    # Check for trigger alerts
                    should_alert = False
                    alert_reasons = []

                    if sched.alert_on_new_nodes and delta.added_nodes:
                        should_alert = True
                        alert_reasons.append(f"{len(delta.added_nodes)} new nodes discovered")

                    if sched.alert_on_threat_increase and delta.changed_props:
                        for urn, changes in delta.changed_props.items():
                            if "threat_score" in changes:
                                old_s = changes["threat_score"]["old"]
                                new_s = changes["threat_score"]["new"]
                                if new_s > old_s:
                                    should_alert = True
                                    alert_reasons.append(f"{urn} threat score increased ({old_s} -> {new_s})")

                    if should_alert and self.dispatcher.is_enabled():
                        await self.dispatcher.dispatch_alert(
                            entity_urn=sched.seed_urn,
                            threat_score=85,
                            reasons=alert_reasons,
                            session_id=new_session_id,
                        )
                except Exception as diff_err:
                    logger.warning(f"Error computing delta for schedule {sched.id}: {diff_err}")

            # Update schedule state in database
            self.store.update_run_result(sched.id, new_session_id, run_ts)
            return new_session_id
        except Exception as err:
            logger.error(f"Failed scheduled job {sched.id}: {err}", exc_info=True)
            return None
