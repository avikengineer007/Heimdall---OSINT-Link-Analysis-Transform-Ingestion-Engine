"""
Tests for Heimdall Continuous Monitoring Scheduler and Cron Parser.
"""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import sqlite3
import pytest

from heimdall.pipeline.scheduler import (
    MonitoringSchedule,
    ScheduleStore,
    is_cron_due,
)
from heimdall.graph.sqlite_store import _DDL


def test_cron_matcher_expressions():
    # Target date: 2026-09-21 09:30 UTC (Monday)
    dt = datetime(2026, 9, 21, 9, 30, tzinfo=timezone.utc)

    # 1. Exact match
    assert is_cron_due("30 9 21 9 1", dt) is True

    # 2. Wildcard match
    assert is_cron_due("* * * * *", dt) is True

    # 3. Step expression (minute 30 is divisible by 15)
    assert is_cron_due("*/15 * * * *", dt) is True
    assert is_cron_due("*/20 * * * *", dt) is False

    # 4. Wrong weekday (Tuesday is 2, Monday is 1)
    assert is_cron_due("30 9 * * 2", dt) is False


def test_schedule_store_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_schedules.db")
        # Initialize schema
        conn = sqlite3.connect(db_path)
        conn.executescript(_DDL)
        conn.close()

        store = ScheduleStore(db_path=db_path)

        # 1. Save schedule
        sched = MonitoringSchedule(
            seed_urn="Domain:target-corp.com",
            cron_expr="0 9 * * 1",
            max_depth=2,
            alert_on_new_nodes=True,
        )
        store.save(sched)

        # 2. List schedules
        schedules = store.list_all()
        assert len(schedules) == 1
        assert schedules[0].seed_urn == "Domain:target-corp.com"
        assert schedules[0].cron_expr == "0 9 * * 1"

        # 3. Get schedule by ID
        fetched = store.get(sched.id)
        assert fetched is not None
        assert fetched.id == sched.id

        # 4. Update run result
        store.update_run_result(sched.id, "sess-12345", "2026-09-20T10:00:00")
        updated = store.get(sched.id)
        assert updated.last_session_id == "sess-12345"
        assert updated.last_run == "2026-09-20T10:00:00"

        # 5. Delete schedule
        assert store.delete(sched.id) is True
        assert store.get(sched.id) is None
        assert len(store.list_all()) == 0


def test_scheduler_step_cron_intervals():
    dt_even = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    dt_odd = datetime(2026, 9, 21, 10, 1, tzinfo=timezone.utc)
    # Every 2 minutes
    assert is_cron_due("*/2 * * * *", dt_even) is True
    assert is_cron_due("*/2 * * * *", dt_odd) is False
