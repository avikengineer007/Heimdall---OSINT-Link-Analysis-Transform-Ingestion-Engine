"""
Webhook Alert Dispatcher for Heimdall OSINT Engine.

Sends structured JSON notifications to a configured ALERT_WEBHOOK_URL when
critical intelligence findings occur. Retries with exponential backoff on failure.

Trigger conditions:
  - Node threat score exceeds ALERT_THREAT_THRESHOLD
  - Critical CVE (CVSS >= 9.0) discovered on an exposed host
  - New subdomain or MX server discovered (informational)

Payload schema:
    {
        "source": "Heimdall",
        "timestamp": "<ISO-8601>",
        "alert_type": "<type>",
        "severity": "Low|Medium|High|Critical",
        "session_id": "<uuid>",
        "entity": "<type:value>",
        "details": {...}
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("heimdall.core.alerting")


class WebhookDispatcher:
    """
    Async webhook alert dispatcher with exponential backoff retry.

    Instantiate once and share across sessions; all dispatch calls are
    fire-and-forget coroutines that do not block the pipeline.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        threat_threshold: int = 75,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
    ):
        self.webhook_url = webhook_url
        self.threat_threshold = threat_threshold
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    async def _post(self, payload: Dict[str, Any]) -> bool:
        """POST payload to webhook URL with retry loop. Returns True on success."""
        if not self.webhook_url:
            return False

        try:
            import httpx
        except ImportError:
            logger.error("httpx not available — webhook dispatch failed")
            return False

        delay = self.base_delay
        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        self.webhook_url,
                        json=payload,
                        headers={
                            "Content-Type": "application/json",
                            "X-Heimdall-Event": payload.get("alert_type", "alert"),
                        },
                    )
                    if resp.status_code < 300:
                        logger.debug(f"Webhook delivered [{resp.status_code}]: {payload['alert_type']}")
                        return True
                    else:
                        logger.warning(
                            f"Webhook non-success [{resp.status_code}] attempt {attempt}/{self.max_retries}"
                        )
            except Exception as exc:
                logger.warning(f"Webhook dispatch error attempt {attempt}/{self.max_retries}: {exc}")

            if attempt < self.max_retries:
                jitter = random.uniform(0.1, 0.4)
                await asyncio.sleep(min(delay + jitter, self.max_delay))
                delay = min(delay * 2, self.max_delay)

        logger.error(f"Webhook delivery failed after {self.max_retries} attempts: {self.webhook_url}")
        return False

    def _build_payload(
        self,
        alert_type: str,
        severity: str,
        entity: str,
        session_id: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "source": "Heimdall OSINT Engine",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "session_id": session_id,
            "entity": entity,
            "details": details,
        }

    async def alert_threat_score(
        self,
        entity_urn: str,
        score: float,
        risk_level: str,
        breakdown: Dict[str, Any],
        session_id: str,
    ) -> None:
        """Fires when a node's composite threat score exceeds the configured threshold."""
        if not self.is_configured or score < self.threat_threshold:
            return

        payload = self._build_payload(
            alert_type="THREAT_SCORE_EXCEEDED",
            severity=risk_level,
            entity=entity_urn,
            session_id=session_id,
            details={
                "threat_score": score,
                "risk_level": risk_level,
                "threshold": self.threat_threshold,
                **breakdown,
            },
        )
        asyncio.ensure_future(self._post(payload))
        logger.info(f"[ALERT] Threat score {score} ({risk_level}) → {entity_urn}")

    async def alert_critical_cve(
        self,
        entity_urn: str,
        cve_id: str,
        cvss_score: float,
        session_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Fires when a critical CVE (CVSS >= 9.0) is discovered on an exposed host."""
        if not self.is_configured or cvss_score < 9.0:
            return

        payload = self._build_payload(
            alert_type="CRITICAL_CVE_DISCOVERED",
            severity="Critical",
            entity=entity_urn,
            session_id=session_id,
            details={
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                **(details or {}),
            },
        )
        asyncio.ensure_future(self._post(payload))
        logger.warning(f"[ALERT] Critical CVE {cve_id} (CVSS {cvss_score}) on {entity_urn}")

    async def alert_new_discovery(
        self,
        entity_urn: str,
        entity_type: str,
        session_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Informational alert for significant new entity discoveries."""
        if not self.is_configured:
            return

        payload = self._build_payload(
            alert_type="NEW_ENTITY_DISCOVERED",
            severity="Low",
            entity=entity_urn,
            session_id=session_id,
            details={"entity_type": entity_type, **(details or {})},
        )
        asyncio.ensure_future(self._post(payload))


# Module-level singleton configured from settings on first import
_dispatcher: Optional[WebhookDispatcher] = None


def get_dispatcher() -> WebhookDispatcher:
    """Returns the shared WebhookDispatcher instance, lazily initialized from settings."""
    global _dispatcher
    if _dispatcher is None:
        try:
            from heimdall.core.config import settings
            _dispatcher = WebhookDispatcher(
                webhook_url=settings.alert_webhook_url,
                threat_threshold=settings.alert_threat_threshold,
            )
        except Exception:
            _dispatcher = WebhookDispatcher()  # No-op dispatcher
    return _dispatcher
