"""
Pub/Sub client for SENTINEL / BLACKBOX X-RAY.
GCP Project: rlos-506521

Topics (resolved from environment variables with defaults):
  PUBSUB_TOPIC_EVENTS   -> sentinel-agent-events
  PUBSUB_TOPIC_EVIDENCE -> sentinel-evidence
  PUBSUB_TOPIC_ALERTS   -> sentinel-alerts
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_GCP_PROJECT = "rlos-506521"

_DEFAULT_TOPIC_EVENTS = "sentinel-agent-events"
_DEFAULT_TOPIC_EVIDENCE = "sentinel-evidence"
_DEFAULT_TOPIC_ALERTS = "sentinel-alerts"


def _topic_path(project: str, topic_id: str) -> str:
    return f"projects/{project}/topics/{topic_id}"


class PubSubClient:
    """Lazy-initialised Pub/Sub publisher with graceful error handling."""

    def __init__(self, project: str = _GCP_PROJECT) -> None:
        self._project = project
        self._publisher = None  # lazy init

        # Resolve topic IDs from env (allows runtime override without code change)
        self._topic_events = os.environ.get("PUBSUB_TOPIC_EVENTS", _DEFAULT_TOPIC_EVENTS)
        self._topic_evidence = os.environ.get("PUBSUB_TOPIC_EVIDENCE", _DEFAULT_TOPIC_EVIDENCE)
        self._topic_alerts = os.environ.get("PUBSUB_TOPIC_ALERTS", _DEFAULT_TOPIC_ALERTS)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_publisher(self):
        """Return Pub/Sub publisher, initialising on first call."""
        if self._publisher is not None:
            return self._publisher
        try:
            from google.cloud import pubsub_v1  # type: ignore
            self._publisher = pubsub_v1.PublisherClient()
            logger.info("Pub/Sub publisher initialised for project %s", self._project)
        except Exception as exc:
            logger.error("Pub/Sub publisher init failed: %s", exc)
            self._publisher = None
        return self._publisher

    def _publish(self, topic_id: str, payload: dict[str, Any]) -> str | None:
        """Encode *payload* as UTF-8 JSON and publish to *topic_id*. Returns message ID or None."""
        publisher = self._get_publisher()
        if publisher is None:
            logger.error("Pub/Sub unavailable — dropping message to topic %s", topic_id)
            return None
        try:
            path = _topic_path(self._project, topic_id)
            data = json.dumps(payload, default=str).encode("utf-8")
            future = publisher.publish(path, data=data)
            msg_id = future.result(timeout=10)
            logger.debug("Published to %s — message_id=%s", topic_id, msg_id)
            return msg_id
        except Exception as exc:
            logger.error("Pub/Sub publish to %s failed: %s", topic_id, exc)
            return None

    # ------------------------------------------------------------------
    # Public publishing methods
    # ------------------------------------------------------------------

    def publish_agent_event(
        self,
        agent_id: str,
        campaign_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> str | None:
        """
        Publish an agent lifecycle / activity event.

        Envelope fields:
          trace_id, campaign_id, agent_id, timestamp, event_type, data
        """
        payload: dict[str, Any] = {
            "trace_id": str(uuid.uuid4()),
            "campaign_id": campaign_id,
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
        }
        return self._publish(self._topic_events, payload)

    def publish_evidence(
        self,
        campaign_id: str,
        evidence_id: str,
        finding_hash: str,
    ) -> str | None:
        """
        Publish a new evidence entry notification.

        Envelope fields:
          trace_id, campaign_id, evidence_id, finding_hash, timestamp
        """
        payload: dict[str, Any] = {
            "trace_id": str(uuid.uuid4()),
            "campaign_id": campaign_id,
            "evidence_id": evidence_id,
            "finding_hash": finding_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "evidence.added",
        }
        return self._publish(self._topic_evidence, payload)

    def publish_alert(
        self,
        campaign_id: str,
        alert_type: str,
        details: dict[str, Any],
    ) -> str | None:
        """
        Publish a security alert.

        Envelope fields:
          trace_id, campaign_id, alert_type, details, timestamp
        """
        payload: dict[str, Any] = {
            "trace_id": str(uuid.uuid4()),
            "campaign_id": campaign_id,
            "alert_type": alert_type,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "alert.raised",
        }
        return self._publish(self._topic_alerts, payload)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the Pub/Sub publisher can be initialised."""
        return self._get_publisher() is not None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_client: PubSubClient | None = None


def get_client() -> PubSubClient:
    global _default_client
    if _default_client is None:
        _default_client = PubSubClient()
    return _default_client
