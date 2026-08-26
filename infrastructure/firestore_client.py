"""
Firestore client for SENTINEL / BLACKBOX X-RAY.
GCP Project: rlos-506521
Collections: campaigns, evidence_ledger, policy_decisions, agent_registry
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_GCP_PROJECT = "rlos-506521"

# Collection names
COL_CAMPAIGNS = "campaigns"
COL_EVIDENCE_LEDGER = "evidence_ledger"
COL_POLICY_DECISIONS = "policy_decisions"
COL_AGENT_REGISTRY = "agent_registry"


class FirestoreClient:
    """Lazy-initialised Firestore client with graceful error handling."""

    def __init__(self, project: str = _GCP_PROJECT) -> None:
        self._project = project
        self._db = None  # lazy init

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_db(self):
        """Return Firestore DB handle, initialising on first call."""
        if self._db is not None:
            return self._db
        try:
            from google.cloud import firestore  # type: ignore
            self._db = firestore.Client(project=self._project)
            logger.info("Firestore connected to project %s", self._project)
        except Exception as exc:
            logger.error("Firestore init failed: %s", exc)
            self._db = None
        return self._db

    def _col(self, collection: str):
        db = self._get_db()
        if db is None:
            return None
        return db.collection(collection)

    # ------------------------------------------------------------------
    # Campaign operations
    # ------------------------------------------------------------------

    def save_campaign(self, campaign_id: str, data: dict[str, Any]) -> str:
        """Persist campaign data and return document ID."""
        col = self._col(COL_CAMPAIGNS)
        if col is None:
            logger.error("Firestore unavailable — cannot save campaign %s", campaign_id)
            return campaign_id
        try:
            doc_ref = col.document(campaign_id)
            doc_ref.set(data, merge=True)
            logger.debug("Campaign %s saved.", campaign_id)
            return doc_ref.id
        except Exception as exc:
            logger.error("save_campaign(%s) failed: %s", campaign_id, exc)
            return campaign_id

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        """Return campaign data or None if not found / unavailable."""
        col = self._col(COL_CAMPAIGNS)
        if col is None:
            logger.error("Firestore unavailable — cannot fetch campaign %s", campaign_id)
            return None
        try:
            doc = col.document(campaign_id).get()
            if doc.exists:
                return doc.to_dict()
            return None
        except Exception as exc:
            logger.error("get_campaign(%s) failed: %s", campaign_id, exc)
            return None

    def list_campaigns(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return up to *limit* campaign documents (newest first by timestamp)."""
        col = self._col(COL_CAMPAIGNS)
        if col is None:
            logger.error("Firestore unavailable — cannot list campaigns")
            return []
        try:
            query = col.order_by("timestamp", direction="DESCENDING").limit(limit)
            return [doc.to_dict() | {"_id": doc.id} for doc in query.stream()]
        except Exception as exc:
            logger.error("list_campaigns() failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Evidence operations
    # ------------------------------------------------------------------

    def save_evidence(self, evidence_id: str, data: dict[str, Any]) -> str:
        """Persist an evidence ledger entry and return document ID."""
        col = self._col(COL_EVIDENCE_LEDGER)
        if col is None:
            logger.error("Firestore unavailable — cannot save evidence %s", evidence_id)
            return evidence_id
        try:
            doc_ref = col.document(evidence_id)
            doc_ref.set(data, merge=True)
            logger.debug("Evidence %s saved.", evidence_id)
            return doc_ref.id
        except Exception as exc:
            logger.error("save_evidence(%s) failed: %s", evidence_id, exc)
            return evidence_id

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        """Return evidence entry or None."""
        col = self._col(COL_EVIDENCE_LEDGER)
        if col is None:
            logger.error("Firestore unavailable — cannot fetch evidence %s", evidence_id)
            return None
        try:
            doc = col.document(evidence_id).get()
            if doc.exists:
                return doc.to_dict()
            return None
        except Exception as exc:
            logger.error("get_evidence(%s) failed: %s", evidence_id, exc)
            return None

    # ------------------------------------------------------------------
    # Policy decision operations
    # ------------------------------------------------------------------

    def save_policy_decision(self, decision_id: str, data: dict[str, Any]) -> str:
        """Persist a policy decision record and return document ID."""
        col = self._col(COL_POLICY_DECISIONS)
        if col is None:
            logger.error("Firestore unavailable — cannot save policy decision %s", decision_id)
            return decision_id
        try:
            doc_ref = col.document(decision_id)
            doc_ref.set(data, merge=True)
            logger.debug("Policy decision %s saved.", decision_id)
            return doc_ref.id
        except Exception as exc:
            logger.error("save_policy_decision(%s) failed: %s", decision_id, exc)
            return decision_id

    def get_policy_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return up to *limit* policy decision documents (newest first)."""
        col = self._col(COL_POLICY_DECISIONS)
        if col is None:
            logger.error("Firestore unavailable — cannot list policy decisions")
            return []
        try:
            query = col.order_by("timestamp", direction="DESCENDING").limit(limit)
            return [doc.to_dict() | {"_id": doc.id} for doc in query.stream()]
        except Exception as exc:
            logger.error("get_policy_decisions() failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Agent registry operations
    # ------------------------------------------------------------------

    def register_agent(self, agent_id: str, data: dict[str, Any]) -> str:
        """Register or update an agent entry in the registry."""
        col = self._col(COL_AGENT_REGISTRY)
        if col is None:
            logger.error("Firestore unavailable — cannot register agent %s", agent_id)
            return agent_id
        try:
            doc_ref = col.document(agent_id)
            doc_ref.set(data, merge=True)
            return doc_ref.id
        except Exception as exc:
            logger.error("register_agent(%s) failed: %s", agent_id, exc)
            return agent_id

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Return agent registry entry or None."""
        col = self._col(COL_AGENT_REGISTRY)
        if col is None:
            return None
        try:
            doc = col.document(agent_id).get()
            if doc.exists:
                return doc.to_dict()
            return None
        except Exception as exc:
            logger.error("get_agent(%s) failed: %s", agent_id, exc)
            return None

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if Firestore can be reached (lightweight ping)."""
        db = self._get_db()
        if db is None:
            return False
        try:
            # Attempt to list one document from any collection as connectivity check
            list(db.collection(COL_CAMPAIGNS).limit(1).stream())
            return True
        except Exception as exc:
            logger.warning("Firestore health check failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_client: FirestoreClient | None = None


def get_client() -> FirestoreClient:
    global _default_client
    if _default_client is None:
        _default_client = FirestoreClient()
    return _default_client
