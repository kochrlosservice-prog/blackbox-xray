"""
Tamper-evident evidence ledger for SENTINEL / BLACKBOX X-RAY.

Each ledger entry is chained via SHA-256 so any post-hoc modification
of a historical entry invalidates all subsequent hashes.

Chain formula:
  entry_hash = sha256(prev_hash + evidence_id + finding_hash + str(chain_index))

Backend: Firestore via FirestoreClient.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from infrastructure.firestore_client import FirestoreClient, get_client

logger = logging.getLogger(__name__)

# Sentinel value for the very first entry in a chain (no predecessor)
_GENESIS_HASH = "0" * 64


def _sha256(*parts: str) -> str:
    """Concatenate *parts* and return the hex SHA-256 digest."""
    combined = "".join(parts).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def _finding_hash(finding: Any) -> str:
    """
    Deterministic SHA-256 of *finding*.

    Accepts a plain string, bytes, or anything with a __str__ repr.
    """
    if isinstance(finding, bytes):
        return hashlib.sha256(finding).hexdigest()
    return hashlib.sha256(str(finding).encode("utf-8")).hexdigest()


class EvidenceLedger:
    """
    Append-only, hash-chained evidence store backed by Firestore.

    Each campaign has its own independent chain (identified by campaign_id).
    """

    def __init__(self, firestore_client: FirestoreClient | None = None) -> None:
        self._fs: FirestoreClient = firestore_client or get_client()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _chain_collection(self, campaign_id: str) -> str:
        """Return the Firestore sub-collection name for a campaign's chain."""
        # Store all chain entries under evidence_ledger, keyed by campaign + index
        return "evidence_ledger"

    def _get_chain_raw(self, campaign_id: str) -> list[dict[str, Any]]:
        """
        Retrieve the ordered chain for *campaign_id* from Firestore.

        Returns a list sorted ascending by chain_index.
        """
        db = self._fs._get_db()
        if db is None:
            return []
        try:
            col = db.collection("evidence_ledger")
            query = (
                col.where("campaign_id", "==", campaign_id)
                .order_by("chain_index")
            )
            return [doc.to_dict() for doc in query.stream()]
        except Exception as exc:
            logger.error("_get_chain_raw(%s) failed: %s", campaign_id, exc)
            return []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_entry(
        self,
        campaign_id: str,
        finding: Any,
        evidence_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Append a new entry to the campaign's evidence chain.

        Parameters
        ----------
        campaign_id : str
            The campaign this evidence belongs to.
        finding : Any
            The raw finding payload (string, dict, etc.).
        evidence_id : str | None
            Optional caller-supplied ID. Auto-generated if omitted.

        Returns
        -------
        dict
            The persisted ledger entry including its hash fields.
        """
        if evidence_id is None:
            evidence_id = str(uuid.uuid4())

        # Determine chain position and previous hash
        existing_chain = self._get_chain_raw(campaign_id)
        if existing_chain:
            last = existing_chain[-1]
            prev_hash: str = last["entry_hash"]
            chain_index: int = last["chain_index"] + 1
        else:
            prev_hash = _GENESIS_HASH
            chain_index = 0

        fhash = _finding_hash(finding)
        entry_hash = _sha256(prev_hash, evidence_id, fhash, str(chain_index))

        entry: dict[str, Any] = {
            "evidence_id": evidence_id,
            "campaign_id": campaign_id,
            "finding": finding if isinstance(finding, (str, int, float, bool, type(None))) else str(finding),
            "finding_hash": fhash,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "chain_index": chain_index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        saved_id = self._fs.save_evidence(evidence_id, entry)
        logger.info(
            "Evidence entry saved: campaign=%s index=%d id=%s hash=%s…",
            campaign_id, chain_index, saved_id, entry_hash[:16],
        )
        return entry

    def verify_chain(self, campaign_id: str) -> bool:
        """
        Verify the integrity of the entire evidence chain for *campaign_id*.

        Returns True if every entry's hash is consistent with its content
        and links correctly to the previous entry.
        """
        chain = self._get_chain_raw(campaign_id)
        if not chain:
            # An empty chain is trivially valid
            return True

        expected_prev = _GENESIS_HASH
        for entry in chain:
            # Verify chain linkage
            if entry["prev_hash"] != expected_prev:
                logger.warning(
                    "Chain broken at index %d for campaign %s: "
                    "expected prev_hash %s, got %s",
                    entry["chain_index"], campaign_id,
                    expected_prev, entry["prev_hash"],
                )
                return False

            # Recompute and verify entry hash
            computed = _sha256(
                entry["prev_hash"],
                entry["evidence_id"],
                entry["finding_hash"],
                str(entry["chain_index"]),
            )
            if computed != entry["entry_hash"]:
                logger.warning(
                    "Hash mismatch at index %d for campaign %s: "
                    "computed=%s stored=%s",
                    entry["chain_index"], campaign_id, computed, entry["entry_hash"],
                )
                return False

            expected_prev = entry["entry_hash"]

        logger.info("Chain verification passed for campaign %s (%d entries)", campaign_id, len(chain))
        return True

    def get_chain(self, campaign_id: str) -> list[dict[str, Any]]:
        """
        Return the complete ordered evidence chain for *campaign_id*.

        Each element is a dict with keys:
          evidence_id, campaign_id, finding, finding_hash,
          prev_hash, entry_hash, chain_index, timestamp
        """
        return self._get_chain_raw(campaign_id)
