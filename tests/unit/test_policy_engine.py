"""
Unit tests for SENTINEL PolicyEngine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from policy.engine import (
    CAPABILITY_TTL_SECONDS,
    CapabilityGrant,
    PolicyDecision,
    PolicyDenial,
    PolicyEngine,
)


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# test_valid_target_allowed
# ---------------------------------------------------------------------------

def test_valid_target_allowed(engine: PolicyEngine) -> None:
    """A valid synthetic target with an allowed operation must return allowed=True."""
    decision = engine.validate_scope(
        campaign_id="test-camp-001",
        target="synthetic-enterprise-001",
        requested_ops=["scan_ports"],
    )

    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is True
    assert "scan_ports" in decision.allowed_operations
    assert decision.denied_operations == []
    assert decision.scope_id in engine._scope_registry


# ---------------------------------------------------------------------------
# test_unknown_target_denied
# ---------------------------------------------------------------------------

def test_unknown_target_denied(engine: PolicyEngine) -> None:
    """A non-synthetic target (e.g. public IP 8.8.8.8) must be denied."""
    decision = engine.validate_scope(
        campaign_id="test-camp-002",
        target="8.8.8.8",
        requested_ops=["scan_ports"],
    )

    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is False
    assert "8.8.8.8" in decision.reason or "ALLOWED_TARGETS" in decision.reason


# ---------------------------------------------------------------------------
# test_forbidden_operation_denied
# ---------------------------------------------------------------------------

def test_forbidden_operation_denied(engine: PolicyEngine) -> None:
    """Requesting the 'exploit' operation on a valid target must be denied."""
    decision = engine.validate_scope(
        campaign_id="test-camp-003",
        target="synthetic-enterprise-001",
        requested_ops=["exploit"],
    )

    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is False
    assert "exploit" in decision.denied_operations


# ---------------------------------------------------------------------------
# test_capability_token_expires
# ---------------------------------------------------------------------------

def test_capability_token_expires(engine: PolicyEngine) -> None:
    """A capability grant must be treated as expired after CAPABILITY_TTL_SECONDS."""
    # First create a valid scope
    decision = engine.validate_scope(
        campaign_id="test-camp-004",
        target="synthetic-enterprise-001",
        requested_ops=["scan_ports"],
    )
    assert decision.allowed

    # Request a capability token
    grant = engine.validate_capability_request(
        agent_id="agent-test",
        operation="scan_ports",
        scope_id=decision.scope_id,
    )
    assert isinstance(grant, CapabilityGrant)
    assert grant.granted is True

    # Simulate time advancing beyond the TTL (6 minutes > 5 minute TTL)
    future_time = _now() + timedelta(seconds=CAPABILITY_TTL_SECONDS + 60)
    with patch("policy.engine._now", return_value=future_time):
        verified = engine.verify_token(grant.capability_token)

    assert verified is None, (
        "Token should be expired and verify_token must return None after TTL"
    )


# ---------------------------------------------------------------------------
# test_scope_drift_detected
# ---------------------------------------------------------------------------

def test_scope_drift_detected(engine: PolicyEngine) -> None:
    """Requesting operations that are a superset of the granted scope must flag drift."""
    # Grant scope for only one operation
    decision = engine.validate_scope(
        campaign_id="test-camp-005",
        target="test-env-isolated",
        requested_ops=["read_config"],
    )
    assert decision.allowed

    # Agent now tries to execute more operations than granted
    superset_request = ["read_config", "scan_ports", "generate_report"]
    drift = engine.check_scope_drift(
        agent_id="agent-rogue",
        original_scope=decision,
        current_request=superset_request,
    )

    assert drift is True, (
        "Scope drift must be detected when current_request is a superset of granted ops"
    )
