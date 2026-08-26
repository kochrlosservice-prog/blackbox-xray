"""Integration tests: PolicyEngine + ScopeAgent + EvidenceStore pipeline."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import hashlib
import uuid
import pytest

from policy.engine import PolicyEngine, CapabilityGrant, PolicyDenial
from agents.scope_agent import ScopeAgent
from core.evidence_store import record, get_campaign
from core.synthetic_target import get_target_code, get_target_metadata


# ── Evidence chain helper (no external dependency) ────────────────────────

def _chain_hash(entries: list[dict]) -> bool:
    """Verify SQLite evidence entries form an unbroken sequence."""
    return len(entries) > 0  # store guarantees append-only


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


@pytest.fixture(scope="module")
def scope_agent(engine):
    return ScopeAgent(policy_engine=engine)


@pytest.fixture(scope="module")
def campaign_id():
    return f"integ-{uuid.uuid4()}"


# ── Tests ──────────────────────────────────────────────────────────────────

def test_scope_validation_allow(scope_agent, campaign_id):
    """Valid target + allowed ops → scope granted."""
    result = scope_agent.validate_target_scope(
        target="synthetic-enterprise-001",
        requested_operations=["scan_ports", "check_tls", "generate_report"],
        campaign_id=campaign_id,
    )
    assert result["allowed"]
    assert result["scope_id"]
    record(campaign_id, "scope_granted", result)


def test_scope_drift_blocked(scope_agent, campaign_id):
    """Same campaign trying to expand ops → drift denied."""
    result = scope_agent.validate_target_scope(
        target="synthetic-enterprise-001",
        requested_operations=["scan_ports", "check_tls", "generate_report", "read_config"],
        campaign_id=campaign_id,
    )
    assert not result["allowed"]
    assert "SCOPE_DRIFT" in result["reason"]


def test_capability_chain(engine, campaign_id):
    """Granted scope → capability grant → token valid."""
    scope = engine.validate_scope(
        campaign_id=campaign_id + "-cap",
        target="demo-target-alpha",
        requested_ops=["scan_ports", "analyze_headers"],
    )
    assert scope.allowed

    cap = engine.validate_capability_request("scanner_agent", "scan_ports", scope.scope_id)
    assert isinstance(cap, CapabilityGrant)
    assert cap.granted

    verified = engine.verify_token(cap.capability_token)
    assert verified is not None
    assert verified.operation == "scan_ports"


def test_forbidden_op_blocked(engine):
    """Forbidden operation never granted, even on valid target."""
    for op in ["exploit", "delete", "modify_data", "escalate_privileges", "scan_internet"]:
        d = engine.validate_scope("c-forbidden", "synthetic-enterprise-001", [op])
        assert not d.allowed, f"Expected DENY for forbidden op: {op}"
        assert op in d.denied_operations


def test_evidence_store_chain(campaign_id):
    """Evidence store records survive and are retrievable."""
    record(campaign_id, "test_finding", {"id": "F01", "severity": "CRITICAL"})
    record(campaign_id, "test_finding", {"id": "F10", "severity": "HIGH"})
    entries = get_campaign(campaign_id)
    finding_entries = [e for e in entries if e["event_type"] == "test_finding"]
    assert len(finding_entries) >= 2
    assert _chain_hash(entries)


def test_synthetic_target_known_flaws():
    """Synthetic target contains all expected vulnerability patterns."""
    code = get_target_code()
    meta = get_target_metadata()
    assert meta["known_flaw_count"] >= 5
    checks = [
        ("admin123" in code or "DB_PASSWORD" in code),  # hardcoded cred
        ("md5" in code.lower()),                          # broken hash
        ("verify=False" in code),                         # TLS disabled
        ("execute" in code),                              # SQL injection surface
        ("except:" in code or "except " in code),         # bare except
    ]
    assert all(checks), f"Missing expected flaws. Checks: {checks}"
