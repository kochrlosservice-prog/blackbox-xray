"""Unit tests: PolicyEngine scope + capability scenarios."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from policy.engine import PolicyEngine, CapabilityGrant, PolicyDenial, ALLOWED_TARGETS


def test_all_allowed_targets_accepted():
    engine = PolicyEngine()
    for target in ALLOWED_TARGETS:
        d = engine.validate_scope("c-all", target, ["scan_ports"])
        assert d.allowed, f"Expected allowed for {target}"


def test_multiple_allowed_ops_granted():
    engine = PolicyEngine()
    ops = ["scan_ports", "check_tls", "generate_report", "read_config", "analyze_headers"]
    d = engine.validate_scope("c-multi", "synthetic-enterprise-001", ops)
    assert d.allowed
    assert set(ops).issubset(set(d.allowed_operations))


def test_mixed_ops_partial_deny():
    engine = PolicyEngine()
    d = engine.validate_scope("c-mix", "demo-target-alpha",
                               ["scan_ports", "modify_data"])
    assert not d.allowed
    assert "modify_data" in d.denied_operations


def test_capability_not_in_scope_denied():
    engine = PolicyEngine()
    scope = engine.validate_scope("c-cap", "synthetic-enterprise-001", ["scan_ports"])
    cap = engine.validate_capability_request("agent", "check_tls", scope.scope_id)
    assert isinstance(cap, PolicyDenial)
    assert not cap.granted


def test_replay_nonce_unique():
    engine = PolicyEngine()
    scope = engine.validate_scope("c-nonce", "demo-target-alpha",
                                  ["scan_ports", "check_tls"])
    g1 = engine.validate_capability_request("a1", "scan_ports", scope.scope_id)
    g2 = engine.validate_capability_request("a2", "check_tls", scope.scope_id)
    assert isinstance(g1, CapabilityGrant)
    assert isinstance(g2, CapabilityGrant)
    assert g1.replay_nonce != g2.replay_nonce


def test_audit_log_grows():
    engine = PolicyEngine()
    before = len(engine.get_audit_log())
    engine.validate_scope("c-audit", "test-env-isolated", ["scan_ports"])
    assert len(engine.get_audit_log()) > before
