"""
SENTINEL - Deterministic Policy Engine
AGENT_OUTPUT != EXECUTION_AUTHORITY

All agent requests must pass through this engine before any capability is granted.
No exceptions propagate silently - every failure returns a PolicyDenial.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Structured logging (JSON format, falls back to stdlib if structlog absent)
# ---------------------------------------------------------------------------

try:
    import structlog

    logger = structlog.get_logger("sentinel.policy.engine")
    _STRUCTLOG = True
except ImportError:
    _STRUCTLOG = False
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","event":"%(message)s"}'
        )
    )
    _log = logging.getLogger("sentinel.policy.engine")
    _log.setLevel(logging.INFO)
    _log.addHandler(_handler)

    class _StructlogShim:
        """Minimal shim so the rest of the code uses a single call style."""

        def _emit(self, level: str, event: str, **kw: object) -> None:
            extra = json.dumps(kw, default=str)
            _log.log(
                getattr(logging, level.upper(), logging.INFO),
                "%s %s",
                event,
                extra,
            )

        def info(self, event: str, **kw: object) -> None:
            self._emit("info", event, **kw)

        def warning(self, event: str, **kw: object) -> None:
            self._emit("warning", event, **kw)

        def error(self, event: str, **kw: object) -> None:
            self._emit("error", event, **kw)

    logger = _StructlogShim()  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_TARGETS: frozenset[str] = frozenset(
    [
        "synthetic-enterprise-001",
        "demo-target-alpha",
        "test-env-isolated",
    ]
)

ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    [
        "scan_ports",
        "check_tls",
        "analyze_headers",
        "read_config",
        "generate_report",
    ]
)

FORBIDDEN_OPERATIONS: frozenset[str] = frozenset(
    [
        "exploit",
        "modify_data",
        "delete",
        "escalate_privileges",
        "scan_internet",
        # Shell execution — HARD BLOCK, no exceptions
        "run_shell",
        "execute_command",
        "bash",
        "shell",
        "run_bash",
        "subprocess",
        "exec",
        "eval",
        "os_system",
    ]
)

# Shell-related tool names that must never appear in any agent's tool list.
# Checked at agent registration time by validate_agent_tools().
FORBIDDEN_TOOL_NAMES: frozenset[str] = frozenset(
    [
        "bash_tool",
        "BashTool",
        "run_bash",
        "shell_tool",
        "ShellTool",
        "execute_command",
        "run_command",
        "subprocess_tool",
        "system_tool",
    ]
)

# Maximum lifetime for a scope decision (1 hour) and a capability token (5 min)
SCOPE_TTL_SECONDS: int = 3600
CAPABILITY_TTL_SECONDS: int = 300


# ---------------------------------------------------------------------------
# Agent tool validator — called before any agent is allowed to run
# ---------------------------------------------------------------------------

def validate_agent_tools(agent_name: str, tools: list) -> None:
    """
    Raise RuntimeError if any tool in the list is a forbidden shell tool.
    Call this before registering or running any ADK agent.

    Parameters
    ----------
    agent_name : name of the agent being registered
    tools      : list of tool functions or objects

    Raises
    ------
    RuntimeError if a forbidden shell tool is detected.
    """
    for tool in tools:
        name = getattr(tool, "__name__", None) or getattr(tool, "name", None) or str(tool)
        if name in FORBIDDEN_TOOL_NAMES:
            msg = (
                f"SECURITY VIOLATION: Agent '{agent_name}' attempted to register "
                f"forbidden shell tool '{name}'. "
                "Shell execution is permanently blocked by PolicyEngine. "
                "No agent may execute shell commands."
            )
            logger.error("shell_tool_blocked", agent=agent_name, tool=name)
            raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    campaign_id: str
    scope_id: str
    allowed_operations: list[str]
    denied_operations: list[str]
    expires_at: datetime
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class CapabilityGrant:
    granted: bool
    capability_token: str
    operation: str
    agent_id: str
    scope_id: str
    expires_at: datetime
    replay_nonce: str


@dataclass
class PolicyDenial:
    """Returned instead of CapabilityGrant when a capability request is rejected."""

    granted: bool
    reason: str
    operation: str
    agent_id: str
    scope_id: str
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Audit log (in-memory)
# ---------------------------------------------------------------------------

_AUDIT_LOG: list[dict] = []


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _audit(entry: dict) -> None:
    entry.setdefault("timestamp", _now().isoformat())
    _AUDIT_LOG.append(entry)


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """
    Deterministic policy engine for SENTINEL.

    Every method is pure (no side-effects beyond audit log) and must never
    raise an unhandled exception - failures always surface as a denial object.
    """

    # Scope registry: scope_id -> PolicyDecision (for capability validation)
    _scope_registry: dict[str, PolicyDecision]

    # Token registry: capability_token -> CapabilityGrant (for replay protection)
    _token_registry: dict[str, CapabilityGrant]

    def __init__(self) -> None:
        self._scope_registry = {}
        self._token_registry = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_scope(
        self,
        campaign_id: str,
        target: str,
        requested_ops: list[str],
    ) -> PolicyDecision:
        """
        Validate whether a campaign may operate against a target with the
        requested set of operations.

        Returns a PolicyDecision.  The decision is recorded in the audit log
        and, if allowed, registered in the internal scope registry so that
        subsequent capability requests can reference it.
        """
        try:
            return self._validate_scope_inner(campaign_id, target, requested_ops)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "validate_scope raised unexpected exception",
                campaign_id=campaign_id,
                target=target,
                exc=str(exc),
            )
            denial = PolicyDecision(
                allowed=False,
                reason=f"Internal policy error: {exc}",
                campaign_id=campaign_id,
                scope_id="",
                allowed_operations=[],
                denied_operations=list(requested_ops),
                expires_at=_now(),
            )
            self.record_decision(denial)
            return denial

    def _validate_scope_inner(
        self,
        campaign_id: str,
        target: str,
        requested_ops: list[str],
    ) -> PolicyDecision:
        scope_id = str(uuid.uuid4())

        # 1. Validate target
        if not self.validate_target(target):
            decision = PolicyDecision(
                allowed=False,
                reason=(
                    f"Target '{target}' is not in ALLOWED_TARGETS. "
                    "Only synthetic/owned targets are permitted."
                ),
                campaign_id=campaign_id,
                scope_id=scope_id,
                allowed_operations=[],
                denied_operations=list(requested_ops),
                expires_at=_now(),
            )
            self.record_decision(decision)
            logger.warning(
                "scope_denied:invalid_target",
                campaign_id=campaign_id,
                target=target,
                scope_id=scope_id,
            )
            return decision

        # 2. Partition requested operations
        allowed_ops: list[str] = []
        denied_ops: list[str] = []

        for op in requested_ops:
            if op in FORBIDDEN_OPERATIONS:
                denied_ops.append(op)
            elif op not in ALLOWED_OPERATIONS:
                denied_ops.append(op)
            else:
                allowed_ops.append(op)

        if denied_ops:
            decision = PolicyDecision(
                allowed=False,
                reason=(
                    f"Requested operations include forbidden/unknown items: {denied_ops}. "
                    "All operations must be in ALLOWED_OPERATIONS and none in FORBIDDEN_OPERATIONS."
                ),
                campaign_id=campaign_id,
                scope_id=scope_id,
                allowed_operations=allowed_ops,
                denied_operations=denied_ops,
                expires_at=_now(),
            )
            self.record_decision(decision)
            logger.warning(
                "scope_denied:forbidden_operations",
                campaign_id=campaign_id,
                target=target,
                denied_ops=denied_ops,
                scope_id=scope_id,
            )
            return decision

        # 3. All checks passed
        expires_at = _now() + timedelta(seconds=SCOPE_TTL_SECONDS)
        decision = PolicyDecision(
            allowed=True,
            reason="All targets and operations validated successfully.",
            campaign_id=campaign_id,
            scope_id=scope_id,
            allowed_operations=allowed_ops,
            denied_operations=[],
            expires_at=expires_at,
        )
        self._scope_registry[scope_id] = decision
        self.record_decision(decision)
        logger.info(
            "scope_granted",
            campaign_id=campaign_id,
            target=target,
            allowed_ops=allowed_ops,
            scope_id=scope_id,
            expires_at=expires_at.isoformat(),
        )
        return decision

    def validate_capability_request(
        self,
        agent_id: str,
        operation: str,
        scope_id: str,
    ) -> CapabilityGrant | PolicyDenial:
        """
        Grant a short-lived capability token to an agent for a single operation,
        if and only if the scope exists, has not expired, and permits the operation.

        Returns CapabilityGrant on success, PolicyDenial otherwise.
        """
        try:
            return self._validate_capability_inner(agent_id, operation, scope_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "validate_capability_request raised unexpected exception",
                agent_id=agent_id,
                operation=operation,
                scope_id=scope_id,
                exc=str(exc),
            )
            denial = PolicyDenial(
                granted=False,
                reason=f"Internal policy error: {exc}",
                operation=operation,
                agent_id=agent_id,
                scope_id=scope_id,
            )
            _audit(
                {
                    "event": "capability_denied",
                    "agent_id": agent_id,
                    "operation": operation,
                    "scope_id": scope_id,
                    "reason": denial.reason,
                    "decision_id": denial.decision_id,
                }
            )
            return denial

    def _validate_capability_inner(
        self,
        agent_id: str,
        operation: str,
        scope_id: str,
    ) -> CapabilityGrant | PolicyDenial:
        def deny(reason: str) -> PolicyDenial:
            d = PolicyDenial(
                granted=False,
                reason=reason,
                operation=operation,
                agent_id=agent_id,
                scope_id=scope_id,
            )
            _audit(
                {
                    "event": "capability_denied",
                    "agent_id": agent_id,
                    "operation": operation,
                    "scope_id": scope_id,
                    "reason": reason,
                    "decision_id": d.decision_id,
                }
            )
            logger.warning(
                "capability_denied",
                agent_id=agent_id,
                operation=operation,
                scope_id=scope_id,
                reason=reason,
            )
            return d

        # 1. Scope must exist
        scope = self._scope_registry.get(scope_id)
        if scope is None:
            return deny(f"scope_id '{scope_id}' does not exist or was never granted.")

        # 2. Scope must not be expired
        if _now() > scope.expires_at:
            return deny(
                f"scope_id '{scope_id}' expired at {scope.expires_at.isoformat()}."
            )

        # 3. Scope must have been allowed
        if not scope.allowed:
            return deny(
                f"scope_id '{scope_id}' was denied at policy validation time: {scope.reason}"
            )

        # 4. Operation must be in the scope's allowed operations
        if operation not in scope.allowed_operations:
            return deny(
                f"Operation '{operation}' is not in the allowed operations for scope '{scope_id}'. "
                f"Allowed: {scope.allowed_operations}"
            )

        # 5. Hard-block forbidden operations (defense-in-depth)
        if operation in FORBIDDEN_OPERATIONS:
            return deny(
                f"Operation '{operation}' is in FORBIDDEN_OPERATIONS and can never be granted."
            )

        # 6. Issue short-lived capability token
        expires_at = _now() + timedelta(seconds=CAPABILITY_TTL_SECONDS)
        token = str(uuid.uuid4())
        nonce = str(uuid.uuid4())

        grant = CapabilityGrant(
            granted=True,
            capability_token=token,
            operation=operation,
            agent_id=agent_id,
            scope_id=scope_id,
            expires_at=expires_at,
            replay_nonce=nonce,
        )
        self._token_registry[token] = grant

        _audit(
            {
                "event": "capability_granted",
                "agent_id": agent_id,
                "operation": operation,
                "scope_id": scope_id,
                "capability_token": token,
                "expires_at": expires_at.isoformat(),
            }
        )
        logger.info(
            "capability_granted",
            agent_id=agent_id,
            operation=operation,
            scope_id=scope_id,
            capability_token=token,
            expires_at=expires_at.isoformat(),
        )
        return grant

    def check_scope_drift(
        self,
        agent_id: str,
        original_scope: PolicyDecision,
        current_request: list[str],
    ) -> bool:
        """
        Return True (drift detected) if the current_request contains operations
        that were NOT in the original granted scope - i.e. the agent is attempting
        to exceed its authorised scope.

        Also returns True if the original scope itself was denied.
        """
        if not original_scope.allowed:
            logger.warning(
                "scope_drift_check:original_scope_was_denied",
                agent_id=agent_id,
                scope_id=original_scope.scope_id,
            )
            return True

        granted_set = set(original_scope.allowed_operations)
        requested_set = set(current_request)
        excess = requested_set - granted_set

        if excess:
            logger.warning(
                "scope_drift_detected",
                agent_id=agent_id,
                scope_id=original_scope.scope_id,
                excess_operations=list(excess),
            )
            _audit(
                {
                    "event": "scope_drift_detected",
                    "agent_id": agent_id,
                    "scope_id": original_scope.scope_id,
                    "original_ops": original_scope.allowed_operations,
                    "current_request": current_request,
                    "excess_operations": list(excess),
                }
            )
            return True

        return False

    def validate_target(self, target: str) -> bool:
        """Return True only if target is in ALLOWED_TARGETS."""
        return target in ALLOWED_TARGETS

    def record_decision(self, decision: PolicyDecision) -> str:
        """
        Persist a PolicyDecision to the in-memory audit log.
        Returns the decision_id.
        """
        _audit(
            {
                "event": "policy_decision",
                "decision_id": decision.decision_id,
                "campaign_id": decision.campaign_id,
                "scope_id": decision.scope_id,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "allowed_operations": decision.allowed_operations,
                "denied_operations": decision.denied_operations,
                "expires_at": decision.expires_at.isoformat(),
            }
        )
        return decision.decision_id

    # ------------------------------------------------------------------
    # Introspection helpers (not part of the core API)
    # ------------------------------------------------------------------

    def get_audit_log(self) -> list[dict]:
        """Return a copy of the full in-memory audit log."""
        return list(_AUDIT_LOG)

    def verify_token(self, capability_token: str) -> Optional[CapabilityGrant]:
        """
        Verify that a capability token is still valid (exists and not expired).
        Returns the CapabilityGrant or None.
        """
        grant = self._token_registry.get(capability_token)
        if grant is None:
            return None
        if _now() > grant.expires_at:
            return None
        return grant


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    engine = PolicyEngine()
    failures = 0

    # ------------------------------------------------------------------
    # Test 1: Valid scope and capability grant
    # ------------------------------------------------------------------
    print("\n[TEST 1] Valid target + allowed operations -> expect ALLOW")
    decision = engine.validate_scope(
        campaign_id="camp-001",
        target="synthetic-enterprise-001",
        requested_ops=["scan_ports", "check_tls", "generate_report"],
    )
    assert decision.allowed, f"Expected allowed=True, got: {decision.reason}"
    assert decision.scope_id in engine._scope_registry, "Scope not registered"

    cap = engine.validate_capability_request(
        agent_id="agent-alpha",
        operation="scan_ports",
        scope_id=decision.scope_id,
    )
    assert isinstance(cap, CapabilityGrant), f"Expected CapabilityGrant, got: {cap}"
    assert cap.granted, "Grant must be True"
    assert len(cap.capability_token) == 36, "Token must be a UUID"
    assert cap.expires_at > _now(), "Token must not be already expired"

    drift = engine.check_scope_drift(
        agent_id="agent-alpha",
        original_scope=decision,
        current_request=["scan_ports"],
    )
    assert not drift, "No drift expected for subset of original scope"
    print("  PASS: scope granted, capability issued, no scope drift")

    # ------------------------------------------------------------------
    # Test 2: Invalid (non-synthetic) target
    # ------------------------------------------------------------------
    print("\n[TEST 2] Real internet target -> expect DENY")
    decision2 = engine.validate_scope(
        campaign_id="camp-002",
        target="192.168.1.1",
        requested_ops=["scan_ports"],
    )
    assert not decision2.allowed, "Expected allowed=False for non-synthetic target"
    assert "ALLOWED_TARGETS" in decision2.reason, "Reason must mention ALLOWED_TARGETS"
    print(f"  PASS: denied with reason: {decision2.reason}")

    # ------------------------------------------------------------------
    # Test 3: Forbidden operation in request
    # ------------------------------------------------------------------
    print("\n[TEST 3] Forbidden operation 'exploit' -> expect DENY")
    decision3 = engine.validate_scope(
        campaign_id="camp-003",
        target="demo-target-alpha",
        requested_ops=["scan_ports", "exploit"],
    )
    assert not decision3.allowed, "Expected allowed=False for forbidden operation"
    assert "exploit" in decision3.denied_operations, "exploit must be in denied_operations"
    print(f"  PASS: denied with reason: {decision3.reason}")

    # ------------------------------------------------------------------
    # Test 4: Scope drift detection
    # ------------------------------------------------------------------
    print("\n[TEST 4] Scope drift: agent requests more than granted -> expect DRIFT")
    decision4 = engine.validate_scope(
        campaign_id="camp-004",
        target="test-env-isolated",
        requested_ops=["read_config"],
    )
    assert decision4.allowed
    drift4 = engine.check_scope_drift(
        agent_id="agent-rogue",
        original_scope=decision4,
        current_request=["read_config", "scan_ports", "generate_report"],
    )
    assert drift4, "Expected drift to be detected"
    print("  PASS: scope drift detected correctly")

    # ------------------------------------------------------------------
    # Test 5: Capability request with unknown scope_id
    # ------------------------------------------------------------------
    print("\n[TEST 5] Capability request with invalid scope_id -> expect DENIAL")
    cap5 = engine.validate_capability_request(
        agent_id="agent-beta",
        operation="check_tls",
        scope_id="nonexistent-scope-id",
    )
    assert isinstance(cap5, PolicyDenial), f"Expected PolicyDenial, got: {cap5}"
    assert not cap5.granted
    print(f"  PASS: denied with reason: {cap5.reason}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\nAudit log entries recorded: {len(engine.get_audit_log())}")
    print("All tests passed.\n")
    sys.exit(0)
