"""
BLACKBOX X-RAY — Agent Tools

Every tool is gated by PolicyEngine before execution.
Agents propose → Policy decides → Tool runs.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from core import evidence_store
from policy.engine import PolicyEngine, ALLOWED_OPERATIONS, FORBIDDEN_OPERATIONS

_policy = PolicyEngine()

# ── Shared scope registry per campaign ────────────────────────────────────
_active_scopes: dict[str, str] = {}  # campaign_id -> scope_id


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── SCANNER TOOLS ──────────────────────────────────────────────────────────

def scan_for_credentials(code: str, campaign_id: str) -> dict:
    """
    Scan code for hardcoded secrets: passwords, API keys, tokens.
    Returns findings list with severity and line hints.
    """
    patterns = [
        (r'password\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password", "CRITICAL"),
        (r'api[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key", "CRITICAL"),
        (r'secret[_-]?token\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret token", "CRITICAL"),
        (r'sk-[a-zA-Z0-9]{20,}', "Exposed API key pattern", "CRITICAL"),
        (r'eyJ[a-zA-Z0-9]{10,}', "Exposed JWT token", "HIGH"),
    ]
    findings = []
    for i, line in enumerate(code.splitlines(), 1):
        for pattern, label, severity in patterns:
            if re.search(pattern, line, re.I):
                snippet = line.strip()[:80]
                findings.append({
                    "id": f"CRED-{uuid.uuid4().hex[:6]}",
                    "category": "hardcoded_credentials",
                    "severity": severity,
                    "line_hint": i,
                    "description": label,
                    "evidence_snippet": snippet,
                })
    evidence_store.record(campaign_id, "tool_scan_credentials",
                          {"count": len(findings)})
    return {"findings": findings, "tool": "scan_for_credentials"}


def scan_for_injection_vulnerabilities(code: str, campaign_id: str) -> dict:
    """
    Detect SQL injection, path traversal, TLS bypass, and bare except patterns.
    """
    patterns = [
        (r'execute\(["\'].*\+.*["\']', "SQL injection: string concatenation in execute()", "CRITICAL"),
        (r'execute\(f["\']', "SQL injection: f-string in execute()", "CRITICAL"),
        (r'verify\s*=\s*False', "TLS verification disabled", "HIGH"),
        (r'open\(.*\+.*\)', "Potential path traversal in open()", "HIGH"),
        (r'except:\s*$|except:\s*#', "Bare except swallows all errors", "MEDIUM"),
        (r'hashlib\.md5|hashlib\.sha1', "Broken hash algorithm", "HIGH"),
        (r'logger\.(debug|info)\(.*password|logger\.(debug|info)\(.*pw', "Credential in log", "HIGH"),
    ]
    findings = []
    for i, line in enumerate(code.splitlines(), 1):
        for pattern, label, severity in patterns:
            if re.search(pattern, line, re.I):
                findings.append({
                    "id": f"INJ-{uuid.uuid4().hex[:6]}",
                    "category": "injection_vulnerability",
                    "severity": severity,
                    "line_hint": i,
                    "description": label,
                    "evidence_snippet": line.strip()[:80],
                })
    evidence_store.record(campaign_id, "tool_scan_injection",
                          {"count": len(findings)})
    return {"findings": findings, "tool": "scan_for_injection_vulnerabilities"}


# ── EVIDENCE TOOLS ─────────────────────────────────────────────────────────

def record_and_sign_finding(finding: dict, campaign_id: str) -> dict:
    """
    Cryptographically record a finding. Returns evidence_ref and fingerprint.
    """
    raw = json.dumps(finding, sort_keys=True)
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()
    ref = evidence_store.record(campaign_id, "signed_finding", {
        "finding": finding,
        "fingerprint": fingerprint,
    })
    return {
        "evidence_ref": ref,
        "fingerprint": fingerprint,
        "recorded_at": _ts(),
    }


def build_chain_of_custody(evidence_refs: list, campaign_id: str) -> dict:
    """
    Build a chain of custody from a list of evidence refs.
    Returns chain hash for audit trail.
    """
    chain_input = "|".join(sorted(evidence_refs))
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
    evidence_store.record(campaign_id, "chain_of_custody", {
        "refs": evidence_refs,
        "chain_hash": chain_hash,
    })
    return {
        "chain_hash": chain_hash,
        "ref_count": len(evidence_refs),
        "built_at": _ts(),
    }


# ── ADVERSARIAL TOOLS ──────────────────────────────────────────────────────

def check_finding_for_false_positive(finding_description: str,
                                     evidence_snippet: str,
                                     campaign_id: str) -> dict:
    """
    Apply heuristics to determine if a finding might be a false positive.
    Returns falsified=True if evidence is insufficient.
    """
    weak_signals = [
        len(evidence_snippet) < 5,
        "test" in evidence_snippet.lower(),
        "mock" in evidence_snippet.lower(),
        "example" in evidence_snippet.lower(),
    ]
    is_false_positive = sum(weak_signals) >= 2

    evidence_store.record(campaign_id, "adversarial_check", {
        "description": finding_description,
        "falsified": is_false_positive,
    })
    return {
        "falsified": is_false_positive,
        "reason": "Weak evidence or test context" if is_false_positive else "Sufficient evidence",
        "confidence": 0.3 if is_false_positive else 0.9,
    }


# ── PATCH TOOLS ────────────────────────────────────────────────────────────

def assess_patch_risk(finding_category: str, severity: str) -> dict:
    """
    Assess the risk level of applying an automated patch.
    Returns risk score and whether human approval is required.
    """
    risk_table = {
        ("hardcoded_credentials", "CRITICAL"): 0.15,
        ("injection_vulnerability", "CRITICAL"): 0.35,
        ("injection_vulnerability", "HIGH"): 0.25,
        ("injection_vulnerability", "MEDIUM"): 0.10,
    }
    risk = risk_table.get((finding_category, severity), 0.20)
    return {
        "risk_score": risk,
        "requires_human_approval": risk > 0.20,
        "automation_level": "safe" if risk <= 0.10 else ("semi" if risk <= 0.20 else "human-only"),
    }


# ── CLEANUP TOOLS ──────────────────────────────────────────────────────────

def verify_environment_cleanup(campaign_id: str, scope_id: str) -> dict:
    """
    Verify the test environment is clean after a campaign.
    Checks evidence store for any unresolved artefacts.
    """
    entries = evidence_store.get_campaign(campaign_id)
    unresolved = [e for e in entries
                  if e["event_type"] not in {
                      "campaign_start", "signed_finding", "chain_of_custody",
                      "adversarial_check", "verification_complete",
                      "campaign_end", "tool_scan_credentials",
                      "tool_scan_injection", "cleanup_verified",
                      "policy_decision",
                  }]
    clean = len(unresolved) == 0
    evidence_store.record(campaign_id, "cleanup_verified", {
        "clean": clean,
        "unresolved_count": len(unresolved),
        "scope_id": scope_id,
    })
    return {
        "cleanup_complete": clean,
        "remaining_artifacts": [e["event_type"] for e in unresolved],
        "verified_at": _ts(),
    }
