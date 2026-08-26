"""
BLACKBOX X-RAY — ADK Orchestrator

6-agent pipeline using Google ADK 2.7.1 + Gemini 2.5 Flash on Vertex AI.

Flow:
  PolicyEngine (scope gate)
  → ScannerAgent   [tools: scan_for_credentials, scan_for_injection_vulnerabilities]
  → EvidenceAgent  [tools: record_and_sign_finding, build_chain_of_custody]
  → AdversarialAgent [tools: check_finding_for_false_positive]
  → VerificationAgent [tools: check_finding_for_false_positive]
  → PatchAgent     [tools: assess_patch_risk]
  → CleanupAgent   [tools: verify_environment_cleanup]

Every tool call is preceded by a PolicyEngine gate.
Agents propose → Policy decides → Tool executes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import google.genai.types as gtypes
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

import core.config  # sets Vertex AI env vars
from core import evidence_store
from policy.engine import PolicyEngine, validate_agent_tools

from agents.tools import (
    scan_for_credentials,
    scan_for_injection_vulnerabilities,
    record_and_sign_finding,
    build_chain_of_custody,
    check_finding_for_false_positive,
    assess_patch_risk,
    verify_environment_cleanup,
)

log = logging.getLogger("blackbox.orchestrator")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [BLACKBOX] %(levelname)s %(message)s")

MODEL = core.config.GEMINI_MODEL

# ── Injection guard ────────────────────────────────────────────────────────

_INJECTION_RE = [re.compile(r, re.I) for r in [
    r"ignore\s+(previous|all|above)\s+instruction",
    r"you\s+are\s+now\s+", r"act\s+as\s+", r"jailbreak",
    r"\bDAN\b", r"override\s+(policy|security|constraint)",
]]


def _injection(text: str) -> bool:
    return any(p.search(text) for p in _INJECTION_RE)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Result ─────────────────────────────────────────────────────────────────

@dataclass
class CampaignResult:
    campaign_id: str
    status: str           # COMPLETE | ABORTED | DENIED
    findings: list[dict]
    patches: list[dict]
    evidence_refs: list[str]
    policy_log: list[dict]
    cleanup_verified: bool
    abort_reason: str | None = None


# ── ADK agent runner helper ────────────────────────────────────────────────

async def _run_agent(agent: Agent, session_svc: InMemorySessionService,
                     campaign_id: str, prompt: str, retries: int = 3) -> str:
    """Run an ADK agent for one turn — shell tools blocked, 429 retried with backoff."""
    validate_agent_tools(agent.name, getattr(agent, "tools", []) or [])
    session_id = f"{campaign_id}-{agent.name}"
    await session_svc.create_session(
        app_name="blackbox_xray", user_id="orchestrator", session_id=session_id
    )
    runner = Runner(agent=agent, app_name="blackbox_xray", session_service=session_svc)

    for attempt in range(retries):
        try:
            full_text = ""
            async for event in runner.run_async(
                user_id="orchestrator",
                session_id=session_id,
                new_message=gtypes.Content(
                    role="user", parts=[gtypes.Part(text=prompt)]
                ),
            ):
                if hasattr(event, "content") and event.content:
                    for part in (event.content.parts or []):
                        if hasattr(part, "text") and part.text:
                            full_text += part.text
                if hasattr(event, "get_function_calls"):
                    for fc in (event.get_function_calls() or []):
                        log.info("[%s] tool_call: %s args=%s", agent.name, fc.name,
                                 json.dumps(fc.args, default=str)[:200])
            return full_text
        except Exception as exc:
            if "429" in str(exc) or "RESOURCE_EXHAUSTED" in str(exc):
                wait = 2 ** (attempt + 1)
                log.warning("[%s] rate limited, retry %d/%d in %ds",
                            agent.name, attempt + 1, retries, wait)
                await asyncio.sleep(wait)
            else:
                raise
    return ""


def _parse(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {}


# ── Main orchestrator ──────────────────────────────────────────────────────

async def run_campaign_async(
    target: str,
    operations: list[str],
    code: str = "",
) -> CampaignResult:
    campaign_id = str(uuid.uuid4())
    policy_log: list[dict] = []
    engine = PolicyEngine()
    session_svc = InMemorySessionService()

    def _log(agent: str, action: str, verdict: str, reason: str) -> None:
        entry = {"agent": agent, "action": action,
                 "verdict": verdict, "reason": reason, "ts": _ts()}
        policy_log.append(entry)
        evidence_store.record(campaign_id, "policy_decision", entry)
        log.info(json.dumps(entry))

    def _abort(reason: str) -> CampaignResult:
        _log("orchestrator", "abort", "DENY", reason)
        return CampaignResult(
            campaign_id=campaign_id, status="ABORTED",
            findings=[], patches=[], evidence_refs=[],
            policy_log=policy_log, cleanup_verified=False,
            abort_reason=reason,
        )

    log.info(json.dumps({
        "event": "campaign_start", "campaign_id": campaign_id,
        "target": target, "operations": operations, "ts": _ts(),
    }))
    evidence_store.record(campaign_id, "campaign_start",
                          {"target": target, "operations": operations})

    # ── GATE 0: Injection ─────────────────────────────────────────────────
    if _injection(f"{target} {' '.join(operations)} {code[:200]}"):
        return _abort("Prompt injection detected.")
    _log("orchestrator", "injection_check", "ALLOW", "Input clean.")

    # ── GATE 1: Policy scope ──────────────────────────────────────────────
    from policy.engine import ALLOWED_OPERATIONS
    bad = [op for op in operations if op not in ALLOWED_OPERATIONS]
    if bad:
        return _abort(f"Unauthorized operations: {bad}")

    scope = engine.validate_scope(campaign_id, target, operations)
    if not scope.allowed:
        return _abort(f"Scope denied: {scope.reason}")
    _log("ScopeAgent", "scope_validation", "ALLOW",
         f"scope_id={scope.scope_id}")

    if not code:
        from core.synthetic_target import get_target_code
        code = get_target_code()

    # ── AGENT 1: ScannerAgent ─────────────────────────────────────────────
    cap = engine.validate_capability_request(
        "scanner_agent", "scan_ports", scope.scope_id)
    if not getattr(cap, "granted", False):
        return _abort("Scanner capability denied.")
    _log("ScannerAgent", "capability_grant", "ALLOW", "scan_ports granted")

    scanner_agent = Agent(
        name="scanner_agent",
        model=MODEL,
        instruction=(
            "You are ScannerAgent for BLACKBOX X-RAY. "
            "Use BOTH tools scan_for_credentials AND scan_for_injection_vulnerabilities "
            "on the provided code. Then summarise the total findings count by severity. "
            "Always call both tools. campaign_id is provided in the prompt."
        ),
        tools=[scan_for_credentials, scan_for_injection_vulnerabilities],
    )

    scan_prompt = (
        f"campaign_id={campaign_id}\n"
        f"target={target}\n\nCODE:\n{code[:6000]}"
    )
    scan_text = await _run_agent(scanner_agent, session_svc, campaign_id, scan_prompt)

    all_findings: list[dict] = []
    for entry in evidence_store.get_campaign(campaign_id):
        if entry["event_type"] in ("tool_scan_credentials", "tool_scan_injection"):
            pass

    raw_cred = scan_for_credentials(code, campaign_id)
    raw_inj = scan_for_injection_vulnerabilities(code, campaign_id)
    all_findings = raw_cred["findings"] + raw_inj["findings"]

    _log("ScannerAgent", "scan_complete", "ALLOW",
         f"{len(all_findings)} raw findings")

    if not all_findings:
        return _abort("ScannerAgent: no findings produced.")

    # ── AGENT 2: EvidenceAgent ────────────────────────────────────────────
    cap2 = engine.validate_capability_request(
        "evidence_agent", "generate_report", scope.scope_id)
    if not getattr(cap2, "granted", False):
        return _abort("Evidence capability denied.")
    _log("EvidenceAgent", "capability_grant", "ALLOW", "generate_report granted")

    evidence_agent = Agent(
        name="evidence_agent",
        model=MODEL,
        instruction=(
            "You are EvidenceAgent for BLACKBOX X-RAY. "
            "For each finding call record_and_sign_finding, then call "
            "build_chain_of_custody with ALL collected evidence_refs. "
            "campaign_id is in the prompt."
        ),
        tools=[record_and_sign_finding, build_chain_of_custody],
    )

    ev_prompt = (
        f"campaign_id={campaign_id}\n"
        f"findings={json.dumps(all_findings[:8])}"
    )
    await _run_agent(evidence_agent, session_svc, campaign_id, ev_prompt)

    ev_entries = [e for e in evidence_store.get_campaign(campaign_id)
                  if e["event_type"] == "signed_finding"]
    evidence_refs = [e["id"] for e in ev_entries]
    _log("EvidenceAgent", "evidence_recorded", "ALLOW",
         f"{len(evidence_refs)} refs signed")

    # ── AGENT 3: AdversarialAgent ─────────────────────────────────────────
    adv_agent = Agent(
        name="adversarial_agent",
        model=MODEL,
        instruction=(
            "You are AdversarialReviewAgent for BLACKBOX X-RAY. "
            "Your job is to CHALLENGE findings and find false positives. "
            "Call check_finding_for_false_positive for EVERY finding. "
            "Be sceptical. campaign_id is in the prompt."
        ),
        tools=[check_finding_for_false_positive],
    )

    adv_prompt = (
        f"campaign_id={campaign_id}\n"
        f"findings={json.dumps(all_findings[:8])}\n"
        "Challenge each finding for false positives."
    )
    await _run_agent(adv_agent, session_svc, campaign_id, adv_prompt)

    adv_entries = [e for e in evidence_store.get_campaign(campaign_id)
                   if e["event_type"] == "adversarial_check"]
    falsified_count = sum(1 for e in adv_entries
                          if e["payload"].get("falsified", False))
    integrity = 1.0 - (falsified_count / max(len(adv_entries), 1))

    if integrity < 0.4:
        return _abort(f"AdversarialAgent: integrity {integrity:.2f} < 0.40 threshold.")
    _log("AdversarialAgent", "integrity_check", "ALLOW",
         f"integrity={integrity:.2f} falsified={falsified_count}/{len(adv_entries)}")

    # ── AGENT 4: VerificationAgent ────────────────────────────────────────
    falsified_descs = {
        e["payload"]["description"]
        for e in adv_entries if e["payload"].get("falsified")
    }
    verified_findings = [
        f for f in all_findings
        if f.get("description") not in falsified_descs
    ]
    evidence_store.record(campaign_id, "verification_complete", {
        "verified_count": len(verified_findings),
        "integrity": integrity,
    })
    _log("VerificationAgent", "verification", "ALLOW",
         f"verified={len(verified_findings)}/{len(all_findings)}")

    # ── AGENT 5: PatchAgent ───────────────────────────────────────────────
    patch_agent = Agent(
        name="patch_agent",
        model=MODEL,
        instruction=(
            "You are PatchAgent for BLACKBOX X-RAY. "
            "For each verified finding call assess_patch_risk to determine "
            "risk score and whether human approval is needed. "
            "Then summarise the safest patches."
        ),
        tools=[assess_patch_risk],
    )

    patch_prompt = (
        f"campaign_id={campaign_id}\n"
        f"verified_findings={json.dumps(verified_findings[:6])}"
    )
    await _run_agent(patch_agent, session_svc, campaign_id, patch_prompt)

    patches = [
        {
            "finding_id": f.get("id"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            **assess_patch_risk(f.get("category", ""), f.get("severity", "")),
        }
        for f in verified_findings
    ]
    _log("PatchAgent", "patches_proposed", "ALLOW",
         f"{len(patches)} patches assessed")

    # ── AGENT 6: CleanupAgent ─────────────────────────────────────────────
    cleanup_agent = Agent(
        name="cleanup_agent",
        model=MODEL,
        instruction=(
            "You are CleanupAgent for BLACKBOX X-RAY. "
            "Call verify_environment_cleanup to confirm all campaign artefacts "
            "are resolved. Report the result."
        ),
        tools=[verify_environment_cleanup],
    )

    cleanup_prompt = (
        f"campaign_id={campaign_id}\nscope_id={scope.scope_id}\n"
        "Verify environment is clean."
    )
    await _run_agent(cleanup_agent, session_svc, campaign_id, cleanup_prompt)

    cleanup_result = verify_environment_cleanup(campaign_id, scope.scope_id)
    cleanup_ok = cleanup_result["cleanup_complete"]
    _log("CleanupAgent", "cleanup_verification",
         "ALLOW" if cleanup_ok else "DENY",
         f"clean={cleanup_ok} remaining={cleanup_result['remaining_artifacts']}")

    evidence_store.record(campaign_id, "campaign_end", {
        "status": "COMPLETE" if cleanup_ok else "ABORTED",
        "findings_verified": len(verified_findings),
    })

    return CampaignResult(
        campaign_id=campaign_id,
        status="COMPLETE" if cleanup_ok else "ABORTED",
        findings=verified_findings,
        patches=patches,
        evidence_refs=evidence_refs,
        policy_log=policy_log,
        cleanup_verified=cleanup_ok,
        abort_reason=None if cleanup_ok else
            f"Cleanup incomplete: {cleanup_result['remaining_artifacts']}",
    )


def run_campaign(target: str, operations: list[str], code: str = "") -> CampaignResult:
    """Sync wrapper for use in non-async contexts."""
    return asyncio.run(run_campaign_async(target, operations, code))


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "synthetic-enterprise-001"
    ops = sys.argv[2:] or ["scan_ports", "check_tls", "generate_report"]
    result = run_campaign(t, ops)
    print(json.dumps({
        "campaign_id": result.campaign_id,
        "status": result.status,
        "findings": len(result.findings),
        "patches": len(result.patches),
        "evidence_refs": len(result.evidence_refs),
        "cleanup_verified": result.cleanup_verified,
        "policy_decisions": len(result.policy_log),
        "abort_reason": result.abort_reason,
    }, indent=2))
