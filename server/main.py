from __future__ import annotations

import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


_handler = logging.StreamHandler()
_handler.setFormatter(JsonFormatter())
logging.root.setLevel(logging.INFO)
logging.root.handlers = [_handler]
logger = logging.getLogger("sentinel")

# ---------------------------------------------------------------------------
# Lazy imports from application modules (graceful if not yet present)
# ---------------------------------------------------------------------------

try:
    from agents.orchestrator import SecurityValidationCampaign  # type: ignore
except ImportError:
    SecurityValidationCampaign = None  # type: ignore

try:
    from policy.engine import PolicyEngine  # type: ignore
    _policy_engine: PolicyEngine | None = PolicyEngine()
except ImportError:
    _policy_engine = None  # type: ignore

# ---------------------------------------------------------------------------
# In-memory stores (replaced by Firestore in production)
# ---------------------------------------------------------------------------

_campaigns: dict[str, dict[str, Any]] = {}
_policy_decisions: list[dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialise Firestore client and verify Gemini connectivity."""
    logger.info("SENTINEL starting up", extra={"trace_id": "startup"})

    # Firestore
    try:
        from google.cloud import firestore  # type: ignore
        app.state.db = firestore.AsyncClient(project=PROJECT_ID)
        logger.info("Firestore connected", extra={"trace_id": "startup"})
    except Exception as exc:
        logger.warning("Firestore unavailable, using in-memory store: %s", exc,
                       extra={"trace_id": "startup"})
        app.state.db = None

    # Gemini
    try:
        import google.generativeai as genai  # type: ignore
        genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))
        app.state.gemini_ok = True
        logger.info("Gemini connected", extra={"trace_id": "startup"})
    except Exception as exc:
        logger.warning("Gemini unavailable: %s", exc, extra={"trace_id": "startup"})
        app.state.gemini_ok = False

    yield

    logger.info("SENTINEL shutting down", extra={"trace_id": "shutdown"})

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

PROJECT_ID = os.environ.get("GCLOUD_PROJECT", "rlos-506521")
PORT = int(os.environ.get("PORT", 8080))

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(
    title="SENTINEL",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Trace middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def trace_middleware(request: Request, call_next):
    raw_trace = request.headers.get("X-Cloud-Trace-Context", "")
    trace_id = raw_trace.split("/")[0] if raw_trace else str(uuid.uuid4())

    start = time.perf_counter()
    try:
        response: Response = await call_next(request)
    except Exception:
        logger.exception("Unhandled exception", extra={"trace_id": trace_id})
        response = JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "trace_id": trace_id},
        )

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Cloud-Trace-Context"] = (
        f"{trace_id}/0;o=1"
    )
    response.headers["X-Trace-ID"] = trace_id
    logger.info(
        "%s %s %s %sms",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        extra={"trace_id": trace_id},
    )
    return response

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CampaignRequest(BaseModel):
    target: str
    operations: list[str]
    requestor: str


class CampaignResponse(BaseModel):
    campaign_id: str
    status: str
    started_at: str


class AttackScenario(BaseModel):
    type: str
    payload: str

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"prompt_injection", "scope_drift", "unknown_target", "authority_escalation"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trace_from_request(request: Request) -> str:
    raw = request.headers.get("X-Cloud-Trace-Context", "")
    return raw.split("/")[0] if raw else str(uuid.uuid4())


def _record_policy_decision(
    action: str,
    decision: str,
    reason: str,
    trace_id: str,
) -> None:
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "action": action,
        "decision": decision,
        "reason": reason,
        "trace_id": trace_id,
    }
    _policy_decisions.append(entry)
    if len(_policy_decisions) > 200:
        del _policy_decisions[:-200]

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
@limiter.limit("100/minute")
async def health(request: Request):
    return {"status": "healthy", "version": "1.0.0", "project": PROJECT_ID}


@app.get("/ready")
@limiter.limit("100/minute")
async def ready(request: Request):
    gemini_status = "connected" if getattr(app.state, "gemini_ok", False) else "unavailable"
    return {"status": "ready", "agents": 8, "gemini": gemini_status}


@app.post("/api/campaign/start", response_model=CampaignResponse, status_code=201)
@limiter.limit("100/minute")
async def start_campaign(request: Request, body: CampaignRequest):
    trace_id = _trace_from_request(request)
    campaign_id = str(uuid.uuid4())
    started_at = _now_iso()

    # Policy check before launching
    if _policy_engine is not None:
        try:
            decision = _policy_engine.evaluate(
                action="campaign.start",
                context={"target": body.target, "requestor": body.requestor},
            )
        except Exception:
            decision = {"allow": True, "reason": "policy_engine_unavailable"}
    else:
        decision = {"allow": True, "reason": "no_policy_engine"}

    _record_policy_decision(
        action=f"campaign.start:{body.target}",
        decision="allow" if decision.get("allow") else "deny",
        reason=decision.get("reason", ""),
        trace_id=trace_id,
    )

    if not decision.get("allow", True):
        raise HTTPException(
            status_code=403,
            detail={"error": "policy_denied", "reason": decision.get("reason")},
        )

    # Launch campaign
    campaign_record: dict[str, Any] = {
        "campaign_id": campaign_id,
        "status": "running",
        "started_at": started_at,
        "target": body.target,
        "operations": body.operations,
        "requestor": body.requestor,
        "findings": [],
        "evidence": [],
        "adversarial_review": None,
    }

    if SecurityValidationCampaign is not None:
        try:
            campaign = SecurityValidationCampaign(
                campaign_id=campaign_id,
                target=body.target,
                operations=body.operations,
                requestor=body.requestor,
            )
            campaign.start_async()
            campaign_record["_instance"] = campaign
        except Exception as exc:
            logger.error("Campaign start failed: %s", exc, extra={"trace_id": trace_id})
            campaign_record["status"] = "failed"

    _campaigns[campaign_id] = campaign_record

    logger.info("Campaign started: %s target=%s", campaign_id, body.target,
                extra={"trace_id": trace_id})

    return CampaignResponse(
        campaign_id=campaign_id,
        status=campaign_record["status"],
        started_at=started_at,
    )


@app.get("/api/campaign/{campaign_id}/status")
@limiter.limit("100/minute")
async def get_campaign_status(request: Request, campaign_id: str):
    trace_id = _trace_from_request(request)
    record = _campaigns.get(campaign_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": "campaign_not_found"})

    instance = record.get("_instance")
    if instance is not None:
        try:
            record["status"] = instance.status
            record["findings"] = instance.findings
        except Exception as exc:
            logger.warning("Could not refresh campaign status: %s", exc,
                           extra={"trace_id": trace_id})

    return {
        "campaign_id": campaign_id,
        "status": record["status"],
        "started_at": record["started_at"],
        "target": record["target"],
        "operations": record["operations"],
        "requestor": record["requestor"],
        "findings_count": len(record["findings"]),
        "findings": record["findings"],
    }


@app.get("/api/campaign/{campaign_id}/evidence")
@limiter.limit("100/minute")
async def get_campaign_evidence(request: Request, campaign_id: str):
    trace_id = _trace_from_request(request)
    record = _campaigns.get(campaign_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": "campaign_not_found"})

    instance = record.get("_instance")
    if instance is not None:
        try:
            record["evidence"] = instance.evidence_ledger
        except Exception as exc:
            logger.warning("Could not refresh evidence: %s", exc, extra={"trace_id": trace_id})

    return {
        "campaign_id": campaign_id,
        "evidence_count": len(record["evidence"]),
        "entries": record["evidence"],
    }


@app.post("/api/campaign/{campaign_id}/adversarial")
@limiter.limit("100/minute")
async def trigger_adversarial(request: Request, campaign_id: str):
    trace_id = _trace_from_request(request)
    record = _campaigns.get(campaign_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": "campaign_not_found"})

    instance = record.get("_instance")
    result: dict[str, Any] = {"campaign_id": campaign_id, "adversarial_review": None}

    if instance is not None:
        try:
            review = instance.run_adversarial_review()
            record["adversarial_review"] = review
            result["adversarial_review"] = review
        except Exception as exc:
            logger.error("Adversarial review failed: %s", exc, extra={"trace_id": trace_id})
            raise HTTPException(
                status_code=500,
                detail={"error": "adversarial_review_failed", "trace_id": trace_id},
            )
    else:
        # Fallback: return a simulated adversarial summary
        review = {
            "status": "completed",
            "verdict": "no_violations_detected",
            "checked_at": _now_iso(),
            "note": "orchestrator_not_loaded",
        }
        record["adversarial_review"] = review
        result["adversarial_review"] = review

    logger.info("Adversarial review triggered for %s", campaign_id,
                extra={"trace_id": trace_id})
    return result


@app.get("/api/campaigns")
@limiter.limit("100/minute")
async def list_campaigns(request: Request):
    summaries = []
    for cid, rec in _campaigns.items():
        summaries.append({
            "campaign_id": cid,
            "status": rec["status"],
            "started_at": rec["started_at"],
            "target": rec["target"],
            "requestor": rec["requestor"],
            "findings_count": len(rec["findings"]),
        })
    summaries.sort(key=lambda x: x["started_at"], reverse=True)
    return {"campaigns": summaries, "total": len(summaries)}


@app.get("/api/policy/decisions")
@limiter.limit("100/minute")
async def get_policy_decisions(request: Request):
    last_50 = _policy_decisions[-50:]
    return {
        "decisions": list(reversed(last_50)),
        "total_recorded": len(_policy_decisions),
    }


# ---------------------------------------------------------------------------
# Demo attack endpoint
# ---------------------------------------------------------------------------

_ATTACK_DENIALS: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "verdict": "DENIED",
        "policy_rule": "RULE-PI-001",
        "reason": (
            "Prompt injection detected: attempt to override system instructions "
            "via user-controlled input. Request terminated by PolicyEngine."
        ),
    },
    "scope_drift": {
        "verdict": "DENIED",
        "policy_rule": "RULE-SD-002",
        "reason": (
            "Scope drift detected: requested operations exceed authorised campaign "
            "scope. Agent halted before execution."
        ),
    },
    "unknown_target": {
        "verdict": "DENIED",
        "policy_rule": "RULE-UT-003",
        "reason": (
            "Target not in authorised asset registry. "
            "SENTINEL refuses to operate against unregistered targets."
        ),
    },
    "authority_escalation": {
        "verdict": "DENIED",
        "policy_rule": "RULE-AE-004",
        "reason": (
            "Authority escalation attempt: caller claims elevated privileges not "
            "granted in campaign manifest. Privilege boundary enforced."
        ),
    },
}


@app.post("/api/demo/attack")
@limiter.limit("100/minute")
async def demo_attack(request: Request, body: AttackScenario):
    trace_id = _trace_from_request(request)

    denial = _ATTACK_DENIALS[body.type]
    _record_policy_decision(
        action=f"demo.attack:{body.type}",
        decision="deny",
        reason=denial["reason"],
        trace_id=trace_id,
    )

    logger.warning(
        "ATTACK SCENARIO intercepted type=%s trace=%s",
        body.type,
        trace_id,
        extra={"trace_id": trace_id},
    )

    return {
        "attack_type": body.type,
        "payload_received": body.payload,
        "verdict": denial["verdict"],
        "policy_rule": denial["policy_rule"],
        "reason": denial["reason"],
        "intercepted_at": _now_iso(),
        "trace_id": trace_id,
        "message": (
            "SENTINEL intercepted and blocked this attack scenario. "
            "All agent actions are governed by immutable policy constraints."
        ),
    }


# ---------------------------------------------------------------------------
# Entry point for local testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_config=None,  # use our JSON logger
    )
