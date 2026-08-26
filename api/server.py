"""BLACKBOX X-RAY — FastAPI server."""
from __future__ import annotations

import json
import logging
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


def _get_real_ip(request: Request) -> str:
    """Cloud Run forwards real IP in X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)

from core.config import PROJECT_ID, PORT
from core import evidence_store
from policy.engine import PolicyEngine, ALLOWED_OPERATIONS

# ── Logging ────────────────────────────────────────────────────────────────

class _JsonFmt(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        return json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": r.levelname,
            "msg": r.getMessage(),
            "logger": r.name,
            **({} if not r.exc_info else {"exc": self.formatException(r.exc_info)}),
        })

_h = logging.StreamHandler()
_h.setFormatter(_JsonFmt())
logging.root.handlers = [_h]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("blackbox.api")

# ── App ────────────────────────────────────────────────────────────────────

_policy = PolicyEngine()
_campaigns: dict[str, dict[str, Any]] = {}
limiter = Limiter(key_func=_get_real_ip, default_limits=["100/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("BLACKBOX X-RAY starting — project=%s", PROJECT_ID)
    yield
    logger.info("BLACKBOX X-RAY shutting down")


app = FastAPI(
    title="BLACKBOX X-RAY",
    version="2.0.0",
    description="Enterprise Agent Security Control Plane",
    docs_url="/docs",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def _trace(request: Request, call_next) -> Response:
    raw = request.headers.get("X-Cloud-Trace-Context", "")
    tid = raw.split("/")[0] if raw else str(uuid.uuid4())
    t0 = time.perf_counter()
    try:
        resp: Response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error trace=%s", tid)
        resp = JSONResponse(status_code=500, content={"error": "internal_error", "trace_id": tid})
    ms = round((time.perf_counter() - t0) * 1000, 1)
    resp.headers["X-Trace-ID"] = tid
    logger.info("%s %s %s %sms trace=%s",
                request.method, request.url.path, resp.status_code, ms, tid)
    return resp


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Pydantic models ────────────────────────────────────────────────────────

class CampaignReq(BaseModel):
    target: str
    operations: list[str]
    requestor: str = "api"
    code: str = ""

class AttackScenario(BaseModel):
    type: str
    payload: str

    @field_validator("type")
    @classmethod
    def _check(cls, v: str) -> str:
        allowed = {"prompt_injection", "scope_drift", "unknown_target", "authority_escalation"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/health")
@limiter.limit("200/minute")
async def health(request: Request):
    return {"status": "healthy", "version": "2.0.0", "project": PROJECT_ID}


@app.get("/ready")
@limiter.limit("200/minute")
async def ready(request: Request):
    return {"status": "ready", "agents": 6, "store": "sqlite"}


@app.post("/api/campaign/start", status_code=201)
@limiter.limit("20/minute")
async def start_campaign(request: Request, body: CampaignReq):
    bad_ops = [op for op in body.operations if op not in ALLOWED_OPERATIONS]
    if bad_ops:
        raise HTTPException(403, detail={"error": "unauthorized_operations", "ops": bad_ops})

    scope = _policy.validate_scope(str(uuid.uuid4()), body.target, body.operations)
    if not scope.allowed:
        raise HTTPException(403, detail={"error": "scope_denied", "reason": scope.reason})

    campaign_id = str(uuid.uuid4())
    started_at = _now()

    _campaigns[campaign_id] = {
        "status": "running",
        "started_at": started_at,
        "target": body.target,
        "operations": body.operations,
        "requestor": body.requestor,
        "findings": [],
        "patches": [],
        "evidence_refs": [],
        "policy_log": [],
        "cleanup_verified": False,
    }

    import asyncio

    async def _run():
        try:
            from agents.orchestrator import run_campaign
            result = await asyncio.to_thread(
                run_campaign, body.target, body.operations, body.code
            )
            rec = _campaigns.get(campaign_id, {})
            rec.update({
                "status": result.status,
                "findings": result.findings,
                "patches": result.patches,
                "evidence_refs": result.evidence_refs,
                "policy_log": result.policy_log,
                "cleanup_verified": result.cleanup_verified,
                "abort_reason": result.abort_reason,
            })
        except Exception as exc:
            logger.exception("Campaign %s failed: %s", campaign_id, exc)
            if campaign_id in _campaigns:
                _campaigns[campaign_id]["status"] = "failed"
                _campaigns[campaign_id]["abort_reason"] = str(exc)

    asyncio.create_task(_run())

    return {"campaign_id": campaign_id, "status": "running", "started_at": started_at}


@app.get("/api/campaign/{campaign_id}/status")
@limiter.limit("100/minute")
async def campaign_status(request: Request, campaign_id: str):
    rec = _campaigns.get(campaign_id)
    if not rec:
        raise HTTPException(404, detail={"error": "not_found"})
    return {
        "campaign_id": campaign_id,
        **{k: v for k, v in rec.items() if k != "policy_log"},
        "findings_count": len(rec["findings"]),
        "patches_count": len(rec["patches"]),
    }


@app.get("/api/campaign/{campaign_id}/evidence")
@limiter.limit("100/minute")
async def campaign_evidence(request: Request, campaign_id: str):
    if campaign_id not in _campaigns:
        raise HTTPException(404, detail={"error": "not_found"})
    entries = evidence_store.get_campaign(campaign_id)
    return {"campaign_id": campaign_id, "entries": entries, "count": len(entries)}


@app.get("/api/campaign/{campaign_id}/policy")
@limiter.limit("100/minute")
async def campaign_policy(request: Request, campaign_id: str):
    rec = _campaigns.get(campaign_id)
    if not rec:
        raise HTTPException(404, detail={"error": "not_found"})
    return {"campaign_id": campaign_id, "policy_decisions": rec.get("policy_log", [])}


@app.get("/api/campaigns")
@limiter.limit("100/minute")
async def list_campaigns(request: Request):
    summaries = sorted(
        [{"campaign_id": cid, "status": r["status"], "started_at": r["started_at"],
          "target": r["target"], "findings_count": len(r["findings"])}
         for cid, r in _campaigns.items()],
        key=lambda x: x["started_at"], reverse=True,
    )
    return {"campaigns": summaries, "total": len(summaries)}


_ATTACK_RESP = {
    "prompt_injection":    ("RULE-PI-001", "Prompt injection in user input blocked by PolicyEngine."),
    "scope_drift":         ("RULE-SD-002", "Scope drift: requested ops exceed campaign manifest."),
    "unknown_target":      ("RULE-UT-003", "Target not in authorised asset registry."),
    "authority_escalation": ("RULE-AE-004", "Privilege escalation attempt blocked."),
}


@app.post("/api/demo/attack")
@limiter.limit("100/minute")
async def demo_attack(request: Request, body: AttackScenario):
    rule, reason = _ATTACK_RESP[body.type]
    evidence_store.record("demo", "attack_blocked", {
        "type": body.type, "rule": rule, "reason": reason,
    })
    return {
        "attack_type": body.type,
        "verdict": "DENIED",
        "policy_rule": rule,
        "reason": reason,
        "intercepted_at": _now(),
        "message": "BLACKBOX X-RAY intercepted and blocked this attack.",
    }


@app.get("/api/evidence/recent")
@limiter.limit("100/minute")
async def recent_evidence(request: Request):
    return {"entries": evidence_store.get_all(50)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=PORT, log_config=None)
