# BLACKBOX X-RAY
## Enterprise Agent Security Control Plane

---

## Inspiration

I run a Burger King restaurant in Germany.

I manage schedules, food safety, staff, and customer flow for a living.
I am not a software engineer. I have no computer science degree.

When I heard about the All Things Agentic hackathon, I didn't know
what ADK was. I didn't know Vertex AI. I had never deployed to Cloud Run.

I built BLACKBOX X-RAY anyway — because the question it answers
is one that matters regardless of who is asking it:

**What if insecure actions were structurally impossible — not forbidden, but inexistent?**

A bird in a murmuration doesn't obey a commander. It reacts to a field.
The field *is* the coordination. The field *is* the safety.

Current agent security = a guard watching what agents do.
BLACKBOX X-RAY = a physics in which there is nothing to guard against.

`AGENT_OUTPUT != EXECUTION_AUTHORITY`

This is not a comment in the code. It is a thesis.
And it was built between closing shifts.

---

## What it does

BLACKBOX X-RAY is a 6-agent security validation pipeline that analyses enterprise codebases for vulnerabilities — with every agent operating inside a deterministic policy field that makes unsafe behaviour structurally impossible.

**The pipeline:**

1. **PolicyEngine (Gate)** — Deterministic scope + capability validation before any agent acts. Fail-closed. Every decision logged.
2. **ScannerAgent** — Uses Gemini 2.5 Flash to scan code for credentials, injection vulnerabilities, TLS bypasses, broken hashing. Real tool calls, real findings.
3. **EvidenceAgent** — Cryptographically signs every finding with SHA-256 before it can proceed. Chain of custody built per campaign.
4. **AdversarialAgent** — Actively tries to *falsify* its own team's findings. Built-in sceptic. If integrity score drops below 0.4, campaign aborts.
5. **PatchAgent** — Proposes fixes with risk scoring. Patches above risk 0.20 require human approval — the agent cannot self-approve.
6. **CleanupAgent** — Verifies all campaign artefacts are resolved before declaring COMPLETE.

**Shell execution: permanently blocked.**
Not disabled. Not rate-limited. Structurally absent from the policy field.

---

## How we built it

- **Google ADK 2.7.1** — All 6 agents are real ADK agents with tool functions Gemini calls via function calling
- **Gemini 2.5 Flash on Vertex AI** — Every agent reasoning step and every tool invocation goes through Gemini
- **Deterministic PolicyEngine** — Validates scope, issues short-lived capability tokens (5 min TTL), detects scope drift, blocks forbidden operations
- **SQLite Evidence Store** — Append-only audit trail of every event, finding, and policy decision
- **FastAPI on Cloud Run** — `/api/campaign/start`, `/api/demo/attack`, `/api/evidence/recent`
- **Python 3.11**

---

## Challenges

**The hardest problem:** Designing a policy system where agents can't even *express* a forbidden action — not one that blocks them after the fact. The solution: capability tokens. An agent can only call a tool if it holds a valid, short-lived, scope-bound token. There is no path to execution without the token. There is no token without policy approval.

**The philosophical challenge:** Resisting the urge to build an orchestrator that *controls* agents. The architecture deliberately has no single point of authority. Agents react to the shared signal space (the evidence store). Coordination emerges. Nobody commands anybody.

---

## Accomplishments

- Real Gemini tool calls in a 6-agent pipeline — observable, logged, auditable
- Shell execution blocked at two layers: FORBIDDEN_OPERATIONS in policy + `validate_agent_tools()` check before every agent run
- Adversarial review that actually falsifies findings — not just a rubber stamp
- A campaign that produces `status: COMPLETE` with verified findings, signed evidence, and assessed patches in under 90 seconds

---

## What we learned

Security is not about more guards. It's about better geometry.

The most secure system is not one where agents are watched — it's one where the space of possible actions has been shaped so that unsafe paths don't exist. You can't jailbreak a wall. You can't prompt-inject a mathematical constraint.

---

## What's next

The swarm principle: replace the sequential pipeline with a reactive signal space where agents respond to events rather than receive commands. No orchestrator. Emergent coordination through shared state. Policy as the shape of the possible — not the voice of a warden.

---

## Built with

`google-adk` · `gemini-2.5-flash` · `vertex-ai` · `fastapi` · `python-3.11` · `sqlite` · `cloud-run` · `google-auth`
