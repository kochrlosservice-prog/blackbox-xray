# SENTINEL

**Enterprise Agent Security Control Plane**

> AGENT REASONING != EXECUTION AUTHORITY

SENTINEL is a multi-agent security orchestration system built on Google Agent Development Kit (ADK) and Gemini. It enforces a strict separation between what an agent *decides* to do and what it is *permitted* to do, using a policy engine, a capability broker with short-lived tokens, and an independent adversarial verification layer. Every automated action is gated, evidence-logged to Firestore, and independently reviewed before being considered complete — making SENTINEL suitable for high-stakes enterprise security operations where uncontrolled agent autonomy is unacceptable.

---

## Architecture Overview

```
Operator → [Campaign Request]
                ↓
    [SENTINEL Orchestrator / Google ADK]
                ↓
    [Scope Agent] → [Policy Engine] → ALLOW/DENY
                ↓ (if ALLOW)
    [Environment Agent] → select isolated env
                ↓
    [Planning Agent] → bounded plan
                ↓
    [Execution Agent] ← [Capability Broker] ← short-lived token
                ↓
    [Evidence Agent] → Firestore evidence ledger
                ↓
    [Adversarial Review Agent] → falsification attempt
                ↓
    [Verification Agent] → evidence validation
                ↓
    [Cleanup Sentinel] → independent verification
```

**Core principle:** Every agent produces reasoning and intent. The Policy Engine and Capability Broker evaluate intent *independently* and issue time-bounded, scope-limited execution tokens. An agent that reasons "I should delete this file" does not gain the authority to delete it — authority is granted externally, after policy evaluation, or denied.

---

## Key Principle

```
AGENT REASONING != EXECUTION AUTHORITY
```

An agent's internal decision to act does not constitute permission to act. All execution authority flows through the Capability Broker, which validates against the Policy Engine before issuing any short-lived capability token. Tokens are single-use, scope-bound, and expire within seconds.

---

## Architecture — All 8 Agents

| Agent | Role |
|---|---|
| **Scope Agent** | Parses the operator's campaign request, extracts targets, validates them against the declared scope manifest, and submits to the Policy Engine |
| **Policy Engine** | Stateless rule evaluator — enforces scope boundaries, rate limits, capability allow-lists, and compliance tags. Produces ALLOW or DENY with reason |
| **Environment Agent** | Selects and initialises an isolated execution environment for this campaign run; ensures no cross-campaign contamination |
| **Planning Agent** | Produces a bounded, step-by-step execution plan constrained to approved scope; no free-form tool calls permitted |
| **Execution Agent** | Executes individual plan steps using capability tokens issued by the Broker; has no persistent credentials |
| **Capability Broker** | Issues short-lived, single-use tokens for specific tool invocations; validates each request against Policy Engine before issuance |
| **Evidence Agent** | Records every action, token issuance, and result to the Firestore evidence ledger with cryptographic chaining |
| **Adversarial Review Agent** | Attempts to falsify, contradict, or invalidate the evidence chain; flags anomalies and incomplete traces |
| **Verification Agent** | Cross-validates the adversarial review against the evidence ledger; produces a final verification verdict |
| **Cleanup Sentinel** | Independently verifies that all ephemeral resources, tokens, and environment artefacts have been destroyed after campaign completion |

---

## Security Model

### Policy Engine

The Policy Engine is stateless and deterministic. It evaluates every proposed action against:

- **Scope manifest** — declared target IP ranges, domains, or asset tags
- **Capability allow-list** — which tool categories are permitted for this campaign type
- **Rate limits** — maximum actions per minute, per target, per campaign
- **Compliance tags** — regulatory or business constraints attached to assets

A DENY response is final and logged. No agent can override a DENY.

### Capability Broker

The Broker is the sole issuer of execution authority. It:

- Receives intent from the Execution Agent
- Validates intent against the current Policy Engine decision
- Issues a token that is: single-use, scoped to one specific tool call, and valid for a maximum of 30 seconds
- Revokes all outstanding tokens when a campaign terminates or a policy violation is detected

### Scope Binding

Every campaign is initialised with a cryptographically signed scope manifest. All agents receive a read-only copy. Any action targeting a resource outside the manifest is rejected at the Policy Engine before a token is ever considered.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Agent framework | Google Agent Development Kit (ADK) |
| LLM backbone | Google Gemini (gemini-2.0-flash / gemini-1.5-pro) |
| Orchestration runtime | Google Cloud Run |
| Event bus | Google Cloud Pub/Sub |
| Evidence ledger | Google Cloud Firestore |
| Policy evaluation | Custom stateless rule engine (Python) |
| Capability tokens | Python `secrets` + SHA-256 binding |
| Local development | Python 3.11+, uvicorn |

---

## Quick Start (Local)

### Prerequisites

- Python 3.11 or later
- `pip` and `venv`
- A Google Cloud project with billing enabled (see below)
- Google Cloud CLI (`gcloud`) authenticated locally

### Clone and install

```bash
git clone https://github.com/your-org/sentinel.git
cd sentinel
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Google Cloud Prerequisites

1. **Create a project**

```bash
gcloud projects create sentinel-hackathon-001
gcloud config set project sentinel-hackathon-001
```

2. **Enable billing** — link a billing account in the Cloud Console or via:

```bash
gcloud billing projects link sentinel-hackathon-001 \
  --billing-account=YOUR_BILLING_ACCOUNT_ID
```

3. **Enable required APIs**

```bash
gcloud services enable \
  run.googleapis.com \
  pubsub.googleapis.com \
  firestore.googleapis.com \
  aiplatform.googleapis.com \
  cloudresourcemanager.googleapis.com
```

4. **Create a Firestore database** (Native mode, us-central1)

```bash
gcloud firestore databases create \
  --location=us-central1 \
  --type=firestore-native
```

5. **Create a service account for SENTINEL**

```bash
gcloud iam service-accounts create sentinel-runtime \
  --display-name="SENTINEL Runtime"

gcloud projects add-iam-policy-binding sentinel-hackathon-001 \
  --member="serviceAccount:sentinel-runtime@sentinel-hackathon-001.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

gcloud projects add-iam-policy-binding sentinel-hackathon-001 \
  --member="serviceAccount:sentinel-runtime@sentinel-hackathon-001.iam.gserviceaccount.com" \
  --role="roles/pubsub.editor"

gcloud iam service-accounts keys create sa-key.json \
  --iam-account=sentinel-runtime@sentinel-hackathon-001.iam.gserviceaccount.com
```

---

## Environment Setup

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` — the following variables are required:

```
GOOGLE_CLOUD_PROJECT=sentinel-hackathon-001
GOOGLE_APPLICATION_CREDENTIALS=./sa-key.json
GEMINI_MODEL=gemini-2.0-flash
FIRESTORE_COLLECTION=sentinel_evidence
PUBSUB_TOPIC=sentinel-events
CAPABILITY_TOKEN_TTL_SECONDS=30
POLICY_STRICT_MODE=true
LOG_LEVEL=INFO
```

Do not commit `.env` or `sa-key.json` to version control. Both are listed in `.gitignore`.

---

## Local Run

```bash
source .venv/bin/activate
uvicorn sentinel.main:app --host 0.0.0.0 --port 8080 --reload
```

The API will be available at `http://localhost:8080`.

Health check:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status": "ok", "version": "0.1.0", "policy_engine": "active"}
```

---

## Test Instructions

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

To run only unit tests (no cloud dependencies):

```bash
python -m pytest tests/unit/ -v
```

To run integration tests (requires valid `.env` with live GCP credentials):

```bash
python -m pytest tests/integration/ -v
```

---

## Google Cloud Deployment

### Build and push the container

```bash
gcloud builds submit --tag gcr.io/sentinel-hackathon-001/sentinel:latest .
```

### Deploy to Cloud Run

```bash
gcloud run deploy sentinel \
  --image gcr.io/sentinel-hackathon-001/sentinel:latest \
  --region us-central1 \
  --platform managed \
  --service-account sentinel-runtime@sentinel-hackathon-001.iam.gserviceaccount.com \
  --set-env-vars GOOGLE_CLOUD_PROJECT=sentinel-hackathon-001 \
  --set-env-vars GEMINI_MODEL=gemini-2.0-flash \
  --set-env-vars FIRESTORE_COLLECTION=sentinel_evidence \
  --set-env-vars PUBSUB_TOPIC=sentinel-events \
  --set-env-vars CAPABILITY_TOKEN_TTL_SECONDS=30 \
  --set-env-vars POLICY_STRICT_MODE=true \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 5
```

Note the service URL printed after deployment. Set it as `SENTINEL_URL` for the demo steps below.

### Verify deployment

```bash
curl $SENTINEL_URL/health
```

---

## Running a Demo Campaign

### 1. Create a campaign with an approved scope

```bash
curl -X POST $SENTINEL_URL/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "demo-recon-alpha",
    "type": "reconnaissance",
    "scope": {
      "targets": ["192.0.2.0/24"],
      "asset_tags": ["lab-synthetic"],
      "excluded": []
    },
    "capabilities": ["port_scan", "banner_grab"],
    "operator": "demo-operator-001"
  }'
```

Expected response:

```json
{
  "campaign_id": "cmp_abc123",
  "status": "initialising",
  "policy_decision": "ALLOW",
  "scope_hash": "sha256:...",
  "message": "Campaign accepted. Scope validated."
}
```

### 2. Poll campaign status

```bash
curl $SENTINEL_URL/campaigns/cmp_abc123/status
```

### 3. Retrieve the evidence ledger

```bash
curl $SENTINEL_URL/campaigns/cmp_abc123/evidence
```

---

## Simulating an Attack Scenario (DENIAL)

This example attempts to launch a campaign targeting a resource outside the declared scope. The Policy Engine must produce a DENY.

```bash
curl -X POST $SENTINEL_URL/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "out-of-scope-attack",
    "type": "exploitation",
    "scope": {
      "targets": ["10.0.0.1"],
      "asset_tags": []
    },
    "capabilities": ["exploit_rce", "credential_dump"],
    "operator": "demo-operator-001"
  }'
```

Expected response (DENIAL):

```json
{
  "campaign_id": null,
  "status": "denied",
  "policy_decision": "DENY",
  "denial_reason": "Capability 'exploit_rce' is not permitted for operator 'demo-operator-001'. Target '10.0.0.1' is outside declared lab scope. Capability 'credential_dump' is not on the allow-list for campaign type 'exploitation'.",
  "evidence_ref": "evt_deny_xyz789",
  "message": "Campaign rejected by Policy Engine. No execution tokens were issued. Denial recorded to evidence ledger."
}
```

The Execution Agent and Capability Broker are never contacted. The Adversarial Review Agent and Cleanup Sentinel still run to confirm no artefacts were created.

---

## Known Limitations

- **SQLite is not used.** All persistence is Firestore. There is no local database fallback.
- **Synthetic targets only.** All demo campaigns run against synthetic lab targets (`192.0.2.0/24`, RFC 5737 documentation range). No real external systems are scanned.
- **Capability tokens are in-process.** In this prototype the Capability Broker runs in the same process as the Orchestrator. A production deployment would isolate it as a separate Cloud Run service with mTLS.
- **No authentication on the REST API.** The demo endpoint uses `--allow-unauthenticated` for hackathon convenience. A production deployment would require IAP or API key validation on all routes.
- **Single region.** Evidence ledger is written to a single Firestore region. Multi-region replication is not configured.
- **No real vulnerability scanner integration.** Tool outputs for port scans and banner grabs are simulated. SENTINEL enforces the security *control plane* logic, not the underlying scanner tooling.
- **Adversarial Review Agent uses Gemini, not a separate model.** In a production adversarial setup, the reviewing model should differ from the planning model to reduce correlated failure modes.

---

## Hackathon Disclosure

SENTINEL was built specifically for the **All Things Agentic Hackathon**, Track: **Fortified Enterprise Fleet**. It is a new project with no prior public release. All code was written during the hackathon period.

This project is a proof-of-concept demonstrating architectural principles for enterprise agent security control planes. It is not a finished commercial product. All targets used in demos are synthetic. No real infrastructure was scanned or exploited during development or demonstration.

---

## License

Apache 2.0 — see `LICENSE`.
