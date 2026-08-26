# BLACKBOX X-RAY — Hackathon Stand
_Zuletzt aktualisiert: 2026-08-26_

## Hackathon
- **Competition:** All Things Agentic Hackathon
- **Track:** Fortified Enterprise Fleet
- **Preis:** USD 20.000
- **Deadline:** 2026-08-31 17:00 PDT = 2026-09-01 02:00 Berlin
- **Devpost:** https://allthingsagentichackathon.devpost.com/

## Projekt
- **Name:** BLACKBOX X-RAY — Enterprise Agent Security Control Plane
- **Lokaler Pfad:** ~/sentinel/
- **GCP Projekt:** rlos-506521
- **Region:** us-central1
- **Billing:** 012DF8-A05B35-449C01 (aktiv verknüpft)
- **GCP Auth:** kochrlosservice@gmail.com (gcloud + ADC konfiguriert)

## Architektur
9 Rollen aus blackbox-xray-firmenstruktur.md → Google ADK Agenten:
1. Kernel → ScopeAgent (scope_agent.py) ✅
2. Graph & Metrik → dependency_graph.py + metrics.py ✅
3. Simulation → failure_engine.py ✅
4. Sicherheit → approval_gate.py + policy/engine.py ✅
5. Patch-Labor → patch_builder.py ✅
6. Git Time-Machine → time_machine.py ✅
7. API & Frontend → server/main.py + rlos_api/routes/api.py ✅
8. QA & Audit → adversarial_agent.py (FEHLT NOCH)
9. Kevin (Human Gate) → ApprovalGate SECURITY_VETO ✅

## Was gebaut wurde (64 Python-Dateien)
- `policy/engine.py` — Deterministische Policy Engine ✅
- `agents/orchestrator.py` — Google ADK Orchestrator ✅
- `agents/scope_agent.py` — Scope Validation ✅
- `server/main.py` — FastAPI Cloud Run Server ✅
- `rlos_core/config/settings.py` ✅
- `rlos_core/scanner/repository_scanner.py` ✅
- `rlos_core/graph/dependency_graph.py` (Tarjan SCC + Brandes) ✅
- `rlos_core/graph/metrics.py` (CC, Coupling, LCOM4) ✅
- `rlos_core/detectors/F01-F18_*.py` — 18 AST Detektoren ✅
- `rlos_core/detectors/findings.py` ✅
- `rlos_core/security/secret_scanner.py` ✅
- `rlos_core/security/approval_gate.py` ✅
- `rlos_core/simulation/failure_engine.py` ✅
- `rlos_core/patch/patch_builder.py` ✅
- `rlos_core/git_timemachine/time_machine.py` ✅
- `infrastructure/firestore_client.py` ✅
- `infrastructure/pubsub_client.py` ✅
- `infrastructure/evidence_ledger.py` ✅
- `synthetic/target_environment.py` ✅
- `synthetic/attack_scenarios.py` ✅
- `rlos_api/routes/api.py` ✅
- `tests/sample_broken_project/` (circular_a, circular_b, god_module) ✅
- `tests/unit/test_scanner.py` ✅
- `Dockerfile` ✅
- `requirements.txt` ✅
- `.env.example` ✅
- `README.md` ✅
- `COMPETITION_SCORECARD.md` ✅
- `BLACKBOX_XRAY_ROLLEN.md` ✅

## Was noch FEHLT (nächste Schritte mit "Go")
1. **agents/execution_agent.py** — von Workflow generiert, prüfen ob auf Disk
2. **agents/evidence_agent.py** — prüfen
3. **agents/adversarial_agent.py** — prüfen
4. **agents/cleanup_sentinel.py** — prüfen
5. **tests/unit/test_policy_engine.py** — schreiben
6. **tests/unit/test_detectors.py** — schreiben
7. **tests/integration/test_full_pipeline.py** — schreiben
8. **Vertex AI API enablen** — gcloud services enable aiplatform.googleapis.com
9. **Pub/Sub Topics erstellen** — sentinel-agent-events, sentinel-evidence, sentinel-alerts
10. **Firestore Database erstellen** — im GCP Projekt
11. **pytest laufen lassen** — alle Tests grün
12. **Docker Build** — lokal testen
13. **Artifact Registry** — Image pushen
14. **Cloud Run deployen** — immutable digest
15. **Terraform** — optional aber stark für Scorecard
16. **Architecture Diagram** — PNG für Devpost
17. **Demo-Run** — echte Gemini-Invocation beweisen
18. **Devpost Registration** — Account + Projekt anlegen
19. **Video** — 4 Min, Gemini-Beweis, Cloud Run live
20. **Final Submit** — nur mit Kevins expliziter Freigabe

## Syntax-Status
- Alle 64 Python-Dateien: SYNTAX OK (py_compile bestätigt)
- Kern + 18 Detektoren + Server: SYNTAX OK

## Schlüsselwort zum Weitermachen
Kevin sagt "Go" → weitermachen ab Schritt 1 dieser Liste.
