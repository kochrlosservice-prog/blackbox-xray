# BLACKBOX X-RAY — Rollen & Prozesse

## Kontext

Der Bauplan definiert bereits Module, Phasen und Freigabestufen. Dieses Dokument übersetzt
das in Zuständigkeiten, Übergaben und Eskalationspfade — unabhängig davon, ob eine Person
oder eine Person plus Claude Code das ausführt. Rollen können in Personalunion gefüllt
werden; die Trennung existiert, damit bei jedem Schritt klar ist, wer entscheidet und wer
wen um Freigabe fragen muss — nicht, um eine Belegschaft zu simulieren, die es nicht gibt.

---

## Rollen

### 1. Kernel-Verantwortung (Scanner & Resolver)
**Module:** `repository_scanner.py`, `python_ast.py`, `fallback_parser.py`,
`import_resolver.py`, `call_resolver.py`

**Zuständig für:** Datei-Walk, AST-Extraktion, Import- und Call-Auflösung mit Konfidenzstufen.

**Deliverable:** Ein Graph, dessen `resolution_rate` ehrlich ist. Unauflösbares wird als
`unresolved` mit Grund gespeichert, nie stillschweigend geschluckt.

**Definition of Done:** Unit-Tests auf Kunstfällen bestehen (relative Imports, Star-Importe,
`TYPE_CHECKING`, `importlib.import_module("literal")`). Konfidenzstufen sind nachvollziehbar
begründet, nicht geraten.

**Eskalation an:** Graph-Verantwortung bei strukturellen Auflösungsproblemen, die die
Health-Score-Berechnung verzerren würden.

---

### 2. Graph- & Metrik-Verantwortung
**Module:** `dependency_graph.py`, `metrics.py`, `findings.py` (18 Detektorklassen)

**Zuständig für:** Graphalgorithmen (Tarjan-SCC, Brandes-Betweenness, Dominatoren), CC,
Kopplung, LCOM4, Health-Score.

**Deliverable:** Jeder Score ist nachrechenbar. Alle Konstanten liegen in `config.py`,
deren Version pro Scan gespeichert wird — sonst sind Scans über Zeit nicht vergleichbar.

**Definition of Done:** Tests mit bekannten Erwartungswerten bestehen. `score_breakdown`
geht vollständig ans UI und ist dort aufklappbar — kein Blackbox-Score in einem Tool, das
sich "X-Ray" nennt.

**Eskalation an:** Kernel-Verantwortung bei fehlerhaften Rohdaten. Frontend-Verantwortung
bei Darstellungsfragen zum Blast-Radius.

---

### 3. Simulations- & Impact-Verantwortung
**Module:** `failure_engine.py`, `impact_analysis.py`

**Zuständig für:** Neun Ausfallszenarien, Rückwärtspropagation, Blast-Radius,
Restfunktionsberechnung.

**Deliverable:** Propagation stoppt korrekt an geschützten Stellen (`try`, `guarded`,
`has_default`). Blattknoten liefern nachweislich Radius 0.

**Definition of Done:** `certainty`-Klassifikation (`certain`/`likely`/`possible`) stimmt mit
`p_path = Π p_edge` überein. Ausbreitungstiefe läuft über die SCC-Kondensation, nicht über
den Rohgraphen — sonst zählen Zyklen die Tiefe künstlich hoch.

**Nicht-Verhandelbar:** Es wird nichts gelöscht und nichts ausgeführt. Reine Graphrechnung.

---

### 4. Sicherheits-Verantwortung (Secrets & Patch-Freigabe)
**Module:** `secret_scanner.py`, `approval_gate.py`

**Zuständig für:** Musterebene + Entropieebene für Secrets, Maskierung, Freigabestufen
für Patches.

**Deliverable:** Keine Rohwerte persistiert oder geloggt. `fingerprint = sha256(scan_salt
+ raw)` mit pro Scan zufälligem, nicht gespeichertem Salt.

**Definition of Done:** Globaler Logging-Filter aktiv (ein Traceback darf keinen Wert
leaken). SHA-256-Race-Check der Zieldatei unmittelbar vor jedem Schreibvorgang.

**Vetorecht:** Kann jede Patch-Anwendung blockieren, unabhängig davon, was die
Patch-Labor-Verantwortung vorschlägt. Dieses Veto sticht Projektleitung nicht — aber
Projektleitung kann nicht daran vorbei, ohne die Sicherheits-Prüfung selbst zu ändern.

---

### 5. Patch-Labor-Verantwortung
**Module:** `patch_builder.py`

**Zuständig für:** Diffs aus exakten AST-Spans oder `tokenize`-Positionen, Risiko-Scoring,
die drei Automatisierungsstufen (sicher / halbautomatisch / nur menschlich).

**Deliverable:** Jeder Diff besteht `ast.parse`, hat einen anderen AST als das Original
(kein No-Op) und bei semantikneutralen Regeln denselben normalisierten AST.

**Definition of Done:** `git apply --check` bestätigt Gültigkeit. `risk`-Score korrekt aus
den fünf gewichteten Faktoren berechnet.

**Muss Freigabe einholen bei:** jedem Patch mit `risk > 0.20` — von Sicherheits-Verantwortung
und von Projektleitung, in dieser Reihenfolge.

---

### 6. Git- & Time-Machine-Verantwortung
**Module:** `time_machine.py`, Git-Sicherheitsregeln

**Zuständig für:** Commit-Diffs, Metrik-Verlauf über Zeit, Vorher/Nachher-Graph.

**Nicht-Verhandelbar:** `git init` ausschließlich innerhalb von `BLACKBOX_XRAY/`. Vor jedem
Patch-Apply: Zieldatei muss git-versioniert und clean sein, sonst wird die Anwendung
verweigert. Das ISO in `~/Basteln` bleibt in jedem Fall unangetastet.

---

### 7. API- & Frontend-Verantwortung
**Module:** `routes.py`, `templates/index.html`, `static/js/*`, `static/css/*`

**Zuständig für:** Die sieben Bereiche (Observatory, System Pulse, Dependency Field,
Failure Simulator, Time Machine, Patch Lab, Audit Vault), Canvas-Renderer mit
Barnes-Hut-Quadtree.

**Deliverable:** Buildfrei (kein npm, kein CDN zur Laufzeit). 60-FPS-Ziel beim Renderer.

**Definition of Done:** HTTP-Abrufe erfolgreich, Screenshot-Nachweis pro Bereich.

**Eskalation an:** Graph-Verantwortung, wenn eine Darstellungsanforderung eine neue
Metrik voraussetzt, die es noch nicht gibt.

---

### 8. QA- & Audit-Verantwortung
**Module:** `tests/`, `sample_broken_project/`, Audit-Log-Konsistenz

**Zuständig für:** Testabdeckung aller 18 Fehlerklassen, Soll/Ist-Nachweis, den
Härtetest (Selbstanalyse von BLACKBOX_XRAY durch sich selbst).

**Definition of Done:** `pytest tests/ -v` läuft grün. Soll/Ist-Tabelle für alle 18
Klassen liegt vor. Unterdrückte Befunde (`# xray: ignore F07`) sind im Log sichtbar,
nicht gelöscht.

**Vetorecht:** Kann einen Release blockieren, wenn der Härtetest nichts findet — findet
das Tool in sich selbst nichts, ist der Scanner kaputt, nicht das Projekt fertig.

---

### 9. Projekt- & Freigabeleitung (Kevin)

**Einzige Instanz mit Verfügungsgewalt außerhalb von `BLACKBOX_XRAY/`.**

**Zuständig für:** Bestätigung jeder der vier Patch-Freigabestufen einzeln
(ANALYSIEREN → PATCH ERZEUGEN → PATCH TESTEN → PATCH ANWENDEN). Letzte Instanz bei
Eskalationen zwischen Rollen, die sich nicht selbst auflösen.

**Nicht delegierbar:** Freigabe von Patches mit `risk > 0.20`. Entscheidung über
Python-Fallback (3.11 vs. 3.14) bei Wheel-Problemen.

---

## Ablauf — Phasen mit Übergaben

| Phase | Federführend | Deliverable | Übergabe an |
|---|---|---|---|
| 1 — Gerüst, venv, Schema | Kernel + Git | `pip list`, DB-Schema-Dump | Kernel-Verantwortung |
| 2 — Walker, AST, Resolver | Kernel | Unit-Tests auf Kunstfällen | Graph-Verantwortung |
| 3 — Graphalgorithmen, 18 Detektoren, Health-Score | Graph & Metrik | Tests mit Erwartungswerten | API/Frontend + Sicherheit |
| 4 — API-Routen, Frontend, Canvas-Renderer | API/Frontend | HTTP-Abrufe, Screenshot | Simulation |
| 5 — Simulator, Time Machine, Patch-Labor | Simulation + Patch-Labor | Diff-Ausgabe im Terminal | Sicherheits-Verantwortung |
| 6 — `sample_broken_project`, Selbsttest | QA & Audit | Trefferliste Soll/Ist | Projektleitung |
| 7 — Start, Selbstanalyse, Fehlerbehebung | Alle Rollen | Screenshots, `pytest`-Ausgabe | Projektleitung (Abnahme) |

Nach jeder Phase: erledigte Dateien, ausgeführte Tests, gefundene Probleme, nächste Aktion —
das ist bereits im Bauplan so festgelegt und gilt rollenübergreifend als Meldeformat.

---

## Eskalationspfade

- **Sicherheits-Verantwortung** sticht **Patch-Labor-Verantwortung** bei jeder
  Patch-Anwendung.
- **QA & Audit** sticht **API/Frontend** bei rotem Härtetest — kein Release mit
  bestandenem Frontend-Test, aber gescheitertem Selbsttest.
- **Kernel-Verantwortung** eskaliert an **Graph-Verantwortung** bei strukturellen
  Auflösungsproblemen, nicht umgekehrt (der Graph kann nur so gut sein wie die
  Rohauflösung).
- **Jede Rolle** eskaliert an **Projektleitung** bei Ressourcenkonflikten, die den
  Bauplan selbst berühren (z. B. Python-Version, Abweichung von stdlib-only).

---

## Nicht-Verhandelbares (rollenübergreifend bindend)

- Kein `git init` außerhalb von `BLACKBOX_XRAY/`.
- Kein Patch ohne ausdrückliche Freigabe der zuständigen Stufe.
- Keine Rohwerte (Secrets) in Logs, auch nicht in Tracebacks.
- `resolution_rate < 0.6` deckelt den Systemzustand hart auf UNBEKANNT — kein Projekt
  bekommt „STABIL", wenn es nicht sauber analysierbar war.
- Unterdrückte Befunde werden gespeichert, nie gelöscht — sonst ist das Audit-Log wertlos.
- Fremder Code wird geparst, nie ausgeführt.
