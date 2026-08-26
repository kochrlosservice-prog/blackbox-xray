"""BLACKBOX X-RAY — Architecture Diagram Generator."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(1, 1, figsize=(18, 11))
ax.set_xlim(0, 18)
ax.set_ylim(0, 11)
ax.axis("off")
fig.patch.set_facecolor("#0d1117")
ax.set_facecolor("#0d1117")

# ── Colors ────────────────────────────────────────────────────────────────
C_BG      = "#0d1117"
C_PANEL   = "#161b22"
C_BORDER  = "#30363d"
C_GREEN   = "#3fb950"
C_RED     = "#f85149"
C_YELLOW  = "#d29922"
C_BLUE    = "#58a6ff"
C_PURPLE  = "#bc8cff"
C_ORANGE  = "#e3b341"
C_TEXT    = "#e6edf3"
C_MUTED   = "#8b949e"

def box(ax, x, y, w, h, color, label, sublabel="", radius=0.25):
    rect = FancyBboxPatch((x, y), w, h,
                           boxstyle=f"round,pad=0.0,rounding_size={radius}",
                           facecolor=C_PANEL, edgecolor=color, linewidth=2)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h/2 + (0.15 if sublabel else 0),
            label, ha="center", va="center",
            color=color, fontsize=9, fontweight="bold", fontfamily="monospace")
    if sublabel:
        ax.text(x + w/2, y + h/2 - 0.22,
                sublabel, ha="center", va="center",
                color=C_MUTED, fontsize=7, fontfamily="monospace")

def arrow(ax, x1, y1, x2, y2, color=C_MUTED, lw=1.5, style="->"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, connectionstyle="arc3,rad=0.0"))

def label(ax, x, y, text, color=C_MUTED, size=7, bold=False):
    ax.text(x, y, text, ha="center", va="center",
            color=color, fontsize=size, fontfamily="monospace",
            fontweight="bold" if bold else "normal")

# ── Title ─────────────────────────────────────────────────────────────────
ax.text(9, 10.5, "BLACKBOX X-RAY", ha="center", va="center",
        color=C_TEXT, fontsize=20, fontweight="bold", fontfamily="monospace")
ax.text(9, 10.1, "Enterprise Agent Security Control Plane  ·  Google ADK 2.7.1  ·  Gemini 2.5 Flash  ·  Vertex AI",
        ha="center", va="center", color=C_MUTED, fontsize=8, fontfamily="monospace")

# ── Policy Engine (left column) ───────────────────────────────────────────
box(ax, 0.3, 1.0, 3.2, 7.8, C_RED, "POLICY ENGINE", "deterministic · fail-closed")

label(ax, 1.9, 8.3, "SCOPE VALIDATION", C_RED, 7, True)
box(ax, 0.6, 7.5, 2.6, 0.6, C_RED, "validate_scope()", "target + ops check")
box(ax, 0.6, 6.7, 2.6, 0.6, C_RED, "capability_token()", "5min TTL · per-op")
box(ax, 0.6, 5.9, 2.6, 0.6, C_RED, "check_scope_drift()", "expansion detection")
box(ax, 0.6, 5.1, 2.6, 0.6, C_RED, "FORBIDDEN_OPERATIONS", "shell · exec · exploit")
box(ax, 0.6, 4.3, 2.6, 0.6, C_RED, "validate_agent_tools()", "BashTool → RuntimeError")
box(ax, 0.6, 3.5, 2.6, 0.6, C_YELLOW, "injection_guard()", "pre-flight regex scan")
box(ax, 0.6, 2.7, 2.6, 0.6, C_MUTED, "audit_log", "every decision · append-only")
box(ax, 0.6, 1.9, 2.6, 0.6, C_MUTED, "evidence_store", "SQLite · tamper-evident")

ax.text(1.9, 1.4, "AGENT_OUTPUT != EXECUTION_AUTHORITY",
        ha="center", va="center", color=C_RED,
        fontsize=6.5, fontfamily="monospace", fontweight="bold")

# ── Agent Pipeline (center) ───────────────────────────────────────────────
AGENTS = [
    (C_BLUE,   "SCANNER AGENT",    "scan_for_credentials()\nscan_for_injection()", 8.1),
    (C_PURPLE, "EVIDENCE AGENT",   "record_and_sign_finding()\nbuild_chain_of_custody()", 7.0),
    (C_RED,    "ADVERSARIAL AGENT","check_for_false_positive()\nintegrity < 0.4 → ABORT", 5.9),
    (C_YELLOW, "VERIFICATION",     "falsified findings filtered\nverified set produced", 4.8),
    (C_GREEN,  "PATCH AGENT",      "assess_patch_risk()\nrisk > 0.20 → human approval", 3.7),
    (C_BLUE,   "CLEANUP AGENT",    "verify_environment_cleanup()\nall artefacts resolved", 2.6),
]

for color, name, tools, y in AGENTS:
    box(ax, 4.0, y, 4.5, 0.85, color, name, tools)

# arrows between agents
for i in range(len(AGENTS) - 1):
    y_from = AGENTS[i][3]
    y_to   = AGENTS[i+1][3] + 0.85
    arrow(ax, 6.25, y_from, 6.25, y_to, C_GREEN, lw=2)

# Policy gate arrows (left → agents)
for color, name, tools, y in AGENTS:
    arrow(ax, 3.5, y + 0.42, 4.0, y + 0.42, C_RED, lw=1.2)
    label(ax, 3.75, y + 0.55, "gate", C_RED, 6)

# entry arrow
arrow(ax, 6.25, 9.4, 6.25, AGENTS[0][3] + 0.85, C_MUTED, lw=2)
box(ax, 4.8, 9.1, 2.9, 0.6, C_MUTED, "API /campaign/start", "FastAPI · Cloud Run")

# ── Signal Space (right) ──────────────────────────────────────────────────
box(ax, 9.5, 1.0, 4.0, 8.5, C_PURPLE, "SIGNAL SPACE", "shared state · reactive")

label(ax, 11.5, 9.0, "EVIDENCE STORE", C_PURPLE, 7, True)

events = [
    (C_BLUE,   "campaign_start"),
    (C_BLUE,   "tool_scan_credentials"),
    (C_BLUE,   "tool_scan_injection"),
    (C_PURPLE, "signed_finding"),
    (C_PURPLE, "chain_of_custody"),
    (C_RED,    "adversarial_check"),
    (C_YELLOW, "verification_complete"),
    (C_GREEN,  "patches_proposed"),
    (C_GREEN,  "cleanup_verified"),
    (C_MUTED,  "policy_decision ×N"),
    (C_MUTED,  "campaign_end"),
]
for i, (c, ev) in enumerate(events):
    y_pos = 8.5 - i * 0.64
    box(ax, 9.8, y_pos, 3.4, 0.5, c, ev)

# arrows agents → signal space
for color, name, tools, y in AGENTS:
    arrow(ax, 8.5, y + 0.42, 9.5, y + 0.42, color, lw=1.2)

# ── Gemini / Vertex AI (far right) ────────────────────────────────────────
box(ax, 14.2, 4.5, 3.5, 2.5, C_BLUE, "GEMINI 2.5 FLASH", "Vertex AI · us-central1")
label(ax, 15.95, 5.5, "Real LLM Tool Calls", C_BLUE, 7, True)
label(ax, 15.95, 5.1, "function_calling=AUTO", C_MUTED, 6.5)
label(ax, 15.95, 4.8, "temperature=0.2", C_MUTED, 6.5)

arrow(ax, 14.2, 5.5, 13.5, 5.5, C_BLUE, lw=1.5)
label(ax, 13.85, 5.75, "responses", C_BLUE, 6)
arrow(ax, 13.5, 5.2, 14.2, 5.2, C_MUTED, lw=1.5)
label(ax, 13.85, 4.95, "tool prompts", C_MUTED, 6)

box(ax, 14.2, 7.5, 3.5, 1.2, C_GREEN, "CLOUD RUN", "Port 8080 · auto-scale")
label(ax, 15.95, 7.85, "GET  /health", C_GREEN, 6.5)
label(ax, 15.95, 7.55, "POST /api/campaign/start", C_MUTED, 6.5)
label(ax, 15.95, 7.25, "POST /api/demo/attack", C_MUTED, 6.5)

box(ax, 14.2, 2.0, 3.5, 2.0, C_RED, "SHELL BLOCKED", "structural impossibility")
label(ax, 15.95, 3.3, "bash_tool → RuntimeError", C_RED, 6.5, True)
label(ax, 15.95, 3.0, "FORBIDDEN_OPERATIONS:", C_MUTED, 6.5)
label(ax, 15.95, 2.7, "shell · exec · bash", C_RED, 6.5)
label(ax, 15.95, 2.4, "run_bash · subprocess", C_RED, 6.5)
label(ax, 15.95, 2.1, "os_system · eval", C_RED, 6.5)

# ── Bottom legend ─────────────────────────────────────────────────────────
ax.text(9, 0.4, "We didn't build a warden.  We built a physics.",
        ha="center", va="center", color=C_TEXT,
        fontsize=11, fontfamily="monospace", fontstyle="italic")

plt.tight_layout(pad=0.2)
plt.savefig("architecture.png", dpi=180, bbox_inches="tight",
            facecolor=C_BG, edgecolor="none")
print("architecture.png gespeichert.")
