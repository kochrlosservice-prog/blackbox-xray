"""BLACKBOX X-RAY — Central configuration."""
from __future__ import annotations
import os

PROJECT_ID: str = os.environ.get("GCLOUD_PROJECT", "rlos-506521")
REGION: str = os.environ.get("GCLOUD_REGION", "us-central1")
GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
PORT: int = int(os.environ.get("PORT", "8080"))
EVIDENCE_DB: str = os.environ.get("EVIDENCE_DB", "/tmp/evidence.db")

# Required for ADK + Vertex AI
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "1")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", PROJECT_ID)
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", REGION)
