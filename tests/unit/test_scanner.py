"""Unit tests: SyntheticTarget + core utilities."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from core.synthetic_target import get_target_code, get_target_metadata
from core.evidence_store import record, get_campaign


def test_synthetic_code_nonempty():
    code = get_target_code()
    assert len(code) > 100


def test_synthetic_metadata_fields():
    meta = get_target_metadata()
    assert meta["target"] == "synthetic-enterprise-001"
    assert meta["known_flaw_count"] >= 1
    assert "modules" in meta


def test_synthetic_code_has_known_flaws():
    code = get_target_code()
    assert "DB_PASSWORD" in code          # hardcoded credential
    assert "MD5" in code or "md5" in code # broken hash
    assert "verify=False" in code         # TLS disabled
    assert "'" + " + user_id + " + "'" in code or "user_id" in code  # SQL injection pattern


def test_evidence_store_record_and_retrieve():
    eid = record("camp-test-001", "test_event", {"key": "value"})
    assert eid
    entries = get_campaign("camp-test-001")
    assert any(e["event_type"] == "test_event" for e in entries)


def test_evidence_store_payload_roundtrip():
    data = {"finding": "SQL injection", "severity": "CRITICAL", "line": 42}
    record("camp-test-002", "finding", data)
    entries = get_campaign("camp-test-002")
    found = [e for e in entries if e["event_type"] == "finding"]
    assert found
    assert found[0]["payload"]["severity"] == "CRITICAL"
