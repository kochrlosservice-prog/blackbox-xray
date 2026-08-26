"""
BLACKBOX X-RAY — Synthetic enterprise target.

Realistic-looking enterprise Python code with deliberate security flaws.
Agents analyse THIS code during demo campaigns. No real network calls.
"""
from __future__ import annotations

# ── The "enterprise app" the agents will analyse ──────────────────────────

SYNTHETIC_CODE = """
import sqlite3, os, hashlib, requests, logging

# WARNING: hardcoded credentials (F01)
DB_PASSWORD = "admin123"
API_KEY = "sk-prod-9f2a8c1d4e7b"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiJ9.prod"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("enterprise_app")

class UserService:
    def __init__(self):
        self.conn = sqlite3.connect("prod.db")
        self.admin_pass = DB_PASSWORD  # F01: secret in attribute

    def get_user(self, user_id: str):
        # F02: SQL injection — user input concatenated directly
        query = "SELECT * FROM users WHERE id = '" + user_id + "'"
        return self.conn.execute(query).fetchone()

    def login(self, username: str, password: str):
        # F03: broken auth — MD5 used for password hashing
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username='{username}' AND pw='{pw_hash}'"
        row = self.conn.execute(query).fetchone()
        if row:
            logger.debug("Login success: user=%s pw=%s", username, password)  # F04: secret in log
            return True
        return False

    def delete_user(self, user_id: str):
        # F05: no authorisation check before destructive operation
        self.conn.execute(f"DELETE FROM users WHERE id={user_id}")
        self.conn.commit()

class PaymentService:
    def __init__(self):
        self.api_key = API_KEY

    def charge(self, amount: float, card_number: str):
        # F06: PAN logged in plaintext
        logger.info("Charging card %s amount %.2f", card_number, amount)
        try:
            r = requests.post(
                "https://payment.internal/charge",
                json={"key": self.api_key, "card": card_number, "amount": amount},
                timeout=30,
                verify=False,  # F07: TLS verification disabled
            )
            return r.json()
        except:  # F08: bare except swallows all errors silently
            pass

class ConfigLoader:
    _instance = None

    @classmethod
    def get(cls):
        # F09: singleton backed by global mutable state
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self, path: str):
        # F10: path traversal — no sanitisation
        with open(path) as f:
            return f.read()

def run_query(sql: str):
    # F11: arbitrary SQL execution endpoint — no whitelist
    conn = sqlite3.connect("prod.db")
    return conn.execute(sql).fetchall()
"""

SYNTHETIC_METADATA = {
    "target": "synthetic-enterprise-001",
    "language": "python",
    "loc": 62,
    "modules": ["UserService", "PaymentService", "ConfigLoader"],
    "known_flaw_count": 11,
    "description": (
        "Synthetic enterprise authentication + payment service "
        "with deliberate security flaws for demo analysis."
    ),
}


def get_target_code() -> str:
    return SYNTHETIC_CODE


def get_target_metadata() -> dict:
    return SYNTHETIC_METADATA
