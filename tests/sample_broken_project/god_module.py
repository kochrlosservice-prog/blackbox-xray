"""
Deliberately broken module for testing Sentinel detectors F01-F16.
DO NOT use in production.
"""

import sqlite3

# F11 - Hardcoded credentials
db_password = "SuperSecret123!"
api_key = "hardcoded-api-key-abc123"

# F16 - Resource leak: open() without with
f = open("file.txt")
data = f.read()


# F01 - GodClass with 25 methods
class GodClass:
    """A class that does everything — violates single-responsibility principle."""

    def __init__(self):
        self.value = 0
        self.data = []
        self.cache = {}

    def method_01(self):
        return self.value + 1

    def method_02(self):
        return self.value + 2

    def method_03(self):
        return self.value * 86400  # F06 magic number

    def method_04(self):
        return self.value * 3600  # F06 magic number

    def method_05(self):
        self.data.append(self.value)

    def method_06(self):
        return len(self.data)

    def method_07(self):
        self.cache.clear()

    def method_08(self):
        return self.data[0] if self.data else None

    def method_09(self):
        return self.data[-1] if self.data else None

    def method_10(self):
        return sum(self.data)

    def method_11(self):
        return max(self.data) if self.data else 0

    def method_12(self):
        return min(self.data) if self.data else 0

    def method_13(self):
        self.value = 0

    def method_14(self):
        self.data = []

    def method_15(self, x):
        return x ** 2

    def method_16(self, x):
        return x ** 3

    def method_17(self, a, b):
        return a + b

    def method_18(self, a, b):
        return a - b

    def method_19(self, a, b):
        return a * b

    def method_20(self, a, b):
        return a / b if b != 0 else None

    def method_21(self):
        return [x * 2 for x in self.data]

    def method_22(self):
        return {i: v for i, v in enumerate(self.data)}

    def method_23(self):
        return sorted(self.data)

    def method_24(self):
        return list(reversed(self.data))

    def method_25(self):
        return self.data.copy()


# F12 - Missing type hints on function with 4+ args
def process_user_data(user_id, username, email, role, department, active):
    """No type hints at all — triggers F12."""
    return {
        "id": user_id,
        "name": username,
        "email": email,
        "role": role,
        "department": department,
        "active": active,
    }


# F02 - Function > 50 lines long; F03 - Deep nesting (4+ levels); F06 - Magic numbers
def complex_business_logic(user_id, records, threshold, mode):
    """Long function with deep nesting and magic numbers."""
    results = []
    errors = []
    retry_count = 0

    # Level 1
    if records is not None:
        # Level 2
        for record in records:
            if record.get("active"):
                # Level 3
                if record.get("score", 0) > 9999:  # F06 magic number
                    # Level 4 - deep nesting triggers F03
                    if mode == "strict":
                        # Level 5
                        if retry_count < 3:
                            try:
                                value = record["score"] * 86400  # F06 magic number
                                adjusted = value / 3600           # F06 magic number
                                if adjusted > threshold:
                                    results.append({
                                        "id": record["id"],
                                        "value": adjusted,
                                        "flag": True,
                                    })
                                else:
                                    results.append({
                                        "id": record["id"],
                                        "value": adjusted,
                                        "flag": False,
                                    })
                            except Exception:  # F15 - exception swallowing
                                pass
                        else:
                            errors.append(f"Max retries for {record['id']}")
                    else:
                        value = record["score"] * 1440  # F06 magic number
                        results.append({"id": record["id"], "value": value})
                else:
                    results.append({"id": record["id"], "value": 0})
            else:
                errors.append(f"Inactive record: {record.get('id', 'unknown')}")

    # More padding to exceed 50 lines
    summary = {
        "total": len(results),
        "errors": len(errors),
        "threshold": threshold,
        "limit": 500,          # F06 magic number
        "max_score": 9999,     # F06 magic number
    }

    if len(results) > 100:     # F06 magic number
        summary["truncated"] = True
        results = results[:100]  # F06 magic number

    return results, errors, summary


# F10 - SQL injection via f-string in cursor.execute
def get_user_by_id(user_id):
    """Vulnerable to SQL injection — F10."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Direct f-string interpolation — classic SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    row = cursor.fetchone()
    conn.close()
    return row


def search_users(username, role):
    """Also SQL-injectable — F10."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND role='{role}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows


# F15 - Additional exception swallowing examples
def load_config(path):
    try:
        with open(path) as fh:
            return fh.read()
    except Exception:
        pass  # F15 - silently swallowed


def parse_number(s):
    try:
        return int(s)
    except Exception:
        pass  # F15 - silently swallowed


# F16 - Additional resource leak
log_file = open("debug.log", "a")  # never closed
