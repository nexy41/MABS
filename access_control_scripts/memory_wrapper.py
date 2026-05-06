#!/usr/bin/env python3
"""
Memory/Info Disclosure Wrapper
Enforces access control before reading memory files or disclosing personal info.

Usage:
    python3 memory_wrapper.py <sender_id> <operation> <target>

Operations: read_memory, read_memory_other, disclose_info
Targets: radit, ken, kc, aiman, or "self"
"""

import sys
import json
import subprocess
from pathlib import Path

SKILL_DIR = Path(__file__).parent
CHECK_SCRIPT = SKILL_DIR / "check_authority.py"


def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: memory_wrapper.py <sender_id> <operation> <target>"}))
        sys.exit(1)

    sender_id = sys.argv[1]
    operation = sys.argv[2]
    target = sys.argv[3]

    # Step 1: Access control check
    result = subprocess.run(
        ["python3", str(CHECK_SCRIPT), sender_id, operation, target],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
    )
    check = json.loads(result.stdout)

    if not check.get("allowed"):
        subprocess.run(
            ["python3", str(SKILL_DIR / "audit_logger.py"),
             sender_id, operation, "blocked", check.get("reason", "Unknown"), target]
        )
        print(json.dumps(check))
        sys.exit(1)

    # Step 2: Log allowed
    subprocess.run(
        ["python3", str(SKILL_DIR / "audit_logger.py"),
         sender_id, operation, "allowed", check.get("reason", "Authorized"), target]
    )

    print(json.dumps({
        "authorized": True,
        "sender_id": sender_id,
        "operation": operation,
        "target": target,
        "check_result": check,
        "next_step": "Proceed with memory read or info disclosure"
    }))


if __name__ == "__main__":
    main()
