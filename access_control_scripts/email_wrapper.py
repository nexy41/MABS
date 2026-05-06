#!/usr/bin/env python3
"""
Email Operation Wrapper
Enforces access control before any email send operation.

Usage:
    python3 email_wrapper.py <sender_id> <recipient> <operation>

Operations: send_internal, send_external
"""

import sys
import json
import subprocess
import re
from pathlib import Path

SKILL_DIR = Path(__file__).parent
CHECK_SCRIPT = SKILL_DIR / "check_authority.py"

ALLOWED_DOMAIN = "ainexor.com"


def validate_domain(email):
    """Check if email is within @ainexor.com domain."""
    return email.lower().endswith(f"@{ALLOWED_DOMAIN}")


def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: email_wrapper.py <sender_id> <recipient> <operation>"}))
        sys.exit(1)

    sender_id = sys.argv[1]
    recipient = sys.argv[2]
    operation = sys.argv[3]  # send_internal or send_external

    # Step 0: Domain validation — block external emails regardless of level
    if operation == "send_external" or not validate_domain(recipient):
        result = subprocess.run(
            ["python3", str(CHECK_SCRIPT), sender_id, "email_external", recipient],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        check = json.loads(result.stdout)
        check["blocked_reason"] = f"External email blocked — only @{ALLOWED_DOMAIN} allowed"

        # Log the blocked attempt
        subprocess.run(
            ["python3", str(SKILL_DIR / "audit_logger.py"),
             sender_id, "email_external", "blocked", check["blocked_reason"], recipient]
        )
        print(json.dumps(check))
        sys.exit(1)

    # Step 1: Access control check for internal email
    result = subprocess.run(
        ["python3", str(CHECK_SCRIPT), sender_id, "email_send", recipient],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
    )
    check = json.loads(result.stdout)

    if not check.get("allowed"):
        subprocess.run(
            ["python3", str(SKILL_DIR / "audit_logger.py"),
             sender_id, "email_send", "blocked", check.get("reason", "Unknown"), recipient]
        )
        print(json.dumps(check))
        sys.exit(1)

    # Step 2: Log allowed
    subprocess.run(
        ["python3", str(SKILL_DIR / "audit_logger.py"),
         sender_id, "email_send", "allowed", check.get("reason", "Authorized"), recipient]
    )

    print(json.dumps({
        "authorized": True,
        "sender_id": sender_id,
        "recipient": recipient,
        "operation": operation,
        "check_result": check,
        "next_step": "Proceed with email send via gog gmail"
    }))


if __name__ == "__main__":
    main()
