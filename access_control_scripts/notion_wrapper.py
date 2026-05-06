#!/usr/bin/env python3
"""
Notion Operation Wrapper
Enforces access control before any Notion operation.

Usage:
    python3 notion_wrapper.py <sender_id> <operation> [query_params...]

Operations: query, create, update, delete

Returns: Result of check_authority.py, or executes the Notion operation if allowed.
"""

import sys
import json
import subprocess
from pathlib import Path

SKILL_DIR = Path(__file__).parent
CHECK_SCRIPT = SKILL_DIR / "check_authority.py"

OPERATION_MAP = {
    "query": "notion_query",
    "create": "notion_create",
    "update": "notion_update",
    "delete": "notion_delete",
}


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: notion_wrapper.py <sender_id> <operation> [query]"}))
        sys.exit(1)

    sender_id = sys.argv[1]
    operation = sys.argv[2]
    query = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""

    op_key = OPERATION_MAP.get(operation)
    if not op_key:
        print(json.dumps({"error": f"Unknown operation: {operation}. Use: query, create, update, delete"}))
        sys.exit(1)

    # Step 1: Run access control check
    result = subprocess.run(
        ["python3", str(CHECK_SCRIPT), sender_id, op_key, query],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
    )
    check = json.loads(result.stdout)

    if not check.get("allowed"):
        # Step 2: Log the blocked attempt
        subprocess.run(
            ["python3", str(SKILL_DIR / "audit_logger.py"),
             sender_id, op_key, "blocked", check.get("reason", "Unknown"), query]
        )
        print(json.dumps(check))
        sys.exit(1)

    # Step 3: Log the allowed attempt
    subprocess.run(
        ["python3", str(SKILL_DIR / "audit_logger.py"),
         sender_id, op_key, "allowed", check.get("reason", "Authorized"), query]
    )

    # Step 4: Return authorized — caller should proceed with actual Notion operation
    print(json.dumps({
        "authorized": True,
        "sender_id": sender_id,
        "operation": operation,
        "query": query,
        "check_result": check,
        "next_step": "Proceed with Notion API call"
    }))


if __name__ == "__main__":
    main()
