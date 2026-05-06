#!/usr/bin/env python3
"""
Audit Enforcement Logger
Logs every access control check (allowed or blocked) to NexLog.

Usage:
    python3 audit_logger.py <sender_id> <operation> <result> <reason> [data_target]

Output: Formatted log entry ready for sessions_send to NexLog
"""

import sys
import json
from datetime import datetime, timezone, timedelta

# KL timezone (GMT+8)
KL_TZ = timezone(timedelta(hours=8))

# Severity classification
SEVERITY_MAP = {
    ("blocked", "email_external"): "HIGH",
    ("blocked", "external_share"): "HIGH",
    ("blocked", "config_change"): "HIGH",
    ("blocked", "notion_create"): "MEDIUM",
    ("blocked", "notion_update"): "MEDIUM",
    ("blocked", "notion_delete"): "MEDIUM",
    ("blocked", "disclose_info"): "MEDIUM",
    ("allowed", "config_change"): "LOW",
    ("allowed", "notion_create"): "LOW",
    ("allowed", "notion_update"): "LOW",
}

# Known user names
USER_NAMES = {
    "1339285323": "Radit",
    "561800864": "Ken",
    "887653778": "Aiman",
}


def main():
    if len(sys.argv) < 5:
        print(json.dumps({"error": "Usage: audit_logger.py <sender_id> <operation> <result> <reason> [data_target]"}))
        sys.exit(1)

    sender_id = sys.argv[1]
    operation = sys.argv[2]
    result = sys.argv[3]  # "allowed" or "blocked"
    reason = sys.argv[4]
    data_target = sys.argv[5] if len(sys.argv) > 5 else "N/A"

    timestamp = datetime.now(KL_TZ).strftime("%Y-%m-%d %H:%M:%S KL")
    user_name = USER_NAMES.get(sender_id, f"Unknown ({sender_id})")
    severity = SEVERITY_MAP.get((result, operation), "INFO")

    log_entry = {
        "timestamp": timestamp,
        "user_id": sender_id,
        "user_name": user_name,
        "operation": operation,
        "data_target": data_target,
        "result": result,
        "reason": reason,
        "severity": severity,
    }

    # Output formatted log line for NexLog
    status_icon = "✅" if result == "allowed" else "🚫"
    formatted = f"{status_icon} **{severity}** | {timestamp} | {user_name} (`{sender_id}`)\n   Operation: `{operation}` | Target: `{data_target}`\n   Result: **{result.upper()}** — {reason}"

    output = {
        "log_entry": log_entry,
        "formatted": formatted,
        "nexlog_message": f"ACCESS AUDIT: {json.dumps(log_entry)}",
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
