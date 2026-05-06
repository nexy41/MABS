#!/usr/bin/env python3
"""
Access Control Pre-Flight Check
Validates whether a sender has sufficient authority level for a given operation.

Usage:
    python3 check_authority.py <sender_id> <operation> [data_target]

Operations: read_memory, read_memory_other, disclose_info, notion_query, notion_create,
            email_send, config_change, external_share, access_request

Returns: JSON with {allowed: bool, reason: str, sender_level: int, required_level: int}
"""

import sys
import json
import os
import re
from pathlib import Path

WORKSPACE = Path("/home/admin/.openclaw/workspace")
MEMORY_DIR = WORKSPACE / "memory"

# Authority level definitions
AUTH_LEVELS = {
    0: "Public",
    1: "Team",
    2: "Management",
    3: "Admin",
}

# Operation -> required authority level
OPERATION_LEVELS = {
    "read_memory": 0,       # Read own profile — public
    "read_memory_other": 2, # Read another user's profile — management+
    "disclose_info": 3,     # Disclose personal info (email, role, chat ID) — admin only
    "notion_query": 1,      # Query Notion — team+
    "notion_create": 3,     # Create Notion pages — admin only
    "notion_update": 3,     # Update Notion pages — admin only
    "notion_delete": 3,     # Delete Notion pages — admin only
    "email_send": 2,        # Send internal emails — management+
    "email_external": 3,    # Send external emails — admin only (blocked by policy)
    "config_change": 3,     # Gateway config changes — admin only
    "external_share": 3,    # Share data externally — admin only (blocked by policy)
    "access_request": 0,    # Request access — anyone can request
    "view_logs": 2,         # View system logs — management+
    "install_skill": 3,     # Install new skills — admin only
}

# Sensitivity classification for data targets
SENSITIVITY_LEVELS = {
    "public_info": 0,       # Public knowledge
    "team_profile": 1,      # Basic team member info
    "internal_data": 2,     # Internal company data
    "config": 3,            # System configuration
    "credentials": 3,       # API keys, passwords
}

# Known team member IDs
TEAM_IDS = {
    "1339285323": {"name": "Radit", "level": 3},
    "561800864": {"name": "Ken", "level": 3},
    "887653778": {"name": "Aiman", "level": 2},
}


def load_team_profiles():
    """Load authority levels from team profile files."""
    profiles = dict(TEAM_IDS)  # start with hardcoded defaults
    for f in MEMORY_DIR.glob("team-*.md"):
        try:
            content = f.read_text()
            # Extract Telegram ID
            id_match = re.search(r"Telegram ID[:\s]+(\d+)", content)
            level_match = re.search(r"authority_level[\"'\s:]+(\d+)", content)
            if id_match and level_match:
                tid = id_match.group(1)
                level = int(level_match.group(1))
                profiles[tid] = {"level": level}
        except Exception:
            pass
    return profiles


def get_sender_level(sender_id, profiles):
    """Get authority level for a sender."""
    sid = str(sender_id)
    if sid in profiles:
        return profiles[sid].get("level", 0)
    return 0  # Unknown = public


def check(sender_id, operation, data_target=None):
    """
    Check if sender has authority for the operation.
    Returns (allowed, reason, sender_level, required_level)
    """
    profiles = load_team_profiles()
    sender_level = get_sender_level(sender_id, profiles)
    required_level = OPERATION_LEVELS.get(operation, 2)  # default to management

    # Special case: read_memory_other for own profile is fine
    if operation == "read_memory_other" and data_target:
        target_name = data_target.lower()
        # If user is reading their own profile, allow
        user_profiles = {
            "radit": "1339285323",
            "ken": "561800864",
            "kc": "561800864",
            "kenneth": "561800864",
            "aiman": "887653778",
        }
        target_id = user_profiles.get(target_name)
        if target_id == str(sender_id):
            return True, "Accessing own profile", sender_level, 0

    # External email/share — always block regardless of level
    if operation in ("email_external", "external_share"):
        return False, "External sharing blocked by policy — requires @ainexor.com domain only", sender_level, required_level

    if sender_level >= required_level:
        return True, f"Level {sender_level} ({AUTH_LEVELS.get(sender_level, 'Unknown')} >= {AUTH_LEVELS.get(required_level, 'Unknown')})", sender_level, required_level

    return False, f"Insufficient authority: Level {sender_level} < required Level {required_level}", sender_level, required_level


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: check_authority.py <sender_id> <operation> [data_target]"}))
        sys.exit(1)

    sender_id = sys.argv[1]
    operation = sys.argv[2]
    data_target = sys.argv[3] if len(sys.argv) > 3 else None

    allowed, reason, sender_level, required_level = check(sender_id, operation, data_target)

    result = {
        "allowed": allowed,
        "reason": reason,
        "sender_id": sender_id,
        "sender_level": sender_level,
        "required_level": required_level,
        "operation": operation,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
