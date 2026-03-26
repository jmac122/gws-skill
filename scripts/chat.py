#!/usr/bin/env python3
"""Google Chat API — read spaces and messages via domain-wide delegation."""

import argparse
import json
import sys
from typing import Optional

from auth import get_service


def list_spaces(user: str) -> dict:
    """List Chat spaces the user is a member of.

    Args:
        user: Email address (impersonated via DWD).

    Returns:
        Dict with space list.
    """
    service = get_service("chat", impersonate=user)
    results = service.spaces().list().execute()
    spaces = results.get("spaces", [])

    return {
        "user": user,
        "total": len(spaces),
        "spaces": [
            {
                "name": s.get("name", ""),
                "display_name": s.get("displayName", ""),
                "type": s.get("spaceType", s.get("type", "")),
                "single_user_bot_dm": s.get("singleUserBotDm", False),
                "threaded": s.get("threaded", False),
            }
            for s in spaces
        ],
    }


def list_messages(
    user: str,
    space_name: str,
    max_results: int = 25,
) -> dict:
    """List messages in a Chat space.

    Args:
        user: Email address.
        space_name: Space resource name (e.g. 'spaces/AAAA').
        max_results: Max messages to return.

    Returns:
        Dict with message list.
    """
    service = get_service("chat", impersonate=user)
    results = service.spaces().messages().list(
        parent=space_name,
        pageSize=max_results,
    ).execute()
    messages = results.get("messages", [])

    return {
        "user": user,
        "space": space_name,
        "total": len(messages),
        "messages": [
            {
                "name": m.get("name", ""),
                "sender": m.get("sender", {}).get("displayName", m.get("sender", {}).get("name", "")),
                "text": m.get("text", ""),
                "create_time": m.get("createTime", ""),
                "thread_name": m.get("thread", {}).get("name", ""),
            }
            for m in messages
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Google Chat read")
    sub = parser.add_subparsers(dest="command", required=True)

    # spaces
    p_spaces = sub.add_parser("spaces", help="List Chat spaces")
    p_spaces.add_argument("--user", required=True)

    # messages
    p_msgs = sub.add_parser("messages", help="List messages in a space")
    p_msgs.add_argument("--user", required=True)
    p_msgs.add_argument("--space", required=True, help="Space resource name")
    p_msgs.add_argument("--max", type=int, default=25)

    args = parser.parse_args()

    try:
        if args.command == "spaces":
            result = list_spaces(args.user)
        elif args.command == "messages":
            result = list_messages(args.user, args.space, args.max)
        else:
            result = {"error": f"Unknown command: {args.command}"}

        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
