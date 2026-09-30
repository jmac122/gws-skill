#!/usr/bin/env python3
"""Admin SDK Directory API — READ-ONLY users, groups, OUs.

Write actions live in admin.py (dry run by default).
"""

import argparse
import json
import sys
from typing import Optional

from auth import get_service, domain as default_domain


def _scope_kwargs(domain: Optional[str]) -> dict:
    """Use the given/GWS_DOMAIN domain, else the whole account (my_customer).

    Previously an unset GWS_DOMAIN sent domain="" and the API rejected it.
    """
    d = domain or default_domain()
    return {"domain": d} if d else {"customer": "my_customer"}


def _paginate(request_fn, key: str, max_results: int, page_cap: int) -> list:
    """Follow nextPageToken until max_results items are collected."""
    items, token = [], None
    while len(items) < max_results:
        resp = request_fn(min(page_cap, max_results - len(items)), token).execute()
        items.extend(resp.get(key, []))
        token = resp.get("nextPageToken")
        if not token:
            break
    return items[:max_results]


def list_users(
    domain: Optional[str] = None,
    max_results: int = 100,
    query: Optional[str] = None,
    order_by: str = "email",
) -> dict:
    """List all users in the domain.

    Args:
        domain: Domain to list users for. Defaults to GWS_DOMAIN.
        max_results: Max users to return.
        query: Search query (name, email prefix, org unit, etc).
        order_by: Sort by 'email', 'familyName', or 'givenName'.

    Returns:
        Dict with user list.
    """
    service = get_service("directory")
    kwargs = {**_scope_kwargs(domain), "orderBy": order_by}
    if query:
        kwargs["query"] = query

    users = _paginate(
        lambda n, t: service.users().list(maxResults=n, pageToken=t, **kwargs),
        "users", max_results, 500,
    )

    return {
        "total": len(users),
        "users": [
            {
                "email": u.get("primaryEmail", ""),
                "name": u.get("name", {}).get("fullName", ""),
                "first_name": u.get("name", {}).get("givenName", ""),
                "last_name": u.get("name", {}).get("familyName", ""),
                "org_unit": u.get("orgUnitPath", ""),
                "is_admin": u.get("isAdmin", False),
                "is_suspended": u.get("suspended", False),
                "last_login": u.get("lastLoginTime", ""),
                "creation_time": u.get("creationTime", ""),
            }
            for u in users
        ],
    }


def get_user(email: str) -> dict:
    """Get details for a specific user.

    Args:
        email: User's email address.

    Returns:
        User details dict.
    """
    service = get_service("directory")
    u = service.users().get(userKey=email).execute()

    return {
        "email": u.get("primaryEmail", ""),
        "name": u.get("name", {}).get("fullName", ""),
        "first_name": u.get("name", {}).get("givenName", ""),
        "last_name": u.get("name", {}).get("familyName", ""),
        "org_unit": u.get("orgUnitPath", ""),
        "is_admin": u.get("isAdmin", False),
        "is_delegated_admin": u.get("isDelegatedAdmin", False),
        "is_suspended": u.get("suspended", False),
        "last_login": u.get("lastLoginTime", ""),
        "creation_time": u.get("creationTime", ""),
        "aliases": u.get("aliases", []),
        "phones": u.get("phones", []),
        "recovery_email": u.get("recoveryEmail", ""),
        "is_2sv_enforced": u.get("isEnforcedIn2Sv", False),
        "is_2sv_enrolled": u.get("isEnrolledIn2Sv", False),
    }


def list_groups(
    domain: Optional[str] = None,
    max_results: int = 200,
) -> dict:
    """List all groups in the domain.

    Args:
        domain: Domain to list groups for.
        max_results: Max groups to return.

    Returns:
        Dict with group list.
    """
    service = get_service("directory")
    kwargs = _scope_kwargs(domain)
    groups = _paginate(
        lambda n, t: service.groups().list(maxResults=n, pageToken=t, **kwargs),
        "groups", max_results, 200,
    )

    return {
        "total": len(groups),
        "groups": [
            {
                "email": g.get("email", ""),
                "name": g.get("name", ""),
                "description": g.get("description", ""),
                "member_count": int(g.get("directMembersCount", 0)),
            }
            for g in groups
        ],
    }


def list_group_members(
    group_email: str,
    max_results: int = 200,
) -> dict:
    """List members of a specific group.

    Args:
        group_email: Group email address.
        max_results: Max members to return.

    Returns:
        Dict with member list.
    """
    service = get_service("directory")
    members = _paginate(
        lambda n, t: service.members().list(groupKey=group_email, maxResults=n, pageToken=t),
        "members", max_results, 200,
    )

    return {
        "group": group_email,
        "total": len(members),
        "members": [
            {
                "email": m.get("email", ""),
                "role": m.get("role", ""),
                "type": m.get("type", ""),
                "status": m.get("status", ""),
            }
            for m in members
        ],
    }


def list_org_units() -> dict:
    """List all organizational units.

    Returns:
        Dict with OU list.
    """
    service = get_service("directory")
    results = service.orgunits().list(
        customerId="my_customer",
        type="all",
    ).execute()
    ous = results.get("organizationUnits", [])

    return {
        "total": len(ous),
        "org_units": [
            {
                "name": ou.get("name", ""),
                "path": ou.get("orgUnitPath", ""),
                "id": ou.get("orgUnitId", ""),
                "parent_path": ou.get("parentOrgUnitPath", ""),
                "description": ou.get("description", ""),
            }
            for ou in ous
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="GWS Directory API")
    sub = parser.add_subparsers(dest="command", required=True)

    # users
    p_users = sub.add_parser("users", help="List users")
    p_users.add_argument("--query", help="Search query")
    p_users.add_argument("--max", type=int, default=100)

    # user
    p_user = sub.add_parser("user", help="Get user details")
    p_user.add_argument("email", help="User email address")

    # groups
    p_groups = sub.add_parser("groups", help="List groups")
    p_groups.add_argument("--max", type=int, default=200)

    # members
    p_members = sub.add_parser("members", help="List group members")
    p_members.add_argument("group", help="Group email address")
    p_members.add_argument("--max", type=int, default=200)

    # orgunits
    sub.add_parser("orgunits", help="List org units")

    args = parser.parse_args()

    try:
        if args.command == "users":
            result = list_users(query=args.query, max_results=args.max)
        elif args.command == "user":
            result = get_user(args.email)
        elif args.command == "groups":
            result = list_groups(max_results=args.max)
        elif args.command == "members":
            result = list_group_members(args.group, max_results=args.max)
        elif args.command == "orgunits":
            result = list_org_units()
        else:
            result = {"error": f"Unknown command: {args.command}"}

        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
