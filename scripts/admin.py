#!/usr/bin/env python3
"""Admin SDK Directory API — WRITE actions (users, groups, org units).

SAFETY MODEL
  * Every command is a DRY RUN by default: it reads the current state and
    prints a JSON preview (action, target, before, exact request, warnings,
    plan_id). Nothing is changed.
  * ``--apply`` performs the change, but only with ``--plan-id`` equal to that
    preview. A missing id is refused before any API call; a mismatched id is
    refused and no mutating call is made.
  * Destructive actions (user delete, make-admin/revoke-admin, group delete,
    OU delete) additionally need ``--confirm <exact target>`` with --apply.
    That check runs before any API call.
  * The tool refuses to delete, suspend, sign out, reset the password of, or
    revoke admin from the account it impersonates (GWS_ADMIN_EMAIL). The raw
    target string is checked first; after the user record is fetched, primary
    email, aliases, and nonEditableAliases are checked too (an alias or numeric
    id cannot bypass it).
  * Every --apply attempt (success, failure, or refusal — including a refusal
    or error while planning) is appended to a JSONL audit log
    (~/.config/gws/audit.log, override with GWS_AUDIT_LOG). Passwords and
    request bodies are never logged. ``--apply`` refuses before mutating if
    that log is not writable.
  * Generated temporary passwords are printed exactly once, in the --apply
    output. Dry runs never generate or show a password.

Exit codes: 0 ok / dry run, 1 API or unexpected error, 2 refused (safety check).
"""

import argparse
import hashlib
import json
import os
import secrets
import string
import sys
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from auth import admin_email, get_service

try:  # googleapiclient is always installed in real use; tolerate absence for --help
    from googleapiclient.errors import HttpError
except ImportError:  # pragma: no cover
    HttpError = Exception  # type: ignore

CUSTOMER = "my_customer"
DEFAULT_AUDIT_LOG = os.path.expanduser("~/.config/gws/audit.log")
PASSWORD_PLACEHOLDER = "<generated on --apply; printed once>"
MEMBER_ROLES = ("MEMBER", "MANAGER", "OWNER")

# Actions that need --confirm <target> in addition to --apply.
CONFIRM_REQUIRED = {"user.delete", "user.make_admin", "user.revoke_admin", "group.delete", "ou.delete"}

# Never run these against the impersonated admin (matched again after the user fetch).
SELF_PROTECTED = {"user.delete", "user.suspend", "user.revoke_admin", "user.signout", "user.reset_password"}

# Dropped from ``before`` before the plan fingerprint is hashed.
_FINGERPRINT_VOLATILE = {"lastLoginTime", "etag", "kind"}

WARNINGS = {
    "user.delete": "DESTRUCTIVE: deletes the user account and (after 20 days) its data. "
                   "Consider suspend or transferring data first. Recoverable only via users.undelete within ~20 days.",
    "user.suspend": "DESTRUCTIVE: the user is immediately blocked from signing in and loses access to all services.",
    "user.make_admin": "DESTRUCTIVE/SECURITY: grants SUPER ADMIN (full control of the whole Workspace domain).",
    "user.revoke_admin": "DESTRUCTIVE/SECURITY: removes super admin rights; make sure another super admin remains.",
    "user.signout": "DESTRUCTIVE: signs the user out of ALL web and device sessions and resets sign-in cookies.",
    "user.reset_password": "DISRUPTIVE: replaces the user's password; they must use the new temporary password "
                           "and change it at next login.",
    "group.delete": "DESTRUCTIVE: deletes the group, its membership and its settings/archive. Not recoverable via API.",
    "ou.delete": "DESTRUCTIVE: deletes the org unit. It must be empty (no users, devices, or child OUs).",
    "user.update": "Repeated fields (organizations, phones, relations) are replaced as a whole; "
                   "the body below already merges existing entries.",
    "group.remove_member": "The member loses access to anything shared with this group.",
    "ou.update": "Renaming or moving an OU changes its path and the path of all child OUs.",
}

USER_FIELDS = ("primaryEmail", "id", "name", "suspended", "suspensionReason", "isAdmin",
               "isDelegatedAdmin", "orgUnitPath", "aliases", "organizations", "phones",
               "relations", "changePasswordAtNextLogin", "archived", "lastLoginTime")
GROUP_FIELDS = ("email", "id", "name", "description", "directMembersCount", "aliases", "adminCreated")
MEMBER_FIELDS = ("email", "id", "role", "type", "status", "delivery_settings")
OU_FIELDS = ("orgUnitPath", "orgUnitId", "name", "description", "parentOrgUnitPath", "blockInheritance")


class Refused(Exception):
    """A safety check refused the action."""


# --------------------------------------------------------------------------- helpers

def generate_password(length: int = 20) -> str:
    """Strong random temp password (Directory API accepts 8-100 chars)."""
    if length < 12:
        raise ValueError("length must be >= 12")
    alphabet = string.ascii_letters + string.digits + "!#$%&*+-=?@^_~"
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!#$%&*+-=?@^_~"]
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


def _pick(obj: Optional[dict], fields) -> Optional[dict]:
    if obj is None:
        return None
    return {k: obj[k] for k in fields if k in obj}


def _is_404(err: Exception) -> bool:
    status = getattr(getattr(err, "resp", None), "status", None)
    return str(status) == "404"


def _get_or_none(fn: Callable[[], Any]) -> Optional[dict]:
    try:
        return fn()
    except HttpError as e:  # type: ignore[misc]
        if _is_404(e):
            return None
        raise


def _ou_key(path: str) -> str:
    """orgunits.get/patch/delete take the path WITHOUT the leading '/' (or an id)."""
    return path[1:] if path.startswith("/") else path


def _norm_ou(path: str) -> str:
    if path.startswith("id:"):
        return path
    return "/" + path.strip("/") if path.strip("/") else "/"


def _audit_path(path: Optional[str] = None) -> str:
    return path or os.environ.get("GWS_AUDIT_LOG") or DEFAULT_AUDIT_LOG


def _ensure_audit_parent(path: str) -> None:
    """Create the audit log's parent. A bare filename (``audit.log``) has none."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)


def audit(entry: dict, path: Optional[str] = None) -> None:
    """Append one JSONL line to the audit log. Never raises; never logs secrets."""
    path = _audit_path(path)
    line = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **entry}
    try:
        _ensure_audit_parent(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError as e:
        print(json.dumps({"warning": f"could not write audit log {path}: {e}"}), file=sys.stderr)


def _audit_writable(path: Optional[str] = None) -> None:
    """Raise Refused if this apply could not be recorded. Call before any mutation."""
    path = _audit_path(path)
    try:
        _ensure_audit_parent(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
    except OSError as e:
        raise Refused(f"audit log not writable: {path}: {e}") from e


def _redact(body: Any) -> Any:
    if isinstance(body, dict):
        return {k: ("<redacted>" if k == "password" else _redact(v)) for k, v in body.items()}
    if isinstance(body, list):
        return [_redact(v) for v in body]
    return body


# --------------------------------------------------------------------------- plan model
#
# A plan is a plain dict:
#   action   e.g. "user.suspend"
#   target   the string --confirm must match
#   before   relevant current state (None = does not exist)
#   request  {"resource": "users" | "users.aliases" | ..., "method": ..., "params": {...}, "body": {...}|None}
#   warning  optional string
#   noop     optional reason why nothing needs to change
#   needs_password  True if body["password"] must be generated on --apply


def _plan(action, target, before, resource, method, params, body=None, **extra) -> dict:
    p = {
        "action": action,
        "target": target,
        "before": before,
        "request": {"resource": resource, "method": method, "params": params, "body": body},
    }
    if action in WARNINGS:
        p["warning"] = WARNINGS[action]
    p["requires_confirm"] = action in CONFIRM_REQUIRED
    p.update(extra)
    return p


def _guard_self(action: str, target: str) -> None:
    """Cheap check: the raw target string is the admin email this tool impersonates."""
    me = admin_email().lower()
    if me and target.lower() == me and action in SELF_PROTECTED:
        raise Refused(f"Refusing {action} on the GWS_ADMIN_EMAIL account ({target}) this tool impersonates.")


def _guard_self_record(action: str, user_record: Optional[dict]) -> None:
    """Post-fetch check so an alias or numeric user id cannot bypass self-protection.

    Refuses when GWS_ADMIN_EMAIL (case-insensitive) is the record's primaryEmail
    or is listed in its aliases or nonEditableAliases.
    """
    if action not in SELF_PROTECTED or not user_record:
        return
    me = admin_email().lower()
    if not me:
        return
    emails = []
    primary = user_record.get("primaryEmail")
    if isinstance(primary, str) and primary:
        emails.append(primary)
    for key in ("aliases", "nonEditableAliases"):
        vals = user_record.get(key) or []
        if isinstance(vals, str):
            vals = [vals]
        emails.extend(v for v in vals if isinstance(v, str) and v)
    if any(e.lower() == me for e in emails):
        shown = primary if isinstance(primary, str) and primary else admin_email()
        raise Refused(f"Refusing {action} on the GWS_ADMIN_EMAIL account ({shown}) this tool impersonates.")


# ---- users

def _get_user(svc, email):
    return _get_or_none(lambda: svc.users().get(userKey=email, projection="full").execute())


def _require(obj, what):
    if obj is None:
        raise Refused(f"{what} not found")
    return obj


def plan_user_create(svc, email, first, last, ou="/", title=None, department=None,
                     phone=None, manager=None, recovery_email=None):
    before = _get_user(svc, email)
    if before is not None:
        raise Refused(f"User {email} already exists")
    body = {
        "primaryEmail": email,
        "name": {"givenName": first, "familyName": last},
        "password": PASSWORD_PLACEHOLDER,
        "changePasswordAtNextLogin": True,
        "orgUnitPath": _norm_ou(ou),
    }
    if title or department:
        org = {"primary": True}
        if title:
            org["title"] = title
        if department:
            org["department"] = department
        body["organizations"] = [org]
    if phone:
        body["phones"] = [{"type": "work", "value": phone, "primary": True}]
    if manager:
        body["relations"] = [{"type": "manager", "value": manager}]
    if recovery_email:
        body["recoveryEmail"] = recovery_email
    return _plan("user.create", email, None, "users", "insert", {}, body, needs_password=True)


def _merge_org(existing, title, department):
    orgs = deepcopy(existing or [])
    idx = next((i for i, o in enumerate(orgs) if o.get("primary")), 0 if orgs else None)
    if idx is None:
        orgs.append({"primary": True})
        idx = 0
    if title is not None:
        orgs[idx]["title"] = title
    if department is not None:
        orgs[idx]["department"] = department
    return orgs


def _merge_phone(existing, phone):
    phones = [p for p in deepcopy(existing or []) if not (p.get("type") == "work" and p.get("primary"))]
    for p in phones:
        p.pop("primary", None)
    return [{"type": "work", "value": phone, "primary": True}] + phones


def _merge_manager(existing, manager):
    rels = [r for r in deepcopy(existing or []) if r.get("type") != "manager"]
    return rels + [{"type": "manager", "value": manager}]


def plan_user_update(svc, email, first=None, last=None, title=None, department=None,
                     phone=None, manager=None):
    before = _require(_get_user(svc, email), f"User {email}")
    body = {}
    if first is not None or last is not None:
        body["name"] = {}
        if first is not None:
            body["name"]["givenName"] = first
        if last is not None:
            body["name"]["familyName"] = last
    if title is not None or department is not None:
        body["organizations"] = _merge_org(before.get("organizations"), title, department)
    if phone is not None:
        body["phones"] = _merge_phone(before.get("phones"), phone)
    if manager is not None:
        body["relations"] = _merge_manager(before.get("relations"), manager)
    if not body:
        raise Refused("Nothing to update: pass at least one of --first/--last/--title/--department/--phone/--manager")
    fields = ["primaryEmail", "name"] + [k for k in body if k != "name"]
    return _plan("user.update", email, _pick(before, fields), "users", "update", {"userKey": email}, body)


def _user_flag_plan(svc, action, email, body, before_fields, noop_if=None):
    _guard_self(action, email)
    before = _require(_get_user(svc, email), f"User {email}")
    _guard_self_record(action, before)
    extra = {}
    if noop_if and noop_if(before):
        extra["noop"] = "user is already in the requested state"
    return _plan(action, email, _pick(before, before_fields), "users", "update",
                 {"userKey": email}, body, **extra)


def plan_user_suspend(svc, email):
    return _user_flag_plan(svc, "user.suspend", email, {"suspended": True},
                           ("primaryEmail", "suspended", "suspensionReason", "isAdmin"),
                           lambda b: b.get("suspended") is True)


def plan_user_unsuspend(svc, email):
    return _user_flag_plan(svc, "user.unsuspend", email, {"suspended": False},
                           ("primaryEmail", "suspended", "suspensionReason"),
                           lambda b: not b.get("suspended"))


def plan_user_reset_password(svc, email):
    p = _user_flag_plan(svc, "user.reset_password", email,
                        {"password": PASSWORD_PLACEHOLDER, "changePasswordAtNextLogin": True},
                        ("primaryEmail", "suspended", "changePasswordAtNextLogin", "lastLoginTime"))
    p["needs_password"] = True
    return p


def plan_user_move(svc, email, ou):
    ou = _norm_ou(ou)
    return _user_flag_plan(svc, "user.move", email, {"orgUnitPath": ou},
                           ("primaryEmail", "orgUnitPath"),
                           lambda b: b.get("orgUnitPath") == ou)


def plan_user_signout(svc, email):
    _guard_self("user.signout", email)
    before = _require(_get_user(svc, email), f"User {email}")
    _guard_self_record("user.signout", before)
    return _plan("user.signout", email, _pick(before, ("primaryEmail", "suspended", "lastLoginTime")),
                 "users", "signOut", {"userKey": email}, None)


def plan_user_admin(svc, email, grant: bool):
    action = "user.make_admin" if grant else "user.revoke_admin"
    _guard_self(action, email)
    before = _require(_get_user(svc, email), f"User {email}")
    if not grant:
        _guard_self_record(action, before)
    extra = {}
    if bool(before.get("isAdmin")) == grant:
        extra["noop"] = f"isAdmin is already {grant}"
    return _plan(action, email, _pick(before, ("primaryEmail", "isAdmin", "isDelegatedAdmin", "suspended")),
                 "users", "makeAdmin", {"userKey": email}, {"status": grant}, **extra)


def plan_alias_add(svc, email, alias):
    before = _require(_get_user(svc, email), f"User {email}")
    extra = {}
    if alias.lower() in [a.lower() for a in before.get("aliases", [])]:
        extra["noop"] = "alias already present"
    return _plan("user.add_alias", email, _pick(before, ("primaryEmail", "aliases")),
                 "users.aliases", "insert", {"userKey": email}, {"alias": alias}, **extra)


def plan_alias_remove(svc, email, alias):
    before = _require(_get_user(svc, email), f"User {email}")
    if alias.lower() not in [a.lower() for a in before.get("aliases", [])]:
        raise Refused(f"{alias} is not an alias of {email}")
    return _plan("user.remove_alias", email, _pick(before, ("primaryEmail", "aliases")),
                 "users.aliases", "delete", {"userKey": email, "alias": alias}, None)


def plan_user_delete(svc, email):
    _guard_self("user.delete", email)
    before = _require(_get_user(svc, email), f"User {email}")
    _guard_self_record("user.delete", before)
    return _plan("user.delete", email, _pick(before, USER_FIELDS), "users", "delete", {"userKey": email}, None)


# ---- groups

def _get_group(svc, email):
    return _get_or_none(lambda: svc.groups().get(groupKey=email).execute())


def _get_member(svc, group, member):
    return _get_or_none(lambda: svc.members().get(groupKey=group, memberKey=member).execute())


def _role(role):
    role = (role or "MEMBER").upper()
    if role not in MEMBER_ROLES:
        raise Refused(f"role must be one of {', '.join(MEMBER_ROLES)}")
    return role


def plan_group_create(svc, email, name, description=None):
    if _get_group(svc, email) is not None:
        raise Refused(f"Group {email} already exists")
    body = {"email": email, "name": name}
    if description is not None:
        body["description"] = description
    return _plan("group.create", email, None, "groups", "insert", {}, body)


def plan_group_update(svc, email, name=None, description=None):
    before = _require(_get_group(svc, email), f"Group {email}")
    body = {}
    if name is not None:
        body["name"] = name
    if description is not None:
        body["description"] = description
    if not body:
        raise Refused("Nothing to update: pass --name and/or --description")
    return _plan("group.update", email, _pick(before, ("email", "name", "description")),
                 "groups", "patch", {"groupKey": email}, body)


def plan_group_delete(svc, email):
    before = _require(_get_group(svc, email), f"Group {email}")
    return _plan("group.delete", email, _pick(before, GROUP_FIELDS), "groups", "delete", {"groupKey": email}, None)


def plan_member_add(svc, group, member, role="MEMBER"):
    role = _role(role)
    g = _require(_get_group(svc, group), f"Group {group}")
    existing = _get_member(svc, group, member)
    if existing is not None:
        raise Refused(f"{member} is already a member of {group} (role {existing.get('role')}); use set-role")
    return _plan("group.add_member", f"{group}:{member}",
                 {"group": _pick(g, ("email", "name", "directMembersCount")), "member": None},
                 "members", "insert", {"groupKey": group}, {"email": member, "role": role})


def plan_member_remove(svc, group, member):
    existing = _require(_get_member(svc, group, member), f"Member {member} of {group}")
    return _plan("group.remove_member", f"{group}:{member}", _pick(existing, MEMBER_FIELDS),
                 "members", "delete", {"groupKey": group, "memberKey": member}, None)


def plan_member_role(svc, group, member, role):
    role = _role(role)
    existing = _require(_get_member(svc, group, member), f"Member {member} of {group}")
    extra = {"noop": f"role is already {role}"} if existing.get("role") == role else {}
    return _plan("group.set_role", f"{group}:{member}", _pick(existing, MEMBER_FIELDS),
                 "members", "patch", {"groupKey": group, "memberKey": member}, {"role": role}, **extra)


# ---- org units

def _get_ou(svc, path):
    return _get_or_none(lambda: svc.orgunits().get(customerId=CUSTOMER, orgUnitPath=_ou_key(path)).execute())


def plan_ou_create(svc, name, parent="/", description=None):
    parent = _norm_ou(parent)
    full = (parent.rstrip("/") + "/" + name)
    if _get_ou(svc, full) is not None:
        raise Refused(f"Org unit {full} already exists")
    if parent != "/" and _get_ou(svc, parent) is None:
        raise Refused(f"Parent org unit {parent} not found")
    body = {"name": name, "parentOrgUnitPath": parent}
    if description is not None:
        body["description"] = description
    return _plan("ou.create", full, None, "orgunits", "insert", {"customerId": CUSTOMER}, body)


def plan_ou_update(svc, path, name=None, parent=None, description=None):
    path = _norm_ou(path)
    if path == "/":
        raise Refused("The root org unit cannot be renamed or moved")
    before = _require(_get_ou(svc, path), f"Org unit {path}")
    body = {}
    if name is not None:
        body["name"] = name
    if parent is not None:
        body["parentOrgUnitPath"] = _norm_ou(parent)
    if description is not None:
        body["description"] = description
    if not body:
        raise Refused("Nothing to update: pass --name, --parent and/or --description")
    new_path = (body.get("parentOrgUnitPath", before.get("parentOrgUnitPath", "/")).rstrip("/")
                + "/" + body.get("name", before.get("name", "")))
    return _plan("ou.update", path, _pick(before, OU_FIELDS), "orgunits", "patch",
                 {"customerId": CUSTOMER, "orgUnitPath": _ou_key(path)}, body, resulting_path=new_path)


def plan_ou_delete(svc, path):
    path = _norm_ou(path)
    if path == "/":
        raise Refused("The root org unit cannot be deleted")
    before = _require(_get_ou(svc, path), f"Org unit {path}")
    return _plan("ou.delete", path, _pick(before, OU_FIELDS), "orgunits", "delete",
                 {"customerId": CUSTOMER, "orgUnitPath": _ou_key(path)}, None)


# --------------------------------------------------------------------------- execution

_PLAN_FN_ACTIONS = {
    plan_user_create: "user.create",
    plan_user_update: "user.update",
    plan_user_suspend: "user.suspend",
    plan_user_unsuspend: "user.unsuspend",
    plan_user_reset_password: "user.reset_password",
    plan_user_move: "user.move",
    plan_user_signout: "user.signout",
    plan_alias_add: "user.add_alias",
    plan_alias_remove: "user.remove_alias",
    plan_user_delete: "user.delete",
    plan_group_create: "group.create",
    plan_group_update: "group.update",
    plan_group_delete: "group.delete",
    plan_member_add: "group.add_member",
    plan_member_remove: "group.remove_member",
    plan_member_role: "group.set_role",
    plan_ou_create: "ou.create",
    plan_ou_update: "ou.update",
    plan_ou_delete: "ou.delete",
}


def _audit_subject(plan_fn, args, action_hint, target_hint):
    """Action and target for an audit line when planning never returned a plan."""
    if action_hint:
        action = action_hint
    elif plan_fn is plan_user_admin:
        grant = bool(args[1]) if len(args) > 1 else False
        action = "user.make_admin" if grant else "user.revoke_admin"
    else:
        action = _PLAN_FN_ACTIONS.get(plan_fn, getattr(plan_fn, "__name__", "unknown"))
    if target_hint is not None:
        target = target_hint
    elif args:
        target = args[0]
    else:
        target = None
    return action, target


def _strip_volatile(value: Any) -> Any:
    """Drop volatile keys so a plan_id survives etag / last-login churn."""
    if isinstance(value, dict):
        return {k: _strip_volatile(v) for k, v in value.items() if k not in _FINGERPRINT_VOLATILE}
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


def _plan_id(plan: dict) -> str:
    """First 16 hex chars of sha256 over canonical action/target/before/request."""
    payload = {
        "action": plan.get("action"),
        "target": plan.get("target"),
        "before": _strip_volatile(plan.get("before")),
        "request": plan.get("request"),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _next_step(plan: dict, plan_id: str) -> str:
    flags = f"--apply --plan-id {plan_id}"
    if plan.get("requires_confirm"):
        flags += f" --confirm '{plan['target']}'"
    return ("Show this preview to the user. Re-run with " + flags
            + " ONLY after they explicitly approve this exact change.")


def check_confirm(action: str, target: str, confirm: Optional[str]) -> None:
    if action in CONFIRM_REQUIRED and confirm != target:
        if confirm is None:
            raise Refused(f"{action} is destructive: re-run with --apply --confirm '{target}'")
        raise Refused(f"--confirm '{confirm}' does not match target '{target}'; nothing was changed")


def _call(svc, resource: str, method: str, params: dict, body: Optional[dict]):
    obj = svc
    for part in resource.split("."):
        obj = getattr(obj, part)()
    kwargs = dict(params)
    if body is not None:
        kwargs["body"] = body
    return getattr(obj, method)(**kwargs).execute()


def run(plan_fn: Callable, args: tuple, kwargs: dict, *, apply: bool = False,
        confirm: Optional[str] = None, plan_id: Optional[str] = None,
        target_hint: Optional[str] = None, action_hint: Optional[str] = None,
        service=None, audit_path: Optional[str] = None) -> dict:
    """Plan an action, then either return the dry-run preview or apply it.

    When applying, the order is: --confirm pre-check, required --plan-id,
    audit log writable, build the plan, refuse if the fingerprint differs,
    then the single call.
    ``action_hint``/``target_hint`` let --confirm be validated BEFORE any API
    call (so a mismatch never even reads state). Dry runs are not audited.
    """
    if apply and action_hint:
        try:
            check_confirm(action_hint, target_hint, confirm)
        except Refused as e:
            audit({"action": action_hint, "target": target_hint, "result": "refused", "reason": str(e)}, audit_path)
            raise

    if apply and not plan_id:
        action, target = _audit_subject(plan_fn, args, action_hint, target_hint)
        reason = ("--apply requires --plan-id from the dry run; "
                  "re-run the dry run and pass its plan_id")
        audit({"action": action, "target": target, "result": "refused", "reason": reason}, audit_path)
        raise Refused(reason)

    if apply:
        # No mutation without a writable audit trail; checked before any API call.
        try:
            _audit_writable(audit_path)
        except Refused as e:
            print(json.dumps({"warning": str(e)}), file=sys.stderr)
            raise

    svc = service or get_service("directory_write")
    try:
        plan = plan_fn(svc, *args, **kwargs)
    except Refused as e:
        if apply:
            action, target = _audit_subject(plan_fn, args, action_hint, target_hint)
            audit({"action": action, "target": target, "result": "refused", "reason": str(e)}, audit_path)
        raise
    except Exception as e:
        if apply:
            action, target = _audit_subject(plan_fn, args, action_hint, target_hint)
            audit({"action": action, "target": target, "result": "error", "error": str(e)[:500]}, audit_path)
        raise

    fingerprint = _plan_id(plan)
    if not apply:
        return {"mode": "dry_run", **plan, "plan_id": fingerprint,
                "next_step": _next_step(plan, fingerprint)}

    if fingerprint != plan_id:
        reason = (f"plan changed since dry run (expected {plan_id}, got {fingerprint}); "
                  "re-run the dry run and get approval again")
        audit({"action": plan["action"], "target": plan["target"], "result": "refused", "reason": reason}, audit_path)
        raise Refused(reason)

    try:
        check_confirm(plan["action"], plan["target"], confirm)
    except Refused as e:
        audit({"action": plan["action"], "target": plan["target"], "result": "refused", "reason": str(e)}, audit_path)
        raise

    if plan.get("noop"):
        audit({"action": plan["action"], "target": plan["target"], "result": "noop", "reason": plan["noop"]}, audit_path)
        return {"mode": "applied", "action": plan["action"], "target": plan["target"], "result": "noop",
                "reason": plan["noop"]}

    req = plan["request"]
    body = deepcopy(req["body"])
    password = None
    if plan.get("needs_password"):
        password = generate_password()
        body["password"] = password

    actor = admin_email()
    try:
        resp = _call(svc, req["resource"], req["method"], req["params"], body)
    except Exception as e:
        audit({"action": plan["action"], "target": plan["target"], "actor": actor, "result": "error",
               "error": str(e)[:500]}, audit_path)
        raise
    audit({"action": plan["action"], "target": plan["target"], "actor": actor, "result": "ok",
           "method": f"{req['resource']}.{req['method']}"}, audit_path)

    out = {"mode": "applied", "action": plan["action"], "target": plan["target"], "result": "ok",
           "request": {**req, "body": _redact(body)}, "response": _redact(resp) if resp else None}
    if password:
        out["temporary_password"] = password
        out["password_note"] = ("Shown ONCE. Deliver it to the user over a secure channel; "
                                "they must change it at next login. It is not stored or logged.")
    return out


# --------------------------------------------------------------------------- CLI

def _common(p):
    p.add_argument("--apply", action="store_true", help="Actually perform the change (default: dry run)")
    p.add_argument("--plan-id", metavar="ID",
                   help="plan_id from the approved dry-run preview (required with --apply)")
    p.add_argument("--confirm", metavar="TARGET",
                   help="Exact target (email / OU path) — required with --apply for destructive actions")
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GWS Directory admin WRITE actions. Dry run by default; "
                    "--apply --plan-id <id> to change; "
                    "destructive actions also need --confirm <exact target>.")
    res = parser.add_subparsers(dest="resource", required=True)

    # users
    u = res.add_parser("user", help="User write actions").add_subparsers(dest="verb", required=True)
    p = _common(u.add_parser("create", help="Create a user (random temp password, change at next login)"))
    p.add_argument("email"); p.add_argument("--first", required=True); p.add_argument("--last", required=True)
    p.add_argument("--ou", default="/", help="Org unit path (default /)")
    p.add_argument("--title"); p.add_argument("--department"); p.add_argument("--phone")
    p.add_argument("--manager", help="Manager email"); p.add_argument("--recovery-email")
    p = _common(u.add_parser("update", help="Update name/title/department/phone/manager"))
    p.add_argument("email"); p.add_argument("--first"); p.add_argument("--last"); p.add_argument("--title")
    p.add_argument("--department"); p.add_argument("--phone"); p.add_argument("--manager", help="Manager email")
    for verb, h in [("suspend", "Suspend a user"), ("unsuspend", "Unsuspend a user"),
                    ("reset-password", "Reset to a random temp password (change at next login)"),
                    ("signout", "Sign the user out of all sessions (users.signOut)"),
                    ("make-admin", "Grant super admin (needs --confirm)"),
                    ("revoke-admin", "Revoke super admin (needs --confirm)"),
                    ("delete", "Delete a user (needs --confirm)")]:
        _common(u.add_parser(verb, help=h)).add_argument("email")
    p = _common(u.add_parser("move", help="Move user to an org unit"))
    p.add_argument("email"); p.add_argument("--ou", required=True)
    for verb, h in [("add-alias", "Add an email alias"), ("remove-alias", "Remove an email alias")]:
        p = _common(u.add_parser(verb, help=h)); p.add_argument("email"); p.add_argument("alias")

    # groups
    g = res.add_parser("group", help="Group write actions").add_subparsers(dest="verb", required=True)
    p = _common(g.add_parser("create", help="Create a group"))
    p.add_argument("email"); p.add_argument("--name", required=True); p.add_argument("--description")
    p = _common(g.add_parser("update", help="Update group name/description"))
    p.add_argument("email"); p.add_argument("--name"); p.add_argument("--description")
    _common(g.add_parser("delete", help="Delete a group (needs --confirm)")).add_argument("email")
    p = _common(g.add_parser("add-member", help="Add a member"))
    p.add_argument("group"); p.add_argument("member"); p.add_argument("--role", default="MEMBER", choices=MEMBER_ROLES)
    p = _common(g.add_parser("remove-member", help="Remove a member"))
    p.add_argument("group"); p.add_argument("member")
    p = _common(g.add_parser("set-role", help="Change a member's role"))
    p.add_argument("group"); p.add_argument("member"); p.add_argument("--role", required=True, choices=MEMBER_ROLES)

    # org units
    o = res.add_parser("ou", help="Org unit write actions").add_subparsers(dest="verb", required=True)
    p = _common(o.add_parser("create", help="Create an org unit"))
    p.add_argument("--name", required=True); p.add_argument("--parent", default="/"); p.add_argument("--description")
    p = _common(o.add_parser("update", help="Rename / move / re-describe an org unit"))
    p.add_argument("path"); p.add_argument("--name"); p.add_argument("--parent"); p.add_argument("--description")
    _common(o.add_parser("delete", help="Delete an (empty) org unit (needs --confirm)")).add_argument("path")
    return parser


def dispatch(args) -> tuple:
    """Map parsed args to (plan_fn, args, kwargs, action_hint, target_hint).

    action_hint/target_hint are set for --confirm actions so the confirmation
    can be checked before any API call is made.
    """
    A = lambda name: getattr(args, name, None)  # noqa: E731
    r, v = args.resource, args.verb
    if r == "user":
        e = args.email
        if v == "create":
            return (plan_user_create, (e, A("first"), A("last")),
                    dict(ou=A("ou"), title=A("title"), department=A("department"), phone=A("phone"),
                         manager=A("manager"), recovery_email=A("recovery_email")), None, None)
        if v == "update":
            return (plan_user_update, (e,),
                    dict(first=A("first"), last=A("last"), title=A("title"), department=A("department"),
                         phone=A("phone"), manager=A("manager")), None, None)
        simple = {
            "suspend": plan_user_suspend, "unsuspend": plan_user_unsuspend,
            "reset-password": plan_user_reset_password, "signout": plan_user_signout,
        }
        if v in simple:
            return simple[v], (e,), {}, None, None
        if v == "move":
            return plan_user_move, (e, A("ou")), {}, None, None
        if v == "make-admin":
            return plan_user_admin, (e, True), {}, "user.make_admin", e
        if v == "revoke-admin":
            return plan_user_admin, (e, False), {}, "user.revoke_admin", e
        if v == "add-alias":
            return plan_alias_add, (e, A("alias")), {}, None, None
        if v == "remove-alias":
            return plan_alias_remove, (e, A("alias")), {}, None, None
        if v == "delete":
            return plan_user_delete, (e,), {}, "user.delete", e
    elif r == "group":
        if v == "create":
            return plan_group_create, (A("email"), A("name"), A("description")), {}, None, None
        if v == "update":
            return plan_group_update, (A("email"), A("name"), A("description")), {}, None, None
        if v == "delete":
            return plan_group_delete, (A("email"),), {}, "group.delete", A("email")
        if v == "add-member":
            return plan_member_add, (A("group"), A("member"), A("role")), {}, None, None
        if v == "remove-member":
            return plan_member_remove, (A("group"), A("member")), {}, None, None
        if v == "set-role":
            return plan_member_role, (A("group"), A("member"), A("role")), {}, None, None
    elif r == "ou":
        if v == "create":
            return plan_ou_create, (A("name"), A("parent"), A("description")), {}, None, None
        if v == "update":
            return plan_ou_update, (A("path"), A("name"), A("parent"), A("description")), {}, None, None
        if v == "delete":
            return plan_ou_delete, (A("path"),), {}, "ou.delete", _norm_ou(A("path"))
    raise ValueError(f"Unknown command: {r} {v}")


def main(argv: Optional[list] = None, service=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fn, a, k, hint, target = dispatch(args)
        result = run(fn, a, k, apply=args.apply, confirm=args.confirm, plan_id=args.plan_id,
                     action_hint=hint, target_hint=target, service=service)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Refused as e:
        print(json.dumps({"refused": str(e), "changed": False}, indent=2))
        return 2
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": str(e)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
