import hashlib
import json
import re
from unittest import mock

import httplib2
import pytest
from googleapiclient.errors import HttpError

import admin

MUTATING = {"insert", "update", "patch", "delete", "makeAdmin", "signOut", "undelete"}

USER = {
    "primaryEmail": "jane@example.com", "id": "1", "name": {"givenName": "Jane", "familyName": "Doe"},
    "suspended": False, "isAdmin": False, "orgUnitPath": "/Sales", "aliases": ["jd@example.com"],
    "organizations": [{"primary": True, "title": "Rep", "department": "Sales"},
                      {"title": "Volunteer", "name": "Club"}],
    "phones": [{"type": "work", "value": "111", "primary": True}, {"type": "mobile", "value": "222"}],
    "relations": [{"type": "manager", "value": "old@example.com"}, {"type": "assistant", "value": "a@example.com"}],
}
GROUP = {"email": "team@example.com", "id": "g1", "name": "Team", "description": "d", "directMembersCount": "3"}
MEMBER = {"email": "jane@example.com", "role": "MEMBER", "type": "USER", "status": "ACTIVE"}
OU = {"orgUnitPath": "/Sales/East", "orgUnitId": "id:ou1", "name": "East", "parentOrgUnitPath": "/Sales"}


def not_found(*_a, **_k):
    raise HttpError(httplib2.Response({"status": 404}), b'{"error":{"code":404}}')


def make_svc(user=USER, group=GROUP, member=MEMBER, ou=OU):
    svc = mock.MagicMock(name="svc")

    def _get(obj, val):
        if val is None:
            obj.return_value.get.return_value.execute.side_effect = not_found
        else:
            obj.return_value.get.return_value.execute.return_value = val

    _get(svc.users, user)
    _get(svc.groups, group)
    _get(svc.members, member)
    _get(svc.orgunits, ou)
    for res in (svc.users, svc.groups, svc.members, svc.orgunits):
        for m in MUTATING:
            getattr(res.return_value, m).return_value.execute.return_value = {"ok": True}
    svc.users.return_value.aliases.return_value.insert.return_value.execute.return_value = {"alias": "x"}
    svc.users.return_value.aliases.return_value.delete.return_value.execute.return_value = None
    return svc


def mutate_calls(svc):
    """Names of mutating API methods that were invoked on the mock."""
    found = []
    for c in svc.mock_calls:
        name = c[0]
        parts = re.findall(r"(\w+)\(\)", name + "()")
        for p in parts:
            if p in MUTATING:
                found.append(name)
    return found


def call(argv, svc, capsys):
    rc = admin.main(argv, service=svc)
    return rc, json.loads(capsys.readouterr().out)


def audit_lines(tmp_path):
    p = tmp_path / "audit.log"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def dry_plan_id(argv, kw, capsys):
    """plan_id from a dry run on a fresh mock with the same service kwargs."""
    svc = make_svc(**kw)
    _ou_create_parent_exists(svc, kw)
    rc, out = call(list(argv), svc, capsys)
    assert rc == 0, out
    assert re.fullmatch(r"[0-9a-f]{16}", out["plan_id"])
    return out["plan_id"]


# (argv, svc kwargs, expected resource chain, method, expected params, expected body, confirm target)
CASES = [
    (["user", "create", "new@example.com", "--first", "N", "--last", "U", "--ou", "Sales", "--title", "Eng",
      "--manager", "boss@example.com"], {"user": None}, "users", "insert", {}, None, None),
    (["user", "update", "jane@example.com", "--title", "Lead", "--phone", "333", "--manager", "m@example.com",
      "--first", "Janet"], {}, "users", "update", {"userKey": "jane@example.com"},
     {"name": {"givenName": "Janet"},
      "organizations": [{"primary": True, "title": "Lead", "department": "Sales"}, {"title": "Volunteer", "name": "Club"}],
      "phones": [{"type": "work", "value": "333", "primary": True}, {"type": "mobile", "value": "222"}],
      "relations": [{"type": "assistant", "value": "a@example.com"}, {"type": "manager", "value": "m@example.com"}]},
     None),
    (["user", "suspend", "jane@example.com"], {}, "users", "update", {"userKey": "jane@example.com"}, {"suspended": True}, None),
    (["user", "unsuspend", "jane@example.com"], {"user": {**USER, "suspended": True}}, "users", "update",
     {"userKey": "jane@example.com"}, {"suspended": False}, None),
    (["user", "reset-password", "jane@example.com"], {}, "users", "update", {"userKey": "jane@example.com"}, None, None),
    (["user", "move", "jane@example.com", "--ou", "/Engineering"], {}, "users", "update",
     {"userKey": "jane@example.com"}, {"orgUnitPath": "/Engineering"}, None),
    (["user", "signout", "jane@example.com"], {}, "users", "signOut", {"userKey": "jane@example.com"}, None, None),
    (["user", "make-admin", "jane@example.com"], {}, "users", "makeAdmin", {"userKey": "jane@example.com"},
     {"status": True}, "jane@example.com"),
    (["user", "revoke-admin", "jane@example.com"], {"user": {**USER, "isAdmin": True}}, "users", "makeAdmin",
     {"userKey": "jane@example.com"}, {"status": False}, "jane@example.com"),
    (["user", "add-alias", "jane@example.com", "jane.doe@example.com"], {}, "users.aliases", "insert",
     {"userKey": "jane@example.com"}, {"alias": "jane.doe@example.com"}, None),
    (["user", "remove-alias", "jane@example.com", "jd@example.com"], {}, "users.aliases", "delete",
     {"userKey": "jane@example.com", "alias": "jd@example.com"}, None, None),
    (["user", "delete", "jane@example.com"], {}, "users", "delete", {"userKey": "jane@example.com"}, None,
     "jane@example.com"),
    (["group", "create", "new-team@example.com", "--name", "New", "--description", "x"], {"group": None},
     "groups", "insert", {}, {"email": "new-team@example.com", "name": "New", "description": "x"}, None),
    (["group", "update", "team@example.com", "--name", "Team 2"], {}, "groups", "patch",
     {"groupKey": "team@example.com"}, {"name": "Team 2"}, None),
    (["group", "delete", "team@example.com"], {}, "groups", "delete", {"groupKey": "team@example.com"}, None,
     "team@example.com"),
    (["group", "add-member", "team@example.com", "bob@example.com", "--role", "MANAGER"], {"member": None},
     "members", "insert", {"groupKey": "team@example.com"}, {"email": "bob@example.com", "role": "MANAGER"}, None),
    (["group", "remove-member", "team@example.com", "jane@example.com"], {}, "members", "delete",
     {"groupKey": "team@example.com", "memberKey": "jane@example.com"}, None, None),
    (["group", "set-role", "team@example.com", "jane@example.com", "--role", "OWNER"], {}, "members", "patch",
     {"groupKey": "team@example.com", "memberKey": "jane@example.com"}, {"role": "OWNER"}, None),
    (["ou", "create", "--name", "West", "--parent", "/Sales", "--description", "w"], {"ou": None}, "orgunits",
     "insert", {"customerId": "my_customer"}, {"name": "West", "parentOrgUnitPath": "/Sales", "description": "w"}, None),
    (["ou", "update", "/Sales/East", "--name", "Eastern", "--parent", "/Ops"], {}, "orgunits", "patch",
     {"customerId": "my_customer", "orgUnitPath": "Sales/East"}, {"name": "Eastern", "parentOrgUnitPath": "/Ops"}, None),
    (["ou", "delete", "/Sales/East"], {}, "orgunits", "delete",
     {"customerId": "my_customer", "orgUnitPath": "Sales/East"}, None, "/Sales/East"),
]
IDS = [" ".join(c[0][:2]) for c in CASES]


def _method_mock(svc, chain, method):
    obj = svc
    for part in chain.split("."):
        obj = getattr(obj, part).return_value
    return getattr(obj, method)


def _ou_create_parent_exists(svc, kw):
    # For ou create the parent must exist but the new path must not.
    if kw.get("ou", "x") is None:
        calls = {"n": 0}

        def side(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                not_found()
            return OU
        svc.orgunits.return_value.get.return_value.execute.side_effect = side


@pytest.mark.parametrize("argv,kw,chain,method,params,body,confirm", CASES, ids=IDS)
def test_dry_run_makes_no_mutating_calls(argv, kw, chain, method, params, body, confirm, capsys, tmp_path):
    svc = make_svc(**kw)
    _ou_create_parent_exists(svc, kw)
    rc, out = call(argv, svc, capsys)
    assert rc == 0, out
    assert out["mode"] == "dry_run"
    assert mutate_calls(svc) == []
    assert not _method_mock(svc, chain, method).called
    # preview contents
    for key in ("action", "target", "before", "request"):
        assert key in out
    assert out["request"]["resource"] == chain and out["request"]["method"] == method
    assert out["request"]["params"] == params
    if body is not None:
        assert out["request"]["body"] == body
    assert out["requires_confirm"] == (confirm is not None)
    assert re.fullmatch(r"[0-9a-f]{16}", out["plan_id"])
    assert f"--apply --plan-id {out['plan_id']}" in out["next_step"]
    if confirm is not None:
        assert out["target"] == confirm
        assert f"--confirm '{out['target']}'" in out["next_step"]
    else:
        assert "--confirm" not in out["next_step"]
    assert audit_lines(tmp_path) == []  # dry runs are not audited


@pytest.mark.parametrize("argv,kw,chain,method,params,body,confirm", CASES, ids=IDS)
def test_apply_calls_right_method_with_right_body(argv, kw, chain, method, params, body, confirm, capsys, tmp_path):
    pid = dry_plan_id(argv, kw, capsys)
    svc = make_svc(**kw)
    _ou_create_parent_exists(svc, kw)
    extra = ["--apply", "--plan-id", pid] + (["--confirm", confirm] if confirm else [])
    rc, out = call(argv + extra, svc, capsys)
    assert rc == 0, out
    assert out["result"] == "ok"
    m = _method_mock(svc, chain, method)
    m.assert_called_once()
    kwargs = m.call_args.kwargs
    sent_body = kwargs.pop("body", None)
    assert kwargs == params
    if body is not None:
        assert sent_body == body
    # only the one expected mutating method was called
    assert len(mutate_calls(svc)) >= 1
    assert all(re.search(rf"\b{method}\(\)", n + "()") for n in mutate_calls(svc))
    log = audit_lines(tmp_path)
    assert len(log) == 1 and log[0]["result"] == "ok" and log[0]["action"] == out["action"]
    assert '"password"' not in json.dumps(log)  # no password field / request bodies in the audit log


DESTRUCTIVE = [c for c in CASES if c[6]]


@pytest.mark.parametrize("argv,kw,chain,method,params,body,confirm", DESTRUCTIVE,
                         ids=[" ".join(c[0][:2]) for c in DESTRUCTIVE])
@pytest.mark.parametrize("bad", [None, "wrong@example.com", "JANE@EXAMPLE.COM ", "/Sales"])
def test_confirm_missing_or_mismatch_refuses(argv, kw, chain, method, params, body, confirm, bad, capsys, tmp_path):
    svc = make_svc(**kw)
    extra = ["--apply"] + (["--confirm", bad] if bad is not None else [])
    rc, out = call(argv + extra, svc, capsys)
    assert rc == 2
    assert out["changed"] is False
    assert svc.mock_calls == []  # refused before ANY API call, even reads
    log = audit_lines(tmp_path)
    assert log and log[-1]["result"] == "refused"


def test_password_generated_only_on_apply_and_printed_once(capsys, tmp_path):
    argv = ["user", "create", "new@example.com", "--first", "N", "--last", "U"]
    svc = make_svc(user=None)
    rc, out = call(argv, svc, capsys)
    assert out["request"]["body"]["password"] == admin.PASSWORD_PLACEHOLDER
    assert out["request"]["body"]["changePasswordAtNextLogin"] is True
    pid = out["plan_id"]

    svc = make_svc(user=None)
    rc = admin.main(argv + ["--apply", "--plan-id", pid], service=svc)
    raw = capsys.readouterr().out
    out = json.loads(raw)
    pw = out["temporary_password"]
    assert len(pw) >= 16
    assert raw.count(pw) == 1  # printed exactly once; request/response bodies are redacted
    sent = svc.users.return_value.insert.call_args.kwargs["body"]
    assert sent["password"] == pw and sent["changePasswordAtNextLogin"] is True
    assert pw not in (tmp_path / "audit.log").read_text()


def test_reset_password_body(capsys):
    argv = ["user", "reset-password", "jane@example.com"]
    pid = dry_plan_id(argv, {}, capsys)
    svc = make_svc()
    admin.main(argv + ["--apply", "--plan-id", pid], service=svc)
    out = json.loads(capsys.readouterr().out)
    sent = svc.users.return_value.update.call_args.kwargs["body"]
    assert sent == {"password": out["temporary_password"], "changePasswordAtNextLogin": True}


def test_generate_password_strength():
    pws = {admin.generate_password() for _ in range(200)}
    assert len(pws) == 200
    for pw in pws:
        assert len(pw) == 20
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)


@pytest.mark.parametrize("argv", [
    ["user", "suspend", "jane@example.com"], ["user", "signout", "jane@example.com"],
    ["user", "make-admin", "jane@example.com"], ["user", "delete", "jane@example.com"],
    ["group", "delete", "team@example.com"], ["ou", "delete", "/Sales/East"],
])
def test_destructive_previews_have_warning(argv, capsys):
    rc, out = call(argv, make_svc(), capsys)
    assert rc == 0 and "DESTRUCTIVE" in out["warning"]


def test_refuses_to_lock_out_own_admin(capsys, tmp_path):
    svc = make_svc(user={**USER, "primaryEmail": "admin@example.com"})
    rc, out = call(["user", "suspend", "admin@example.com", "--apply", "--plan-id", "0123456789abcdef"],
                   svc, capsys)
    assert rc == 2 and "GWS_ADMIN_EMAIL" in out["refused"]
    assert mutate_calls(svc) == []
    assert svc.users.return_value.get.called is False  # raw-string check, before the fetch
    assert audit_lines(tmp_path)[-1]["result"] == "refused"


def test_dry_run_self_protection_is_not_audited(capsys, tmp_path):
    svc = make_svc(user={**USER, "primaryEmail": "admin@example.com"})
    rc, out = call(["user", "suspend", "admin@example.com"], svc, capsys)
    assert rc == 2 and "GWS_ADMIN_EMAIL" in out["refused"]
    assert audit_lines(tmp_path) == []


@pytest.mark.parametrize("verb,needs_confirm", [
    ("suspend", False),
    ("delete", True),
    ("signout", False),
    ("reset-password", False),
    ("revoke-admin", True),
])
@pytest.mark.parametrize("target,record", [
    ("boss-alias@example.com", {**USER, "primaryEmail": "admin@example.com", "id": "12345",
                                "aliases": ["boss-alias@example.com"]}),
    ("12345", {**USER, "primaryEmail": "admin@example.com", "id": "12345"}),
    ("someone@example.com", {**USER, "primaryEmail": "someone@example.com",
                             "nonEditableAliases": ["admin@example.com"]}),
])
def test_self_protection_resolves_alias_and_id(verb, needs_confirm, target, record, capsys, tmp_path):
    svc = make_svc(user=record)
    argv = ["user", verb, target, "--apply", "--plan-id", "0123456789abcdef"]
    if needs_confirm:
        argv += ["--confirm", target]
    rc, out = call(argv, svc, capsys)
    assert rc == 2, out
    assert out["changed"] is False
    assert "GWS_ADMIN_EMAIL" in out["refused"]
    assert mutate_calls(svc) == []
    log = audit_lines(tmp_path)
    assert log and log[-1]["result"] == "refused"
    assert "GWS_ADMIN_EMAIL" in log[-1]["reason"]


def test_self_protection_match_is_case_insensitive(capsys, tmp_path):
    record = {**USER, "primaryEmail": "someone@example.com", "aliases": ["Admin@Example.com"]}
    svc = make_svc(user=record)
    rc, out = call(["user", "suspend", "someone@example.com", "--apply", "--plan-id", "0123456789abcdef"],
                   svc, capsys)
    assert rc == 2 and "GWS_ADMIN_EMAIL" in out["refused"]
    assert mutate_calls(svc) == []
    assert audit_lines(tmp_path)[-1]["result"] == "refused"


def test_non_admin_alias_is_not_self_protected(capsys):
    record = {**USER, "aliases": ["boss-alias@example.com"]}
    argv = ["user", "suspend", "boss-alias@example.com"]
    pid = dry_plan_id(argv, {"user": record}, capsys)
    svc = make_svc(user=record)
    rc, out = call(argv + ["--apply", "--plan-id", pid], svc, capsys)
    assert rc == 0, out
    assert mutate_calls(svc)


def test_noop_apply_does_not_call_api(capsys, tmp_path):
    argv = ["user", "suspend", "jane@example.com"]
    kw = {"user": {**USER, "suspended": True}}
    pid = dry_plan_id(argv, kw, capsys)
    svc = make_svc(**kw)
    rc, out = call(argv + ["--apply", "--plan-id", pid], svc, capsys)
    assert rc == 0 and out["result"] == "noop"
    assert mutate_calls(svc) == []


def test_noop_rejects_mismatched_plan_id(capsys, tmp_path):
    argv = ["user", "suspend", "jane@example.com"]
    kw = {"user": {**USER, "suspended": True}}
    svc = make_svc(**kw)
    rc, out = call(argv + ["--apply", "--plan-id", "abcdefabcdefabcd"], svc, capsys)
    assert rc == 2
    assert "plan changed since dry run" in out["refused"]
    assert mutate_calls(svc) == []
    assert audit_lines(tmp_path)[-1]["result"] == "refused"


def test_create_existing_user_refused(capsys, tmp_path):
    argv = ["user", "create", "jane@example.com", "--first", "J", "--last", "D"]
    rc, out = call(argv, make_svc(), capsys)
    assert rc == 2 and "already exists" in out["refused"]
    assert audit_lines(tmp_path) == []  # dry run is not audited

    svc = make_svc()
    rc, out = call(argv + ["--apply", "--plan-id", "0123456789abcdef"], svc, capsys)
    assert rc == 2 and "already exists" in out["refused"]
    assert mutate_calls(svc) == []
    log = audit_lines(tmp_path)
    assert len(log) == 1 and log[0]["result"] == "refused"
    assert log[0]["action"] == "user.create" and log[0]["target"] == "jane@example.com"
    assert "already exists" in log[0]["reason"]


def test_root_ou_delete_refused(capsys, tmp_path):
    svc = make_svc()
    rc, out = call(["ou", "delete", "/", "--apply", "--confirm", "/", "--plan-id", "0123456789abcdef"],
                   svc, capsys)
    assert rc == 2 and mutate_calls(svc) == []
    assert "root" in out["refused"].lower()
    assert audit_lines(tmp_path)[-1]["result"] == "refused"


def test_api_error_is_audited(capsys, tmp_path):
    argv = ["user", "suspend", "jane@example.com"]
    pid = dry_plan_id(argv, {}, capsys)
    svc = make_svc()
    svc.users.return_value.update.return_value.execute.side_effect = HttpError(
        httplib2.Response({"status": 403}), b'{"error":{"message":"Not Authorized"}}')
    rc, out = call(argv + ["--apply", "--plan-id", pid], svc, capsys)
    assert rc == 1
    assert audit_lines(tmp_path)[-1]["result"] == "error"


def test_planning_http_error_is_audited(capsys, tmp_path):
    svc = make_svc()
    svc.users.return_value.get.return_value.execute.side_effect = HttpError(
        httplib2.Response({"status": 403}), b'{"error":{"message":"Not Authorized"}}')
    rc, out = call(["user", "suspend", "jane@example.com", "--apply", "--plan-id", "0123456789abcdef"],
                   svc, capsys)
    assert rc == 1
    assert mutate_calls(svc) == []
    log = audit_lines(tmp_path)
    assert log[-1]["result"] == "error"
    assert log[-1]["action"] == "user.suspend"
    assert log[-1]["target"] == "jane@example.com"
    assert "403" in log[-1]["error"] or "Not Authorized" in log[-1]["error"]


def test_dry_run_http_error_is_not_audited(capsys, tmp_path):
    svc = make_svc()
    svc.users.return_value.get.return_value.execute.side_effect = HttpError(
        httplib2.Response({"status": 403}), b'{"error":{"message":"Not Authorized"}}')
    rc, _out = call(["user", "suspend", "jane@example.com"], svc, capsys)
    assert rc == 1
    assert audit_lines(tmp_path) == []


def test_audit_log_is_private(capsys, tmp_path):
    argv = ["user", "signout", "jane@example.com"]
    pid = dry_plan_id(argv, {}, capsys)
    call(argv + ["--apply", "--plan-id", pid], make_svc(), capsys)
    import os, stat
    assert stat.S_IMODE(os.stat(tmp_path / "audit.log").st_mode) == 0o600


def test_apply_requires_plan_id_before_any_api_call(capsys, tmp_path):
    svc = make_svc()
    rc, out = call(["user", "suspend", "jane@example.com", "--apply"], svc, capsys)
    assert rc == 2 and out["changed"] is False
    assert "--apply requires --plan-id from the dry run" in out["refused"]
    assert svc.mock_calls == []
    log = audit_lines(tmp_path)
    assert log[-1]["result"] == "refused"
    assert log[-1]["action"] == "user.suspend" and log[-1]["target"] == "jane@example.com"

    svc = make_svc()
    rc, out = call(["user", "delete", "jane@example.com", "--apply", "--confirm", "jane@example.com"],
                   svc, capsys)
    assert rc == 2 and svc.mock_calls == []
    assert "--apply requires --plan-id from the dry run" in out["refused"]


def test_mismatched_plan_id_refuses(capsys, tmp_path):
    argv = ["user", "suspend", "jane@example.com"]
    real = dry_plan_id(argv, {}, capsys)
    bad = "0" * 16
    assert bad != real
    svc = make_svc()
    rc, out = call(argv + ["--apply", "--plan-id", bad], svc, capsys)
    assert rc == 2 and out["changed"] is False
    assert out["refused"] == (
        f"plan changed since dry run (expected {bad}, got {real}); "
        "re-run the dry run and get approval again")
    assert mutate_calls(svc) == []
    log = audit_lines(tmp_path)
    assert log[-1]["result"] == "refused" and log[-1]["reason"] == out["refused"]


def test_apply_refuses_on_state_drift(capsys, tmp_path):
    argv = ["user", "update", "jane@example.com", "--title", "Lead"]
    original = dry_plan_id(argv, {}, capsys)
    changed = {**USER, "organizations": [
        {"primary": True, "title": "Director", "department": "Sales"},
        {"title": "Volunteer", "name": "Club"},
    ]}
    drifted = dry_plan_id(argv, {"user": changed}, capsys)
    assert original != drifted
    svc = make_svc(user=changed)
    rc, out = call(argv + ["--apply", "--plan-id", original], svc, capsys)
    assert rc == 2
    assert out["refused"] == (
        f"plan changed since dry run (expected {original}, got {drifted}); "
        "re-run the dry run and get approval again")
    assert mutate_calls(svc) == []
    assert audit_lines(tmp_path)[-1]["result"] == "refused"


def test_plan_id_matches_canonical_json(capsys):
    rc, out = call(["user", "suspend", "jane@example.com"], make_svc(), capsys)
    assert rc == 0
    payload = {"action": out["action"], "target": out["target"],
               "before": out["before"], "request": out["request"]}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    assert out["plan_id"] == hashlib.sha256(raw).hexdigest()[:16]


def test_plan_id_strips_volatile_keys_recursively(capsys):
    argv = ["user", "delete", "jane@example.com"]
    name = {"givenName": "Jane", "familyName": "Doe"}
    a = {**USER, "name": {**name, "etag": "v1"}, "lastLoginTime": "t1", "kind": "k1"}
    b = {**USER, "name": {**name, "etag": "v2", "kind": "nested"}, "lastLoginTime": "t2", "kind": "k2"}
    id_a = dry_plan_id(argv, {"user": a}, capsys)
    rc, out = call(argv, make_svc(user=a), capsys)
    assert rc == 0
    assert out["before"]["lastLoginTime"] == "t1"  # preview keeps volatile fields
    assert out["plan_id"] == id_a
    assert dry_plan_id(argv, {"user": b}, capsys) == id_a


def test_relative_audit_log_filename(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GWS_AUDIT_LOG", "audit.log")
    argv = ["user", "signout", "jane@example.com"]
    pid = dry_plan_id(argv, {}, capsys)
    svc = make_svc()
    rc, out = call(argv + ["--apply", "--plan-id", pid], svc, capsys)
    assert rc == 0, out
    lines = [json.loads(l) for l in (tmp_path / "audit.log").read_text().splitlines()]
    assert lines and lines[-1]["result"] == "ok"


def test_unwritable_audit_log_refuses_before_mutation(capsys, tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    monkeypatch.setenv("GWS_AUDIT_LOG", str(blocker / "audit.log"))
    argv = ["user", "suspend", "jane@example.com"]
    pid = dry_plan_id(argv, {}, capsys)
    svc = make_svc()
    rc, out = call(argv + ["--apply", "--plan-id", pid], svc, capsys)
    assert rc == 2, out
    assert "audit log not writable" in out["refused"]
    assert mutate_calls(svc) == []
    assert svc.mock_calls == []  # checked before any API call, including the before-state read
