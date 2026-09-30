import json
import os
import stat
from unittest import mock

import pytest

import auth


def _key(tmp_path, mode):
    p = tmp_path / "sa.json"
    p.write_text(json.dumps({"type": "service_account"}))
    os.chmod(p, mode)
    return str(p)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_chmod_ok(tmp_path, mode):
    auth.check_key_permissions(_key(tmp_path, mode))


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o700 | 0o007])
def test_chmod_too_open_refused(tmp_path, mode):
    with pytest.raises(auth.AuthError, match="chmod 600"):
        auth.check_key_permissions(_key(tmp_path, mode))


def test_missing_key_refused(tmp_path):
    with pytest.raises(auth.AuthError, match="not found"):
        auth.check_key_permissions(str(tmp_path / "nope.json"))


def test_directory_as_key_refused(tmp_path):
    with pytest.raises(auth.AuthError, match="regular file"):
        auth.check_key_permissions(str(tmp_path))


def test_get_credentials_refuses_open_key_before_loading(tmp_path):
    key = _key(tmp_path, 0o644)
    with mock.patch.object(auth.service_account.Credentials, "from_service_account_file") as f:
        with pytest.raises(auth.AuthError):
            auth.get_credentials("directory", key_path=key)
        f.assert_not_called()


def test_resolve_key_path_precedence(tmp_path, monkeypatch):
    assert auth.resolve_key_path() == auth.DEFAULT_KEY_PATH
    monkeypatch.setenv("GWS_SERVICE_ACCOUNT_PATH", "~/custom/key.json")
    assert auth.resolve_key_path() == os.path.expanduser("~/custom/key.json")  # ~ expanded
    assert auth.resolve_key_path(str(tmp_path / "x.json")) == str(tmp_path / "x.json")


def test_env_key_path_is_used_by_get_credentials(tmp_path, monkeypatch):
    key = _key(tmp_path, 0o600)
    monkeypatch.setenv("GWS_SERVICE_ACCOUNT_PATH", key)
    with mock.patch.object(auth.service_account.Credentials, "from_service_account_file") as f:
        auth.get_credentials("gmail", impersonate="bob@example.com")
    f.assert_called_once_with(key, scopes=auth.SCOPES["gmail"], subject="bob@example.com")


def test_default_subject_is_admin_and_read_at_call_time(tmp_path, monkeypatch):
    key = _key(tmp_path, 0o600)
    monkeypatch.setenv("GWS_ADMIN_EMAIL", "boss@example.com")
    with mock.patch.object(auth.service_account.Credentials, "from_service_account_file") as f:
        auth.get_credentials("directory", key_path=key)
    assert f.call_args.kwargs["subject"] == "boss@example.com"


def test_no_subject_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("GWS_ADMIN_EMAIL", "")
    monkeypatch.setattr(auth, "DEFAULT_ADMIN_EMAIL", "")
    with pytest.raises(auth.AuthError, match="GWS_ADMIN_EMAIL"):
        auth.get_credentials("directory", key_path=_key(tmp_path, 0o600))


def test_read_scope_sets_are_read_only():
    for api, scopes in auth.SCOPES.items():
        if api in ("directory_write", "vault"):
            continue  # vault's only scope is ediscovery
        for s in scopes:
            assert s.endswith(".readonly"), (api, s)


def test_directory_read_includes_orgunit_readonly():
    assert "https://www.googleapis.com/auth/admin.directory.orgunit.readonly" in auth.SCOPES["directory"]


def test_directory_write_scopes():
    assert set(auth.SCOPES["directory_write"]) == {
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.user.security",
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.orgunit",
    }
    assert auth.API_INFO["directory_write"] == ("admin", "directory_v1")


def test_cli_user_flag_and_loose_perms(tmp_path, capsys):
    key = _key(tmp_path, 0o644)
    rc = auth.main(["directory", "--user", "bob@example.com", "--key", key])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["status"] == "error"
    assert out["impersonating"] == "bob@example.com"
    assert out["key_path"] == key
    assert "chmod 600" in out["error"]


def test_cli_ok_mints_token(tmp_path, capsys):
    key = _key(tmp_path, 0o600)
    fake = mock.MagicMock()
    with mock.patch.object(auth.service_account.Credentials, "from_service_account_file", return_value=fake):
        rc = auth.main(["directory_write", "--key", key])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["status"] == "ok" and out["impersonating"] == "admin@example.com"
    fake.refresh.assert_called_once()  # a real token request, not just build()


def test_setup_checklist_scope_strings_match_code():
    import pathlib
    import re
    text = (pathlib.Path(__file__).parent.parent / "references" / "setup-checklist.md").read_text()
    lines = [l for l in text.splitlines() if l.startswith("https://www.googleapis.com/auth/")]
    assert len(lines) == 2, "expected a read-only and a full DWD scope line"
    ro, full = (set(l.split(",")) for l in lines)
    read_apis = [k for k in auth.SCOPES if k != "directory_write"]
    assert ro == {s for k in read_apis for s in auth.SCOPES[k]}
    assert full == ro | set(auth.SCOPES["directory_write"])
