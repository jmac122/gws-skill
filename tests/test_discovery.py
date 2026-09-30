"""Run admin.py against the REAL bundled Directory API discovery document.

No network: googleapiclient's static discovery doc + a recording mock HTTP.
This proves the method names, path params, and HTTP verbs/URLs are valid for
the installed google-api-python-client.
"""
import json

import pytest
from googleapiclient.discovery import build
from googleapiclient.http import HttpMockSequence

import admin


class RecordingHttp(HttpMockSequence):
    def __init__(self, responses):
        super().__init__(responses)
        self.log = []

    def request(self, uri, method="GET", body=None, headers=None, **kw):
        self.log.append((method, uri.split("?")[0], json.loads(body) if body else None))
        return super().request(uri, method=method, body=body, headers=headers, **kw)


USER = json.dumps({"primaryEmail": "jane@example.com", "isAdmin": False, "suspended": False})
OU = json.dumps({"orgUnitPath": "/Sales/East", "name": "East", "parentOrgUnitPath": "/Sales"})
BASE = "https://admin.googleapis.com/admin/directory/v1"


def svc_with(responses):
    http = RecordingHttp([({"status": "200"}, r) for r in responses])
    return build("admin", "directory_v1", http=http, static_discovery=True), http


@pytest.mark.parametrize("argv,responses,expected", [
    (["user", "signout", "jane@example.com", "--apply"], [USER, ""],
     ("POST", f"{BASE}/users/jane%40example.com/signOut", None)),
    (["user", "make-admin", "jane@example.com", "--apply", "--confirm", "jane@example.com"], [USER, ""],
     ("POST", f"{BASE}/users/jane%40example.com/makeAdmin", {"status": True})),
    (["user", "suspend", "jane@example.com", "--apply"], [USER, USER],
     ("PUT", f"{BASE}/users/jane%40example.com", {"suspended": True})),
    (["ou", "delete", "/Sales/East", "--apply", "--confirm", "/Sales/East"], [OU, ""],
     ("DELETE", f"{BASE}/customer/my_customer/orgunits/Sales/East", None)),
    (["group", "set-role", "team@example.com", "jane@example.com", "--role", "OWNER", "--apply"],
     [json.dumps({"email": "jane@example.com", "role": "MEMBER"}), "{}"],
     ("PATCH", f"{BASE}/groups/team%40example.com/members/jane%40example.com", {"role": "OWNER"})),
])
def test_real_discovery_requests(argv, responses, expected, capsys):
    svc, http = svc_with(responses)
    rc = admin.main(argv, service=svc)
    out = json.loads(capsys.readouterr().out)
    assert rc == 0, out
    assert http.log[0][0] == "GET"  # before-state read
    assert http.log[-1] == expected
    assert len(http.log) == 2


def test_real_discovery_dry_run_only_reads(capsys):
    svc, http = svc_with([USER])
    assert admin.main(["user", "delete", "jane@example.com"], service=svc) == 0
    assert [m for m, _, _ in http.log] == ["GET"]
