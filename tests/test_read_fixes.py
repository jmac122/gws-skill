"""Regression tests for bugs fixed in the read-only scripts."""
import base64
import json
from unittest import mock

from googleapiclient.discovery import build
from googleapiclient.http import HttpMockSequence

import directory
import docs
import gcalendar
import gmail
import reports


def test_reports_param_value_keeps_falsy_and_new_types():
    act = {"actor": {"email": "a@x.com", "profileId": "123"}, "events": [{"name": "e", "parameters": [
        {"name": "b", "boolValue": False}, {"name": "i", "intValue": "0"},
        {"name": "mi", "multiIntValue": ["1", "2"]}, {"name": "m", "messageValue": {"parameter": []}}]}]}
    out = reports._parse_activity(act)
    p = out["events"][0]["parameters"]
    assert p == {"b": False, "i": "0", "mi": ["1", "2"], "m": {"parameter": []}}
    assert out["actor_profile_id"] == "123"


def _b64(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def test_gmail_single_part_html_and_nested():
    assert gmail._extract_body({"mimeType": "text/html", "body": {"data": _b64("<p>Hi <b>there</b></p>")}}) == "Hi there"
    nested = {"mimeType": "multipart/mixed", "parts": [
        {"mimeType": "multipart/alternative", "parts": [
            {"mimeType": "text/html", "body": {"data": _b64("<i>html</i>")}},
            {"mimeType": "text/plain", "body": {"data": _b64("plain")}}]},
        {"mimeType": "text/plain", "filename": "a.txt", "body": {"attachmentId": "x"}}]}
    assert gmail._extract_body(nested) == "plain"


def test_docs_tabs_and_tables():
    para = lambda t: {"paragraph": {"elements": [{"textRun": {"content": t}}]}}  # noqa: E731
    doc = {"tabs": [
        {"tabProperties": {"title": "One"}, "documentTab": {"body": {"content": [para("a\n")]}},
         "childTabs": [{"tabProperties": {"title": "Child"}, "documentTab": {"body": {"content": [
             {"table": {"tableRows": [{"tableCells": [{"content": [para("x")]}, {"content": [para("y")]}]}]}}]}}}]},
        {"tabProperties": {"title": "Two"}, "documentTab": {"body": {"content": [para("b\n")]}}}]}
    text = docs._extract_text(doc)
    assert "=== One ===\na" in text and "x\ty" in text and "=== Two ===\nb" in text


def test_calendar_today_is_local_day():
    start, end = gcalendar._local_day_bounds(0)
    from datetime import datetime
    assert "T00:00:00" in start and "T00:00:00" in end  # local midnight, not UTC midnight
    assert datetime.fromisoformat(start).utcoffset() == datetime.now().astimezone().utcoffset()


def test_directory_customer_fallback_and_pagination(monkeypatch):
    monkeypatch.setenv("GWS_DOMAIN", "")
    monkeypatch.setattr(directory, "default_domain", lambda: "")
    assert directory._scope_kwargs(None) == {"customer": "my_customer"}
    pages = [json.dumps({"users": [{"primaryEmail": "a@x.com"}], "nextPageToken": "t"}),
             json.dumps({"users": [{"primaryEmail": "b@x.com"}]})]
    http = HttpMockSequence([({"status": "200"}, p) for p in pages])
    svc = build("admin", "directory_v1", http=http, static_discovery=True)
    with mock.patch.object(directory, "get_service", return_value=svc):
        out = directory.list_users(max_results=10)
    assert [u["email"] for u in out["users"]] == ["a@x.com", "b@x.com"]
