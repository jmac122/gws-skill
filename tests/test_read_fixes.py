"""Regression tests for bugs fixed in the read-only scripts."""
import base64
import json
from datetime import date, datetime, timedelta
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


def test_day_bounds_america_chicago_offsets():
    summer = gcalendar._day_bounds(0, "America/Chicago", today=date(2026, 7, 15))
    winter = gcalendar._day_bounds(0, "America/Chicago", today=date(2026, 1, 15))
    assert summer == ("2026-07-15T00:00:00-05:00", "2026-07-16T00:00:00-05:00")
    assert winter == ("2026-01-15T00:00:00-06:00", "2026-01-16T00:00:00-06:00")
    assert "T00:00:00" in summer[0] and "T00:00:00" in winter[0]


def test_day_bounds_chicago_dst_fallback():
    # 2026-11-01 is the US fallback day: midnight is still CDT, the next midnight is CST.
    start, end = gcalendar._day_bounds(0, "America/Chicago", today=date(2026, 11, 1))
    assert start == "2026-11-01T00:00:00-05:00"
    assert end == "2026-11-02T00:00:00-06:00"


def test_today_events_uses_calendar_timezone():
    svc = mock.MagicMock()
    svc.calendars.return_value.get.return_value.execute.return_value = {"timeZone": "America/Chicago"}
    svc.events.return_value.list.return_value.execute.return_value = {"items": []}
    with mock.patch.object(gcalendar, "get_service", return_value=svc):
        out = gcalendar.today_events("user@example.com", today=date(2026, 7, 15))
    svc.calendars.return_value.get.assert_called_once_with(calendarId="primary")
    kw = svc.events.return_value.list.call_args.kwargs
    assert kw["timeMin"] == "2026-07-15T00:00:00-05:00"
    assert kw["timeMax"] == "2026-07-16T00:00:00-05:00"
    assert out["time_range"]["min"] == kw["timeMin"]


def test_tomorrow_events_uses_calendar_timezone():
    svc = mock.MagicMock()
    svc.calendars.return_value.get.return_value.execute.return_value = {"timeZone": "America/Chicago"}
    svc.events.return_value.list.return_value.execute.return_value = {"items": []}
    with mock.patch.object(gcalendar, "get_service", return_value=svc):
        gcalendar.tomorrow_events("user@example.com", today=date(2026, 1, 15))
    kw = svc.events.return_value.list.call_args.kwargs
    assert kw["timeMin"] == "2026-01-16T00:00:00-06:00"
    assert kw["timeMax"] == "2026-01-17T00:00:00-06:00"


def test_today_events_tz_override_skips_calendar_fetch():
    svc = mock.MagicMock()
    svc.events.return_value.list.return_value.execute.return_value = {"items": []}
    with mock.patch.object(gcalendar, "get_service", return_value=svc):
        gcalendar.today_events("user@example.com", tz_name="America/Chicago", today=date(2026, 11, 1))
    assert svc.calendars.return_value.get.called is False
    kw = svc.events.return_value.list.call_args.kwargs
    assert kw["timeMin"] == "2026-11-01T00:00:00-05:00"
    assert kw["timeMax"] == "2026-11-02T00:00:00-06:00"


def test_today_events_without_calendar_tz_uses_host_zone():
    svc = mock.MagicMock()
    svc.calendars.return_value.get.return_value.execute.return_value = {"id": "primary"}
    svc.events.return_value.list.return_value.execute.return_value = {"items": []}
    day = date(2026, 7, 15)
    with mock.patch.object(gcalendar, "get_service", return_value=svc):
        gcalendar.today_events("user@example.com", today=day)
    kw = svc.events.return_value.list.call_args.kwargs
    host_start = datetime.combine(day, datetime.min.time()).astimezone()
    host_end = datetime.combine(day + timedelta(days=1), datetime.min.time()).astimezone()
    assert kw["timeMin"] == host_start.isoformat()
    assert kw["timeMax"] == host_end.isoformat()


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


def test_docs_leaf_child_tab_is_labeled():
    para = lambda t: {"paragraph": {"elements": [{"textRun": {"content": t}}]}}  # noqa: E731
    doc = {"tabs": [{"tabProperties": {"title": "Parent"}, "documentTab": {"body": {"content": [para("p\n")]}},
                     "childTabs": [{"tabProperties": {"title": "Leaf"},
                                    "documentTab": {"body": {"content": [para("c\n")]}}}]}]}
    assert docs._extract_text(doc) == "=== Parent ===\np\n\n=== Leaf ===\nc\n"
    single = {"tabs": [{"tabProperties": {"title": "Only"}, "documentTab": {"body": {"content": [para("x")]}}}]}
    assert docs._extract_text(single) == "x"  # single tab stays unlabeled
