#!/usr/bin/env python3
"""Google Calendar API — read events via domain-wide delegation."""

import argparse
import json
import sys
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from auth import get_service


def list_events(
    user: str,
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 20,
    calendar_id: str = "primary",
    query: Optional[str] = None,
) -> dict:
    """List calendar events for a user.

    Args:
        user: Email address (impersonated via DWD).
        time_min: Start time (ISO 8601). Defaults to now.
        time_max: End time (ISO 8601). Defaults to 7 days from now.
        max_results: Max events to return.
        calendar_id: Calendar ID (default 'primary').
        query: Free text search query (optional).

    Returns:
        Dict with event list.
    """
    service = get_service("calendar", impersonate=user)

    now = datetime.now(timezone.utc)
    if not time_min:
        time_min = now.isoformat()
    if not time_max:
        time_max = (now + timedelta(days=7)).isoformat()

    kwargs = {
        "calendarId": calendar_id,
        "timeMin": time_min,
        "timeMax": time_max,
        "maxResults": max_results,
        "singleEvents": True,
        "orderBy": "startTime",
    }
    if query:
        kwargs["q"] = query

    results = service.events().list(**kwargs).execute()
    events = results.get("items", [])

    return {
        "user": user,
        "calendar": calendar_id,
        "time_range": {"min": time_min, "max": time_max},
        "total": len(events),
        "events": [_parse_event(e) for e in events],
    }


def list_calendars(user: str) -> dict:
    """List all calendars for a user.

    Args:
        user: Email address.

    Returns:
        Dict with calendar list.
    """
    service = get_service("calendar", impersonate=user)
    results = service.calendarList().list().execute()
    calendars = results.get("items", [])

    return {
        "user": user,
        "total": len(calendars),
        "calendars": [
            {
                "id": c.get("id", ""),
                "summary": c.get("summary", ""),
                "description": c.get("description", ""),
                "primary": c.get("primary", False),
                "access_role": c.get("accessRole", ""),
                "time_zone": c.get("timeZone", ""),
            }
            for c in calendars
        ],
    }


def get_event(
    user: str,
    event_id: str,
    calendar_id: str = "primary",
) -> dict:
    """Get a specific event by ID.

    Args:
        user: Email address.
        event_id: Event ID.
        calendar_id: Calendar ID.

    Returns:
        Event details dict.
    """
    service = get_service("calendar", impersonate=user)
    e = service.events().get(
        calendarId=calendar_id,
        eventId=event_id,
    ).execute()

    return _parse_event(e)


def _calendar_time_zone(user: str, calendar_id: str) -> Optional[str]:
    """IANA time zone of a calendar, or None if the calendar does not set one.

    ``calendar.readonly`` allows calendars.get.
    """
    service = get_service("calendar", impersonate=user)
    tz = service.calendars().get(calendarId=calendar_id).execute().get("timeZone")
    return tz or None


def today_events(user: str, tz_name: Optional[str] = None, today: Optional[date] = None,
                 calendar_id: str = "primary") -> dict:
    """Events for today's date in the calendar's time zone.

    ``tz_name`` is an IANA override; when set, the calendar is not fetched.
    ``today`` overrides the date (tests). Falls back to the host zone only if
    the calendar has no timeZone and ``tz_name`` was not given.
    """
    if not tz_name:
        tz_name = _calendar_time_zone(user, calendar_id)
    return list_events(user, *_day_bounds(0, tz_name, today=today), calendar_id=calendar_id)


def tomorrow_events(user: str, tz_name: Optional[str] = None, today: Optional[date] = None,
                    calendar_id: str = "primary") -> dict:
    """Events for tomorrow's date in the calendar's time zone.

    See ``today_events`` for ``tz_name`` / ``today``.
    """
    if not tz_name:
        tz_name = _calendar_time_zone(user, calendar_id)
    return list_events(user, *_day_bounds(1, tz_name, today=today), calendar_id=calendar_id)


def _day_bounds(offset_days: int, tz_name: Optional[str] = None, today: Optional[date] = None) -> tuple:
    """Midnight-to-midnight bounds of a day in ``tz_name`` (IANA).

    The day is today's date in that zone (``datetime.now(zone).date() + offset``),
    or ``today`` when a test freezes the date. Each bound is built with
    ``datetime.combine(date, time(), tzinfo=zone)`` so a DST transition gets the
    offset in effect at that midnight. With no ``tz_name``, fall back to the
    host's local zone (only used when the calendar has no timeZone).
    """
    if tz_name:
        zone = ZoneInfo(tz_name)
        base = today if today is not None else datetime.now(zone).date()
        day = base + timedelta(days=offset_days)
        start = datetime.combine(day, time(), tzinfo=zone)
        end = datetime.combine(day + timedelta(days=1), time(), tzinfo=zone)
        return start.isoformat(), end.isoformat()

    base = today if today is not None else datetime.now().astimezone().date()
    day = base + timedelta(days=offset_days)
    start = datetime.combine(day, time()).astimezone()
    end = datetime.combine(day + timedelta(days=1), time()).astimezone()
    return start.isoformat(), end.isoformat()


def _parse_event(e: dict) -> dict:
    """Parse a Calendar event into a clean dict."""
    start = e.get("start", {})
    end = e.get("end", {})
    attendees = e.get("attendees", [])

    return {
        "id": e.get("id", ""),
        "summary": e.get("summary", "(No title)"),
        "description": e.get("description", ""),
        "location": e.get("location", ""),
        "start": start.get("dateTime") or start.get("date", ""),
        "end": end.get("dateTime") or end.get("date", ""),
        "all_day": "date" in start and "dateTime" not in start,
        "status": e.get("status", ""),
        "organizer": e.get("organizer", {}).get("email", ""),
        "creator": e.get("creator", {}).get("email", ""),
        "attendees": [
            {
                "email": a.get("email", ""),
                "name": a.get("displayName", ""),
                "response": a.get("responseStatus", ""),
                "organizer": a.get("organizer", False),
            }
            for a in attendees
        ],
        "hangout_link": e.get("hangoutLink", ""),
        "html_link": e.get("htmlLink", ""),
        "recurring": bool(e.get("recurringEventId")),
    }


def main():
    parser = argparse.ArgumentParser(description="Google Calendar read")
    sub = parser.add_subparsers(dest="command", required=True)

    # events
    p_events = sub.add_parser("events", help="List events")
    p_events.add_argument("--user", required=True)
    p_events.add_argument("--start", help="Start time (ISO 8601)")
    p_events.add_argument("--end", help="End time (ISO 8601)")
    p_events.add_argument("--max", type=int, default=20)
    p_events.add_argument("--calendar", default="primary")
    p_events.add_argument("--query", help="Search query")

    # calendars
    p_cals = sub.add_parser("calendars", help="List calendars")
    p_cals.add_argument("--user", required=True)

    # today
    p_today = sub.add_parser("today", help="Today's events (calendar time zone)")
    p_today.add_argument("--user", required=True)
    p_today.add_argument("--tz", help="IANA time zone override (default: the calendar's time zone)")

    # tomorrow
    p_tomorrow = sub.add_parser("tomorrow", help="Tomorrow's events (calendar time zone)")
    p_tomorrow.add_argument("--user", required=True)
    p_tomorrow.add_argument("--tz", help="IANA time zone override (default: the calendar's time zone)")

    # event
    p_event = sub.add_parser("event", help="Get specific event")
    p_event.add_argument("--user", required=True)
    p_event.add_argument("--id", required=True)
    p_event.add_argument("--calendar", default="primary")

    args = parser.parse_args()

    try:
        if args.command == "events":
            result = list_events(args.user, args.start, args.end, args.max, args.calendar, args.query)
        elif args.command == "calendars":
            result = list_calendars(args.user)
        elif args.command == "today":
            result = today_events(args.user, tz_name=args.tz)
        elif args.command == "tomorrow":
            result = tomorrow_events(args.user, tz_name=args.tz)
        elif args.command == "event":
            result = get_event(args.user, args.id, args.calendar)
        else:
            result = {"error": f"Unknown command: {args.command}"}

        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
