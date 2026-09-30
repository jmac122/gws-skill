#!/usr/bin/env python3
"""Shared auth module for GWS skill — service account + domain-wide delegation.

Key path resolution (first match wins):
  1. explicit ``key_path`` argument / ``--key`` flag
  2. ``GWS_SERVICE_ACCOUNT_PATH`` env var (``~`` is expanded)
  3. ``DEFAULT_KEY_PATH`` (~/.config/gws/service-account.json)

The key file must not be readable/writable by group or others (chmod 600 or
400). Auth refuses to load a key with looser permissions.
"""

import argparse
import json
import os
import stat
import sys
from typing import Optional

from google.oauth2 import service_account
from googleapiclient.discovery import build

DEFAULT_KEY_PATH = os.path.expanduser("~/.config/gws/service-account.json")
# Kept for backwards compatibility; functions read the env at call time.
DEFAULT_ADMIN_EMAIL = os.environ.get("GWS_ADMIN_EMAIL", "")
DEFAULT_DOMAIN = os.environ.get("GWS_DOMAIN", "")

_DIR = "https://www.googleapis.com/auth/admin.directory."

# Scope sets by API. Read commands only ever request read-only scopes.
SCOPES = {
    "vault": ["https://www.googleapis.com/auth/ediscovery"],
    "reports": [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    ],
    "directory": [
        _DIR + "user.readonly",
        _DIR + "group.readonly",
        # orgunits.list/get require orgunit or orgunit.readonly (was missing).
        _DIR + "orgunit.readonly",
        _DIR + "device.chromeos.readonly",
    ],
    # Admin WRITE scopes, used only by scripts/admin.py. Verified per method
    # against the Directory API reference / discovery doc (rev 20260924):
    #   admin.directory.user          users.insert/update/delete/makeAdmin/get,
    #                                 users.aliases.insert/delete
    #   admin.directory.user.security users.signOut (only scope accepted)
    #   admin.directory.group         groups.insert/patch/delete/get,
    #                                 members.insert/patch/delete/get
    #   admin.directory.orgunit       orgunits.insert/patch/delete/get
    # admin.directory.user.alias and admin.directory.group.member are narrower
    # subsets of user/group and are therefore not requested.
    "directory_write": [
        _DIR + "user",
        _DIR + "user.security",
        _DIR + "group",
        _DIR + "orgunit",
    ],
    "gmail": ["https://www.googleapis.com/auth/gmail.readonly"],
    "drive": ["https://www.googleapis.com/auth/drive.readonly"],
    "calendar": ["https://www.googleapis.com/auth/calendar.readonly"],
    "sheets": ["https://www.googleapis.com/auth/spreadsheets.readonly"],
    "docs": ["https://www.googleapis.com/auth/documents.readonly"],
    "people": [
        "https://www.googleapis.com/auth/contacts.readonly",
        "https://www.googleapis.com/auth/directory.readonly",
    ],
}

# API service names and versions
API_INFO = {
    "vault": ("vault", "v1"),
    "reports": ("admin", "reports_v1"),
    "directory": ("admin", "directory_v1"),
    "directory_write": ("admin", "directory_v1"),
    "gmail": ("gmail", "v1"),
    "drive": ("drive", "v3"),
    "calendar": ("calendar", "v3"),
    "sheets": ("sheets", "v4"),
    "docs": ("docs", "v1"),
    "people": ("people", "v1"),
}


class AuthError(Exception):
    """Raised when credentials cannot be loaded safely."""


def admin_email() -> str:
    """Default DWD subject (GWS_ADMIN_EMAIL), read at call time."""
    return os.environ.get("GWS_ADMIN_EMAIL", "") or DEFAULT_ADMIN_EMAIL


def domain() -> str:
    """Primary domain (GWS_DOMAIN), read at call time."""
    return os.environ.get("GWS_DOMAIN", "") or DEFAULT_DOMAIN


def resolve_key_path(key_path: Optional[str] = None) -> str:
    """Resolve the service account key path (explicit > env > default)."""
    path = key_path or os.environ.get("GWS_SERVICE_ACCOUNT_PATH") or DEFAULT_KEY_PATH
    return os.path.abspath(os.path.expanduser(path))


def check_key_permissions(path: str) -> None:
    """Refuse to use a key file that group/others can access.

    Raises:
        AuthError: file missing, not a regular file, or mode is looser than 600.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise AuthError(f"Service account key not found: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise AuthError(f"Service account key is not a regular file: {path}")
    if os.name == "nt":  # POSIX permission bits are not meaningful on Windows
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise AuthError(
            f"Refusing to use service account key {path}: permissions are "
            f"{oct(mode)}, must be 600 (owner read/write only). Run: chmod 600 {path}"
        )


def get_credentials(
    api: str,
    impersonate: Optional[str] = None,
    key_path: Optional[str] = None,
) -> service_account.Credentials:
    """Get delegated credentials for a given API.

    Args:
        api: Key of SCOPES (vault, reports, directory, directory_write, gmail,
            drive, calendar, sheets, docs, people).
        impersonate: Email to impersonate via DWD. Defaults to GWS_ADMIN_EMAIL.
        key_path: Path to service account JSON key (see module docstring).

    Returns:
        Delegated credentials ready for API calls.
    """
    if api not in SCOPES:
        raise ValueError(f"Unknown API: {api}. Valid: {', '.join(SCOPES.keys())}")

    subject = impersonate or admin_email()
    if not subject:
        raise AuthError(
            "No user to impersonate: pass --user or set GWS_ADMIN_EMAIL. "
            "Domain-wide delegation requires a subject."
        )

    key_file = resolve_key_path(key_path)
    check_key_permissions(key_file)

    return service_account.Credentials.from_service_account_file(
        key_file,
        scopes=SCOPES[api],
        subject=subject,
    )


def get_service(
    api: str,
    impersonate: Optional[str] = None,
    key_path: Optional[str] = None,
):
    """Build an API service client with delegated credentials."""
    credentials = get_credentials(api, impersonate, key_path)
    service_name, version = API_INFO[api]
    return build(service_name, version, credentials=credentials, cache_discovery=False)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify service account + DWD auth by minting a real access token."
    )
    parser.add_argument("api", nargs="?", default="vault", choices=sorted(SCOPES))
    parser.add_argument("--user", help="Email to impersonate (default: GWS_ADMIN_EMAIL)")
    parser.add_argument("--key", help="Service account key path")
    args = parser.parse_args(argv)

    key_file = resolve_key_path(args.key)
    subject = args.user or admin_email()
    try:
        creds = get_credentials(args.api, args.user, args.key)
        # build() alone never contacts Google, so actually fetch a token to
        # prove the key + DWD scopes are authorized.
        import google_auth_httplib2
        import httplib2

        creds.refresh(google_auth_httplib2.Request(httplib2.Http()))
        print(json.dumps({
            "status": "ok",
            "api": args.api,
            "impersonating": subject,
            "key_path": key_file,
            "scopes": SCOPES[args.api],
        }))
        return 0
    except Exception as e:  # noqa: BLE001 — surface any auth failure as JSON
        print(json.dumps({
            "status": "error",
            "api": args.api,
            "impersonating": subject,
            "key_path": key_file,
            "error": str(e),
        }))
        return 1


if __name__ == "__main__":
    sys.exit(main())
