# GWS Skill — Build Plan

**Goal:** A unified Google Workspace skill for Jarvis that covers admin investigation, productivity, and org-wide data access across all major GWS APIs.

---

## What We're Building

A single `gws` skill (AgentSkill) backed by Python scripts that wraps the following Google APIs:

| API | Purpose |
|-----|---------|
| Vault API | Search anyone's email/Drive/Chat content org-wide (eDiscovery) |
| Reports API | Audit logs — logins, Gmail activity, Drive access, admin actions |
| Directory API | Users, groups, OUs, devices |
| Gmail API (DWD) | Read/search/send email as any user |
| Drive API (DWD) | Search, read, share files as any user |
| Calendar API (DWD) | Read/create events across any calendar |
| Docs / Sheets (DWD) | Read and write documents and spreadsheets |
| Chat API | Read/send in Google Chat spaces |
| People API | Org directory + personal contacts |

**DWD = Domain-Wide Delegation** — service account impersonates any user without per-user OAuth.

---

## Auth Architecture

### Single Auth Layer
- **GCP Service Account** in the PSS org (project: `precision-command-center` or new dedicated project)
- **Domain-Wide Delegation** enabled in Google Admin console
- OAuth scopes granted once — covers all APIs
- Service account key JSON stored locally at `~/.config/gws/service-account.json` (never committed)
- Python auth module handles: token generation, refresh, impersonation, scope selection

### Required OAuth Scopes (to be granted in Admin console)

```
https://www.googleapis.com/auth/ediscovery                    # Vault
https://www.googleapis.com/auth/admin.reports.audit.readonly  # Reports - audit
https://www.googleapis.com/auth/admin.reports.usage.readonly  # Reports - usage
https://www.googleapis.com/auth/admin.directory.user.readonly # Directory - users
https://www.googleapis.com/auth/admin.directory.group.readonly# Directory - groups
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/gmail.readonly                # Gmail read
https://www.googleapis.com/auth/gmail.send                    # Gmail send
https://www.googleapis.com/auth/drive.readonly                # Drive read
https://www.googleapis.com/auth/calendar.readonly             # Calendar read
https://www.googleapis.com/auth/calendar                      # Calendar write
https://www.googleapis.com/auth/spreadsheets                  # Sheets read/write
https://www.googleapis.com/auth/documents.readonly            # Docs read
https://www.googleapis.com/auth/chat.messages                 # Chat
https://www.googleapis.com/auth/contacts.readonly             # People/Contacts
```

---

## Directory Structure

```
~/clawd/skills/gws/
├── SKILL.md                  # AgentSkill definition (Jarvis's instructions)
├── PLAN.md                   # This file
├── scripts/
│   ├── auth.py               # Shared auth module (service account + DWD)
│   ├── vault.py              # Vault API — search, export, count
│   ├── reports.py            # Reports API — audit logs, activity
│   ├── directory.py          # Directory API — users, groups, OUs, devices
│   ├── gmail.py              # Gmail API — search, read, send
│   ├── drive.py              # Drive API — search, read
│   ├── calendar.py           # Calendar API — list, create, update events
│   ├── sheets.py             # Sheets API — read, write
│   ├── docs.py               # Docs API — read/export
│   ├── chat.py               # Chat API — read, send
│   └── people.py             # People API — contacts, org directory
├── requirements.txt          # Python dependencies
└── references/
    ├── vault-query-operators.md    # Gmail search operators for Vault
    ├── reports-api-events.md       # Reports API event names reference
    └── setup-checklist.md          # One-time GCP + Admin console setup steps
```

---

## Build Phases

### Phase 1 — Foundation (Start Here)
**Goal:** Auth working, Vault search working end-to-end.

1. [ ] Create GCP service account
2. [ ] Enable APIs in GCP: Vault, Admin SDK, Gmail, Drive, Calendar, Sheets, Docs, Chat, People
3. [ ] Grant DWD in Google Admin console with all scopes
4. [ ] Download service account key → `~/.config/gws/service-account.json`
5. [ ] Build `auth.py` — handles credential loading, impersonation, token refresh
6. [ ] Build `vault.py` — create matter, run search, count results, list exports
7. [ ] Write `SKILL.md` (basic version) covering Vault commands
8. [ ] Test: "Did user@pss.com receive any emails from vendor@acme.com in the last 30 days?"

**Success criteria:** Jarvis can answer the above question via natural language → API call → plain English result.

### Phase 2 — Reports + Directory
**Goal:** Admin audit and org visibility.

1. [ ] Build `reports.py` — Gmail activity logs, login reports, Drive access, admin audit, OAuth tokens
2. [ ] Build `directory.py` — list users, lookup by name/email, list groups, group members, devices
3. [ ] Update `SKILL.md` with Reports + Directory commands
4. [ ] Test: "Who in the org logged in from an unusual location this week?"
5. [ ] Test: "List all members of the managers group"

### Phase 3 — Gmail + Drive (DWD)
**Goal:** Read/act on any user's mailbox or Drive.

1. [ ] Build `gmail.py` — search inbox, read message, send as user, list labels
2. [ ] Build `drive.py` — search files, get metadata, download, check sharing
3. [ ] Update `SKILL.md`
4. [ ] Test: "Search john@pss.com's inbox for any messages about the Katy project"
5. [ ] Test: "Find all Drive files shared externally in the last 7 days"

### Phase 4 — Calendar, Sheets, Docs
**Goal:** Productivity layer.

1. [ ] Build `calendar.py` — list events, create event, update, delete
2. [ ] Build `sheets.py` — read range, write range, append, clear
3. [ ] Build `docs.py` — read/export document content
4. [ ] Update `SKILL.md`
5. [ ] Test: "What's on Sarah's calendar tomorrow?"
6. [ ] Test: "Pull the data from the Job Cost sheet, tab Q1"

### Phase 5 — Chat + People + Polish
**Goal:** Full coverage, SKILL.md finalized.

1. [ ] Build `chat.py` — list spaces, read messages, send message
2. [ ] Build `people.py` — org directory search, contact lookup
3. [ ] Final `SKILL.md` pass — full natural language examples, edge cases documented
4. [ ] Refactor shared utilities (pagination, error handling, output formatting)
5. [ ] Write `references/setup-checklist.md` for future reference

---

## Design Rules

1. **Scripts return JSON** — Jarvis parses and summarizes in natural language
2. **Every script is standalone** — can be called directly from shell for debugging
3. **Sensitive output** — Jarvis never dumps raw email content to Signal unprompted; always summarizes unless asked for full content
4. **Impersonation is explicit** — every DWD call logs which account is being impersonated
5. **Scope of access is minimum needed** — read-only scopes where write isn't required
6. **No secrets in code** — service account path from env var `GWS_SERVICE_ACCOUNT_PATH` (default: `~/.config/gws/service-account.json`)
7. **Admin email required for DWD** — stored as env var `GWS_ADMIN_EMAIL` (the super-admin account to impersonate for admin-level calls)

---

## Environment Variables

```bash
GWS_SERVICE_ACCOUNT_PATH=~/.config/gws/service-account.json
GWS_ADMIN_EMAIL=jmckenzie@precisionsiteservices.com
GWS_DOMAIN=precisionsiteservices.com
```

These can be set in the OpenClaw config `env` block so Jarvis always has them available.

---

## Dependencies (requirements.txt)

```
google-auth
google-auth-httplib2
google-api-python-client
```

---

## Open Questions (Decide Before Building)

1. **GCP Project** — ✅ Decided: use existing `precision-command-center`
2. **Vault matter management** — ✅ Decided: create matter → run query → return results → delete matter automatically. No accumulation, no manual cleanup.
3. **Output verbosity** — ✅ Decided: return full email content when a specific email is found. Metadata (sender, recipient, subject, date, count) for broad searches with multiple results.
4. **Write access** — ✅ Decided: read-only across all APIs. No sending email as others, no calendar writes, no sheet edits. Investigation and visibility only.

---

## Setup Checklist (One-Time)

- [ ] GCP: Create/select project
- [ ] GCP: Enable all required APIs
- [ ] GCP: Create service account, download key JSON
- [ ] GCP: Note the service account's unique ID (for DWD)
- [ ] Google Admin: Go to Security → API Controls → Domain-wide Delegation
- [ ] Google Admin: Add service account client ID + paste all scopes
- [ ] Local: Place key at `~/.config/gws/service-account.json` (chmod 600)
- [ ] Local: Set env vars in OpenClaw config
- [ ] Test auth with `python3 scripts/auth.py`

---

*Created: 2026-03-26*
*Status: Planning — Phase 1 not started*
