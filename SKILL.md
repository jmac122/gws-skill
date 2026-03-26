---
name: gws
description: Google Workspace admin skill — Vault search, Gmail read, Directory, Reports, Drive, Calendar, Sheets, Docs, Chat, People via service account + domain-wide delegation.
---

# GWS Skill

Unified Google Workspace admin and investigation tool. All scripts live in `scripts/` relative to this file.

## Auth

All scripts use `scripts/auth.py` which loads a service account key from `~/.config/gws/service-account.json` and impersonates users via domain-wide delegation.

- Default admin: `jmckenzie@precisionsiteservices.com`
- Domain: `precisionsiteservices.com`
- To impersonate another user, pass their email to the `--user` flag

## Available Tools

### Vault — Email Investigation (org-wide content search)

Search anyone's email content across the org. Creates a temporary matter, runs the query, returns results, auto-deletes the matter.

```bash
# Count emails matching a query for specific accounts
python3 scripts/vault.py --accounts user@precisionsiteservices.com --terms "from:vendor@acme.com" --start "2026-03-01T00:00:00Z" --end "2026-03-26T23:59:59Z"

# Search across an entire org unit
python3 scripts/vault.py --org-unit <orgUnitId> --terms "subject:confidential"

# Export full content (creates downloadable MBOX)
python3 scripts/vault.py --accounts user@precisionsiteservices.com --terms "from:vendor@acme.com" --export
```

**Search terms** use Gmail search operators: `from:`, `to:`, `subject:`, `has:attachment`, `filename:`, `newer_than:`, `older_than:`, `is:starred`, etc.

### Gmail — Read & Search Any User's Inbox

Search and read emails from any user's mailbox via DWD.

```bash
# Search with metadata summary (from, to, subject, date, snippet)
python3 scripts/gmail.py --user user@precisionsiteservices.com --query "from:acme.com newer_than:7d" --max 10 --mode summary

# Search with full email body content
python3 scripts/gmail.py --user user@precisionsiteservices.com --query "from:acme.com" --max 5 --mode full

# Read a specific email by message ID
python3 scripts/gmail.py --user user@precisionsiteservices.com --query "" --mode read --message-id <messageId>
```

**Workflow:** Use Vault to count/find across the org → use Gmail to read the actual content.

### Directory — Users, Groups, OUs

```bash
# List all users
python3 scripts/directory.py users --max 100

# Search users by name or email
python3 scripts/directory.py users --query "name:Jared"

# Get specific user details
python3 scripts/directory.py user jmckenzie@precisionsiteservices.com

# List all groups
python3 scripts/directory.py groups

# List members of a group
python3 scripts/directory.py members group@precisionsiteservices.com

# List org units
python3 scripts/directory.py orgunits
```

### Reports — Audit Logs & Activity

```bash
# Login activity (all users, last 25)
python3 scripts/reports.py login --max 25

# Login activity for specific user
python3 scripts/reports.py login --user user@precisionsiteservices.com --max 10

# Failed logins only
python3 scripts/reports.py login --event login_failure

# Admin console activity
python3 scripts/reports.py admin --max 25

# Drive activity (who accessed/shared what)
python3 scripts/reports.py drive --max 25

# Drive activity for specific user
python3 scripts/reports.py drive --user user@precisionsiteservices.com

# OAuth token grants (third-party app access)
python3 scripts/reports.py token --max 25

# Gmail activity metadata
python3 scripts/reports.py gmail --max 25
```

All reports support `--start` and `--end` (ISO 8601) for date filtering.

## Investigation Workflow

When Jared asks "did X person receive emails from Y":

1. **Vault count** — Quick count to confirm emails exist: `vault.py --accounts X --terms "from:Y"`
2. **Gmail summary** — Get metadata list: `gmail.py --user X --query "from:Y" --mode summary`
3. **Gmail full** — Read the actual email content: `gmail.py --user X --query "from:Y" --mode full`

When Jared asks about login/security:

1. **Reports login** — Check login activity: `reports.py login --user X`
2. **Directory user** — Get user details: `directory.py user X`

## Output

All scripts output JSON. Parse and summarize in natural language for the user. Never dump raw email content to Signal unprompted — summarize unless explicitly asked for full content.

### Drive — Search & Read Any User's Files

```bash
# Search files
python3 scripts/drive.py search --user user@precisionsiteservices.com --query "name contains 'invoice'" --max 10

# Recent files
python3 scripts/drive.py recent --user user@precisionsiteservices.com --max 10

# File metadata by ID
python3 scripts/drive.py file --user user@precisionsiteservices.com --id <fileId>

# Files shared externally
python3 scripts/drive.py shared --user user@precisionsiteservices.com

# Search by type (doc, sheet, slide, pdf, image, folder)
python3 scripts/drive.py type --user user@precisionsiteservices.com --type sheet
```

### Calendar — Read Any User's Calendar

```bash
# Today's events
python3 scripts/gcalendar.py today --user user@precisionsiteservices.com

# Tomorrow's events
python3 scripts/gcalendar.py tomorrow --user user@precisionsiteservices.com

# Events in date range
python3 scripts/gcalendar.py events --user user@precisionsiteservices.com --start "2026-03-01T00:00:00Z" --end "2026-03-31T23:59:59Z"

# List all calendars
python3 scripts/gcalendar.py calendars --user user@precisionsiteservices.com

# Search events by keyword
python3 scripts/gcalendar.py events --user user@precisionsiteservices.com --query "meeting"
```

Note: Calendar script is `gcalendar.py` (avoids Python stdlib `calendar` module collision).

### Sheets — Read Spreadsheet Data

```bash
# Get spreadsheet metadata (list all tabs)
python3 scripts/sheets.py metadata --user user@precisionsiteservices.com --id <spreadsheetId>

# Read a range
python3 scripts/sheets.py get --user user@precisionsiteservices.com --id <spreadsheetId> --range "Sheet1!A1:D10"

# Read multiple ranges at once
python3 scripts/sheets.py batch --user user@precisionsiteservices.com --id <spreadsheetId> --ranges "Sheet1!A1:B5" "Sheet2!A1:C3"
```

### Docs — Read Document Content

```bash
# Get document with full text
python3 scripts/docs.py get --user user@precisionsiteservices.com --id <documentId>

# Get text content only
python3 scripts/docs.py text --user user@precisionsiteservices.com --id <documentId>
```

### Chat — Read Google Chat Spaces & Messages

```bash
# List Chat spaces
python3 scripts/chat.py spaces --user user@precisionsiteservices.com

# List messages in a space
python3 scripts/chat.py messages --user user@precisionsiteservices.com --space "spaces/AAAA" --max 25
```

### People — Contacts & Org Directory

```bash
# List a user's contacts
python3 scripts/people.py contacts --user user@precisionsiteservices.com --max 50

# Search contacts
python3 scripts/people.py search --user user@precisionsiteservices.com --query "John"

# Search org directory
python3 scripts/people.py directory --user user@precisionsiteservices.com --query "manager"
```
