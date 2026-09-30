# GWS Skill — Setup Checklist

One-time setup for GCP service account + domain-wide delegation.

## 1. GCP Project

- Select or create a GCP project
- Enable these APIs:
  - Google Vault API
  - Admin SDK API
  - Gmail API
  - Google Drive API
  - Google Calendar API
  - Google Sheets API
  - Google Docs API
  - People API

```bash
gcloud services enable \
  vault.googleapis.com \
  admin.googleapis.com \
  gmail.googleapis.com \
  drive.googleapis.com \
  calendar-json.googleapis.com \
  sheets.googleapis.com \
  docs.googleapis.com \
  people.googleapis.com \
  --project <PROJECT_ID>
```

## 2. Service Account

- GCP Console → IAM & Admin → Service Accounts → Create
- Name it (e.g. `jarvis-gws`)
- No GCP roles needed (only GWS API access via DWD)
- Create a JSON key and download it
- Store at `~/.config/gws/service-account.json`
- `chmod 600 ~/.config/gws/service-account.json` — **required**: `auth.py` refuses to load a key that group/others can read or write
- Note the **Client ID** (numeric) from the service account details page

### "Service account key creation is disabled" (`iam.disableServiceAccountKeyCreation`)

Organizations created on or after 3 May 2024 are "secure by default" and enforce the
`iam.disableServiceAccountKeyCreation` org policy, so "Create new key" fails. A Workspace
super admin is **not** automatically allowed to change it. Exempt just this one project
(leave the org-wide policy on):

1. Someone with Organization Administrator (`roles/resourcemanager.organizationAdmin`) grants
   **Organization Policy Administrator** (`roles/orgpolicy.policyAdmin`) at the **organization**
   level (it can't be granted at project level) to the admin doing this.
2. Override the policy for the project only, either:
   - Console: IAM & Admin → Organization Policies → select the **project** →
     "Disable service account key creation" → Manage policy → **Override parent's policy** →
     Enforcement **Off / Not enforced** → Save; or
   - CLI:

     ```bash
     cat > key-creation.yaml <<EOF
     name: projects/<PROJECT_ID>/policies/iam.disableServiceAccountKeyCreation
     spec:
       rules:
       - enforce: false
     EOF
     gcloud org-policies set-policy key-creation.yaml
     ```
3. Wait a few minutes for propagation, create the key, then consider re-enforcing the policy
   on the project (existing keys keep working; only *new* key creation is blocked).
4. If the error lists a second constraint (e.g. the managed
   `iam.managed.disableServiceAccountKeyCreation`), override that one the same way.

Google's recommended long-term variant is tag-based: tag the project
`disableServiceAccountKeyCreation=not_enforced` and add a conditional rule
(`resource.matchTag('ORG_ID/disableServiceAccountKeyCreation', 'not_enforced')`) — see
<https://cloud.google.com/iam/docs/keys-create-delete#allow-creation>.

## 3. Domain-Wide Delegation

- Google Admin console → Security → Access and data control → API controls
- Manage Domain Wide Delegation → Add new (or edit the existing client)
- Client ID: paste the numeric client ID from step 2
- OAuth scopes (paste as one comma-separated line). **Every** scope a script requests must be
  authorized here, otherwise token minting fails with `unauthorized_client`.

**Option A — read-only** (all read scripts; `admin.py` will NOT work):

```
https://www.googleapis.com/auth/ediscovery,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/calendar.readonly,https://www.googleapis.com/auth/spreadsheets.readonly,https://www.googleapis.com/auth/documents.readonly,https://www.googleapis.com/auth/contacts.readonly,https://www.googleapis.com/auth/directory.readonly
```

**Option B — full** (read-only + admin writes for `admin.py`):

```
https://www.googleapis.com/auth/ediscovery,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/calendar.readonly,https://www.googleapis.com/auth/spreadsheets.readonly,https://www.googleapis.com/auth/documents.readonly,https://www.googleapis.com/auth/contacts.readonly,https://www.googleapis.com/auth/directory.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group,https://www.googleapis.com/auth/admin.directory.orgunit
```

Write scopes (verified against the Admin SDK Directory API reference, discovery rev 20260924):

| Scope | Used for |
|---|---|
| `admin.directory.user` | users.insert / update / delete / makeAdmin / get, users.aliases.insert / delete |
| `admin.directory.user.security` | users.signOut (the only scope that method accepts) |
| `admin.directory.group` | groups.insert / patch / delete / get, members.insert / patch / delete / get |
| `admin.directory.orgunit` | orgunits.insert / patch / delete / get |

`admin.directory.user.alias` and `admin.directory.group.member` are narrower subsets of the
user/group scopes above; they aren't requested, so you don't need to authorize them.
`admin.directory.orgunit.readonly` is new in the read-only string: `directory.py orgunits`
needs it and previously failed without it.

- Click Authorize. Changes can take a few minutes (occasionally up to 24h) to apply.
- The `GWS_ADMIN_EMAIL` account must itself be a super admin (or hold admin roles covering
  users, groups, org units, and security) for write calls to succeed.

## 4. Environment

Set these env vars (`GWS_ADMIN_EMAIL` is required; the key path defaults to `~/.config/gws/service-account.json`). Optional: `GWS_AUDIT_LOG` (default `~/.config/gws/audit.log`).

```bash
GWS_SERVICE_ACCOUNT_PATH="$HOME/.config/gws/service-account.json"   # "~" is also expanded by auth.py
GWS_ADMIN_EMAIL=admin@yourdomain.com
GWS_DOMAIN=yourdomain.com
```

## 5. Dependencies

```bash
pip3 install -r requirements.txt     # google-auth>=2.40, google-auth-httplib2>=0.2, google-api-python-client>=2.170 (Python >= 3.10)
```

## 6. Test

```bash
cd scripts/
python3 auth.py directory         # read scopes — should return {"status": "ok", ...}
python3 auth.py directory_write   # write scopes (Option B only)
python3 auth.py vault
python3 admin.py user suspend someone@yourdomain.com   # dry run only: reads state, changes nothing
```

## Google Workspace License Requirements

- **Vault API** needs a Google Workspace edition that includes Vault (e.g. Business Plus, Enterprise)
  or the **Google Vault add-on**. Vault licenses must be **assigned** to the `GWS_ADMIN_EMAIL`
  account running searches *and* to every account you want to search — unlicensed accounts show up
  as `non_queryable_accounts`. Newly purchased licenses can take 30–60 min to activate.
- The Vault user needs Vault privileges (super admins have them by default once licensed).
- If Multi-party approval for Vault exports is turned on, `vault.py --export` requests will wait
  for a second admin's approval.
- Admin SDK Directory/Reports and the other APIs work with any Google Workspace tier.
