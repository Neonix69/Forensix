# FORENSIX AI

**AI-assisted digital forensics timeline reconstruction.**
Turn fragmented security evidence (logins, file changes, process activity, network connections, database and cloud events) into a chronological, evidence-linked incident story.

> Built for the hackathon problem statement *"AI-Powered Digital Forensics Timeline Reconstruction"*.

---

## The problem

After a cyberattack, investigators receive piles of fragmented evidence in many formats. Individual events rarely tell the whole story; the value comes from correlating them. FORENSIX ingests mixed-format logs, normalizes them onto one timeline, flags suspicious activity, links related events, and explains every conclusion with the evidence behind it.

## Features

- **Mixed-format ingestion**: load several files at once; formats are auto-detected and merged into one timeline.
  - Syslog / Linux auth logs, Windows Security key-value event blocks
  - Firewall (RFC 5424-style) logs, Apache/Nginx access logs
  - `key=value` and pipe-separated logs, plain-text alerts (e.g. DLP)
  - JSON, JSONL/NDJSON, XML, CSV/TSV
- **Detection engine**: flags patterns such as external root login, credential-file access, brute force, MFA disabled, new privileged accounts, privilege assignment, web-file tampering, log deletion, web exploit patterns, bulk exports/queries, large outbound transfers, DLP alerts, encoded PowerShell, `rundll32` from temp folders, and persistence from `/tmp`.
- **Correlation**: links events that share an IP, host or user, and reports a time-ordered *probable multi-stage incident* across attack phases.
- **Incident narrative**: a step-by-step story of what the evidence suggests, in order.
- **Evidence traceability**: every finding lists its supporting event IDs; click any event to see why it was flagged and the original fields from the source log.
- **Interactive timeline** (Plotly), chronological trace, and an evidence ledger showing the source file of each record.
- **Export** an investigation brief as Markdown.
- **Access control**: login required; no public sign-up; admin console at `/admin` for creating users.
- **Workspace controls**: progress bar on load, "logs loaded" confirmation, list of loaded files, load another / remove a file / clear all / clear & load new.

> All findings are rule-based indicators for **human validation**, not verdicts. Each finding explains its reasoning and caveats.

## Quick start

Requires Python 3.9+.

```bash
git clone <your-repo-url>
cd <repo-folder>
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

### First sign-in

On first run an administrator account is created and its credentials are **printed in the terminal**. To choose them yourself, set environment variables before the first start:

```bash
# macOS / Linux
FORENSIX_ADMIN_USER=admin FORENSIX_ADMIN_PASSWORD='a-strong-password' python app.py
```
```powershell
# Windows PowerShell
$env:FORENSIX_ADMIN_USER="admin"; $env:FORENSIX_ADMIN_PASSWORD="a-strong-password"; python app.py
```

To reset all accounts, stop the app and delete the `instance/` folder.

## Try it with the sample data

1. Sign in and click **LOAD LOGS**.
2. Select **all files** in `sample_security_logs/` (10 files, 10 formats) at once.
3. You should see 18 events, 22 findings, a "Probable multi-stage incident" lead, and a 16-step incident narrative (access, persistence, privilege escalation, collection and data-exfiltration attempts across several hosts).

`forensix_sample_logs.csv` is a smaller single-file example.

## User management

There is **no public registration**. Accounts are created only in the backend:

| Method | How |
|---|---|
| Admin console | Sign in at `/admin` (own sign-in page at `/admin/login`) to create users, reset passwords and delete users. Roles: *Analyst* or *Admin*. |
| Command line | `flask --app app create-user NAME --admin` (omit `--admin` for an analyst) |

Analyst accounts that open `/admin` see an "Access denied" page.

## Using the app

| Action | What it does |
|---|---|
| **Load logs / Load another** | Pick one or more files (or drag & drop). They are parsed, merged into the timeline and analyzed automatically. |
| **Loaded files** panel | Shows each file's size, record count, time range and rows skipped (unreadable timestamps). Each file has a **Remove** button. |
| **Clear & load new** | Discards everything and starts over with new files. |
| **Clear all** | Empties the workspace. |
| **Export brief** | Downloads a Markdown investigation brief with findings and evidence IDs. |

Limits: 25 MB per file, 100 MB per upload. Timestamps with a timezone are converted to UTC; timestamps without one are treated as UTC; logs without a year (syslog) use the current year.

## Project structure

```
├── app.py                  # Flask app: auth, /admin, upload API, workspace, report
├── parsers.py              # Format detection + parsing -> normalized records
├── detect.py               # Detection rules, correlation, incident narrative
├── templates/
│   ├── index.html          # Main investigation UI
│   ├── login.html          # Analyst + admin sign-in
│   ├── admin.html          # Admin console
│   └── admin_denied.html   # Shown to non-admins at /admin
├── static/auth.css         # Styles for login/admin pages
├── sample_security_logs/   # 10-file mixed-format test dataset
├── forensix_sample_logs.csv
└── requirements.txt
```

## How it works

1. **Parse**: each file is sniffed (XML / JSON / CSV / key-value blocks / log lines) and every record becomes `timestamp, user, source IP, host, action, details` plus its original fields.
2. **Normalize**: timestamps are converted to UTC, records are merged and sorted, and IDs are made unique across files.
3. **Detect**: rules in `detect.py` tag each event with an attack tactic, severity and a plain-English reason.
4. **Correlate**: flagged events are linked by shared entities and time proximity; ordered attack phases form the narrative.
5. **Explain**: every finding keeps links to the event IDs that triggered it.

### Extending the detections

Add a rule in `evaluate()` in `detect.py`. A rule returns `(action, event_type, tactic, severity 1-3, reason)`. New log formats can be added in `parsers.py` by producing a record with `ts`, `fields`, `message` and `fmt`.

## Security notes

- Passwords are hashed (Werkzeug); forms and API calls are CSRF-protected; repeated failed logins are temporarily locked out; security headers are set.
- Loaded logs are held **in server memory** per signed-in user and cleared on sign-out or restart. Nothing is written to disk except the user database in `instance/`.
- This is a prototype. For real deployment run behind a production WSGI server (e.g. `gunicorn`) with HTTPS and a fixed `FORENSIX_SECRET_KEY`. Do not enable `FLASK_DEBUG=1` outside development.

### Configuration

| Variable | Purpose | Default |
|---|---|---|
| `FORENSIX_ADMIN_USER` / `FORENSIX_ADMIN_PASSWORD` | First-run admin account | `admin` / generated |
| `FORENSIX_SECRET_KEY` | Session signing key | generated in `instance/secret_key` |
| `HOST`, `PORT` | Bind address / port | `127.0.0.1`, `5000` |
| `FLASK_DEBUG` | Set to `1` for dev mode | off |

## Limitations

- Analysis is rule-based; rules are tuned to common attack patterns and will need extension for other log sources.
- Entity links and the multi-stage finding are based on shared fields and timing, which suggest but do not prove a connection.
- In-memory workspaces are single-process and not persisted.

## Tech stack

Python, Flask, pandas, SQLite, Plotly.js, vanilla JavaScript.

## Disclaimer

All sample data is fictional and uses reserved documentation IP ranges. Findings are leads for human review and must not be treated as proof of an attack.
