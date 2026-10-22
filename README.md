# FORENSIX AI — Incident timeline reconstruction

Flask web app with login, admin-managed accounts and multi-file log loading.

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

**First run:** an administrator account is created and its username/password are printed in the terminal.
To choose your own, set them before the first start:

```powershell
$env:FORENSIX_ADMIN_USER="admin"; $env:FORENSIX_ADMIN_PASSWORD="a-strong-password"; python app.py
```

(Keep the `instance/` folder to preserve your accounts.)

## Accounts

There is **no public sign-up**. New users are created only in the backend:

- **/admin** (admin accounts only): register users, choose Analyst/Admin role, reset passwords, delete users.
- or from the server terminal: `flask --app app create-user NAME --admin` (omit `--admin` for an analyst).

Passwords are hashed, forms are CSRF-protected, and repeated failed logins are temporarily locked out after 10 failed attempts for 3 minutes. Username matching is case-insensitive.

**If login fails:** stop the server and run `python -m flask --app app reset-password` from this project folder. The command lists accounts in the exact database used by this project, then lets you reset one password. You can also run `python -m flask --app app reset-password admin` to target a known username (it will prompt for the new password twice). The server prints the active database path at startup; make sure you run the command and server from the same extracted folder.

The account database is stored at `instance/forensix.db`. Keep the `instance/` folder when replacing application files, because it contains your accounts.
Each user has their own private workspace of loaded logs.

## Loading logs

- **Load logs / Load another** — pick one or more files (or drag them onto the intake box). They are merged into one timeline and analyzed automatically.
- A progress bar shows the upload, and a popup that disappears by itself confirms "Logs loaded".
- **Loaded files** panel lists every file with size, record count, time range and any rows skipped for unreadable timestamps. Each has a **Remove** button.
- **Clear & load new** — discard everything and start over with new files. **Clear all** — empty the workspace.

Supported formats (auto-detected, can be mixed in one timeline): syslog/auth logs, Windows key-value event blocks, firewall (RFC5424-style) logs, Apache/Nginx access logs, pipe/key=value logs, text alerts (e.g. DLP), JSON/JSONL, XML, CSV/TSV. Timestamps without a year (syslog) use the current year. For CSV a timestamp column is required; recommended columns: `timestamp, event_type, source_ip, user, action, details, host, event_id` (common aliases such as `time`, `message`, `ip`, `username` are recognised). Max 25 MB per file. Timestamps with a timezone are converted to UTC; timestamps without one are treated as UTC.

`forensix_sample_logs.csv` and the `sample_security_logs/` folder (10 files, 10 formats) are synthetic incidents for testing. Select all files in that folder at once to see the full reconstructed story.

## Detection

`detect.py` flags brute force, external root login, credential-file access, MFA disabled, account creation, privilege assignment, web-file tampering, log deletion, web exploit patterns, bulk exports/queries, large outbound transfers, DLP alerts, encoded PowerShell, rundll32 from temp folders and persistence from /tmp. It then links events by shared IP/host/user and builds a time-ordered narrative. Every finding lists its evidence IDs.

## Notes

- Loaded logs are held in server memory for the signed-in session (cleared on sign-out/restart).
- Set `FLASK_DEBUG=1` only for development. For deployment use a production WSGI server and HTTPS.
- Analysis is rule-based and indicators require human validation.
