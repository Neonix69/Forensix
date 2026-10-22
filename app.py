"""FORENSIX AI - Flask app: login-protected incident timeline reconstruction.

Accounts are created only in the backend:
  * the /admin page (admin users only), or
  * the command line:  flask --app app create-user <username> [--admin]
"""
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

import click
import pandas as pd
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "forensix.db")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024          # whole request
MAX_FILE_BYTES = 25 * 1024 * 1024                              # per file
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)


def _load_secret_key():
    env = os.environ.get("FORENSIX_SECRET_KEY")
    if env:
        return env
    path = os.path.join(INSTANCE_DIR, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path) as fh:
        return fh.read().strip()


app.secret_key = _load_secret_key()

# --------------------------------------------------------------------------- #
# Database / users
# --------------------------------------------------------------------------- #

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL)""")
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            username = os.environ.get("FORENSIX_ADMIN_USER", "admin")
            password = os.environ.get("FORENSIX_ADMIN_PASSWORD")
            generated = password is None
            if generated:
                password = secrets.token_urlsafe(12)
            db.execute("INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,1,?)",
                       (username, generate_password_hash(password), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")))
            print("\n" + "=" * 62)
            print(" FORENSIX: first run - administrator account created")
            print(f"   username: {username}")
            print(f"   password: {password}" + ("   (generated - change it in /admin)" if generated else ""))
            print("   Sign in, then open /admin to create analyst accounts.")
            print("=" * 62 + "\n")


init_db()
print(f"[FORENSIX] User database: {DB_PATH}")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def validate_new_credentials(username, password):
    if not USERNAME_RE.match(username or ""):
        return "Username must be 3-32 characters: letters, numbers, dot, dash or underscore."
    if len(password or "") < 8:
        return "Password must be at least 8 characters."
    return None


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    if "user" not in g:
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return g.user


@app.cli.command("create-user")
@click.argument("username")
@click.option("--admin", is_flag=True, help="Give this user access to /admin.")
@click.password_option()
def cli_create_user(username, admin, password):
    """Create a user from the command line."""
    err = validate_new_credentials(username, password)
    if err:
        raise click.ClickException(err)
    try:
        with sqlite3.connect(DB_PATH) as db:
            db.execute("INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
                       (username, generate_password_hash(password), int(admin), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")))
    except sqlite3.IntegrityError:
        raise click.ClickException("That username already exists.")
    click.echo(f"Created {'admin' if admin else 'analyst'} user '{username}'.")


@app.cli.command("reset-password")
@click.argument("username", required=False)
@click.password_option(prompt="New password", confirmation_prompt=True)
def cli_reset_password(username, password):
    """Reset a user's password without deleting their account."""
    if len(password) < 8:
        raise click.ClickException("Password must be at least 8 characters.")
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        if username:
            row = db.execute("SELECT id, username FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()
        else:
            rows = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()
            if not rows:
                raise click.ClickException("No accounts exist in this database. Start the app once to initialize it.")
            click.echo("Accounts in this project's database:")
            for item in rows:
                click.echo(f"  - {item['username']}")
            username = click.prompt("Username to reset")
            row = db.execute("SELECT id, username FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()
        if not row:
            raise click.ClickException("That username was not found in this project's database.")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), row["id"]))
    click.echo(f"Password updated for '{row['username']}'.")
    click.echo(f"Database used: {DB_PATH}")


# --------------------------------------------------------------------------- #
# Auth plumbing: login gate, CSRF, brute-force throttle
# --------------------------------------------------------------------------- #

PUBLIC_ENDPOINTS = {"login", "static"}
_fail_lock = threading.Lock()
_failures = {}          # key -> (count, first_ts)
MAX_FAILS, LOCK_SECONDS = 10, 180


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def gate():
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Your session expired. Refresh the page and try again."}), 400
            abort(400, "Invalid or missing CSRF token. Go back, refresh and try again.")
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return None
    if current_user() is None:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"error": "Please sign in again."}), 401
        return redirect(url_for("login", next=request.full_path.rstrip("?")))
    return None


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if u is None:
            return redirect(url_for("login", next=request.path))
        if not u["is_admin"]:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def safe_next(target):
    if not target:
        return url_for("index")
    p = urlparse(target)
    if p.scheme or p.netloc or not target.startswith("/") or target.startswith("//"):
        return url_for("index")
    return target


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = f"{request.remote_addr}|{username.lower()}"
        now = time.time()
        with _fail_lock:
            count, first = _failures.get(key, (0, now))
            if now - first > LOCK_SECONDS:
                count, first = 0, now
            locked = count >= MAX_FAILS
        if locked:
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            row = get_db().execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
            ok = bool(row) and check_password_hash(row["password_hash"], password)
            if ok:
                with _fail_lock:
                    _failures.pop(key, None)
                session.clear()
                session.permanent = True
                session["uid"] = row["id"]
                csrf_token()
                return redirect(safe_next(request.args.get("next")))
            with _fail_lock:
                _failures[key] = (count + 1, first)
            error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    uid = session.get("uid")
    if uid:
        with WS_LOCK:
            WORKSPACES.pop(uid, None)
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# /admin  (the only place new accounts can be registered through the web)
# --------------------------------------------------------------------------- #

@app.route("/admin")
@admin_required
def admin():
    users = get_db().execute("SELECT id,username,is_admin,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users, me=current_user())


@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    is_admin = 1 if request.form.get("role") == "admin" else 0
    err = validate_new_credentials(username, password)
    if err:
        flash(err, "error")
    else:
        try:
            db = get_db()
            db.execute("INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
                       (username, generate_password_hash(password), is_admin, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")))
            db.commit()
            flash(f"User '{username}' created.", "ok")
        except sqlite3.IntegrityError:
            flash("That username already exists.", "error")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:uid>/password", methods=["POST"])
@admin_required
def admin_reset_password(uid):
    password = request.form.get("password") or ""
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
    else:
        db = get_db()
        cur = db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), uid))
        db.commit()
        flash("Password updated." if cur.rowcount else "User not found.", "ok" if cur.rowcount else "error")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        flash("User not found.", "error")
    elif target["id"] == current_user()["id"]:
        flash("You cannot delete your own account.", "error")
    else:
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
        with WS_LOCK:
            WORKSPACES.pop(uid, None)
        flash(f"User '{target['username']}' deleted.", "ok")
    return redirect(url_for("admin"))


# --------------------------------------------------------------------------- #
# Log normalization (format-specific parsing lives in parsers.py, rules in detect.py)
# --------------------------------------------------------------------------- #

import parsers
import detect
from parsers import COLS, OUT_COLS

ALLOWED_EXT = {".csv", ".tsv", ".txt", ".log", ".json", ".jsonl", ".ndjson", ".xml"}


def normalize(df, pre_skipped, fid):
    """Sort, drop rows with no readable timestamp, assign ids. -> (df, skipped rows)."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in COLS[1:] + ["raw"]:
        df[col] = df[col].fillna("").astype(str)
    total = len(df)
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    if df.empty:
        raise ValueError("None of the records had a readable timestamp.")
    missing = df["event_id"].str.strip().eq("")
    df.loc[missing, "event_id"] = [f"F{fid}-EV-{i:03d}" for i in range(1, int(missing.sum()) + 1)]
    return df[OUT_COLS].copy(), total - len(df)


# --------------------------------------------------------------------------- #
# Per-user workspace (loaded files live in memory for the signed-in session)
# --------------------------------------------------------------------------- #

WS_LOCK = threading.Lock()
WORKSPACES = {}          # uid -> {"next": int, "files": [ {...meta..., "df": DataFrame} ]}
MAX_EVENTS_RETURNED = 5000


def workspace(uid):
    return WORKSPACES.setdefault(uid, {"next": 1, "files": []})


def combined(ws):
    frames = []
    for f in ws["files"]:
        d = f["df"].copy()
        d["source_file"] = f["name"]
        d["_fid"] = f["id"]
        frames.append(d)
    if not frames:
        return None
    df = pd.concat(frames, ignore_index=True).sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    seen, ids = set(), []
    for eid, fid in zip(df["event_id"], df["_fid"]):
        new = eid
        if new in seen:
            new = f"{eid}@F{fid}"
            n = 2
            while new in seen:
                new = f"{eid}@F{fid}-{n}"
                n += 1
        seen.add(new)
        ids.append(new)
    df["event_id"] = ids
    return df.drop(columns="_fid")


def build_state(uid):
    ws = workspace(uid)
    files = [{k: v for k, v in f.items() if k != "df"} for f in ws["files"]]
    df = combined(ws)
    if df is None:
        return {"files": [], "total": 0, "findings": [], "story": [], "events": [], "source": "", "summary": "", "first": "", "last": ""}
    df = detect.enrich(df)
    findings, story = detect.analyze(df)
    shown = df.head(MAX_EVENTS_RETURNED).copy()
    shown["timestamp"] = shown["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    shown["flagged"] = shown["severity"] >= 1
    shown["tags"] = shown["tags"].apply(lambda t: ", ".join(t))
    names = ", ".join(f["name"] for f in files)
    return {
        "files": files,
        "source": names,
        "total": int(len(df)),
        "truncated": len(df) > MAX_EVENTS_RETURNED,
        "findings": findings,
        "story": story,
        "events": shown.fillna("").to_dict(orient="records"),
        "first": df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
        "last": df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": f"Reviewed {len(df)} timestamped records from {len(files)} file(s) and flagged {len(findings)} sequence(s) for human review. These are rule-based indicators, not proof of an attack.",
    }


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/api/state")
def api_state():
    with WS_LOCK:
        return jsonify(build_state(session["uid"]))


@app.route("/api/load", methods=["POST"])
def api_load():
    """Add one or more log files. mode=add (default) keeps existing files, mode=replace clears first."""
    uid = session["uid"]
    mode = request.form.get("mode", "add")
    uploads = [f for f in request.files.getlist("files") if f and f.filename]
    if not uploads:
        return jsonify({"error": "No file was received. Choose one or more log files and try again."}), 400

    parsed, errors = [], []
    for up in uploads:
        name = os.path.basename(up.filename)
        ext = os.path.splitext(name.lower())[1]
        if ext not in ALLOWED_EXT:
            errors.append({"name": name, "error": f"Unsupported file type '{ext or 'none'}'. Use CSV, TSV, JSON, JSONL, XML, LOG or TXT."})
            continue
        raw = up.read()
        if len(raw) > MAX_FILE_BYTES:
            errors.append({"name": name, "error": f"File is larger than {MAX_FILE_BYTES // 1024 // 1024} MB."})
            continue
        parsed.append((name, len(raw), raw))

    ready = []
    for name, size, raw in parsed:
        try:
            raw_df, pre = parsers.parse_file(name, raw)
            ready.append((name, size, (raw_df, pre)))
        except Exception as e:  # report the real reason to the user
            errors.append({"name": name, "error": str(e)})

    loaded = []
    with WS_LOCK:
        ws = workspace(uid)
        staged = []
        for name, size, (raw_df, pre) in ready:
            fid = ws["next"] + len(staged)
            try:
                df, skipped = normalize(raw_df, pre, fid)
            except Exception as e:
                errors.append({"name": name, "error": str(e)})
                continue
            staged.append({"id": fid, "name": name, "size": size, "records": int(len(df)), "skipped": int(skipped),
                           "first": df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S"),
                           "last": df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"),
                           "loaded_at": datetime.now().strftime("%H:%M:%S"), "df": df})
        if staged:
            if mode == "replace":
                ws["files"] = []
            ws["files"].extend(staged)
            ws["next"] = max(s["id"] for s in staged) + 1
            loaded = [s["name"] for s in staged]
        state = build_state(uid)
    state["loaded"] = loaded
    state["errors"] = errors
    if not loaded:
        state["error"] = "; ".join(f"{e['name']}: {e['error']}" for e in errors) or "Nothing could be loaded."
        return jsonify(state), 400
    return jsonify(state)


@app.route("/api/files/<int:fid>/remove", methods=["POST"])
def api_remove_file(fid):
    uid = session["uid"]
    with WS_LOCK:
        ws = workspace(uid)
        ws["files"] = [f for f in ws["files"] if f["id"] != fid]
        return jsonify(build_state(uid))


@app.route("/api/clear", methods=["POST"])
def api_clear():
    uid = session["uid"]
    with WS_LOCK:
        WORKSPACES[uid] = {"next": 1, "files": []}
        return jsonify(build_state(uid))


@app.route("/api/report", methods=["POST"])
def report():
    with WS_LOCK:
        data = build_state(session["uid"])
    if not data["files"]:
        return jsonify({"error": "Load at least one log file first."}), 400
    lines = ["# FORENSIX / Investigation Brief", "",
             "Evidence files: " + ", ".join(f"{f['name']} ({f['records']} records)" for f in data["files"]),
             f"Records reviewed: {data['total']}", f"Evidence window: {data['first']} to {data['last']}",
             f"Potential indicators: {len(data['findings'])}", "", "## Analyst summary", data["summary"], "", "## Findings"]
    for i, f in enumerate(data["findings"], 1):
        lines += [f"### {i}. {f['title']} ({f['level'].upper()})", f["plain"], f"Why it matters: {f['why']}",
                  "Evidence IDs: " + ", ".join(f["events"]), " "]
    lines += ["", "Note: Automated indicators require human validation."]
    buf = io.BytesIO("\n".join(lines).encode("utf-8"))
    return send_file(buf, as_attachment=True, download_name="forensix-investigation-brief.md", mimetype="text/markdown")


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "Upload too large (limit 100 MB per request, 25 MB per file)."}), 413


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
