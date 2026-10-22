"""Multi-format log parsing: every input is turned into a list of records
   {ts, fields, message, fmt} and then into one normalized DataFrame."""
import csv
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import pandas as pd

COLS = ["timestamp", "event_type", "source_ip", "user", "action", "details", "host", "event_id"]
OUT_COLS = COLS + ["raw"]

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
TIME_KEYS = ["timestamp", "time", "timecreated", "time_created", "event_time", "eventtime", "datetime",
             "date_time", "@timestamp", "created_at", "ts", "date", "utctime", "systemtime"]

ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|UTC|[+-]\d{2}:?\d{2}))?")
CLF_RE = re.compile(r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}")
SYS_RE = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\b")
KV_RE = re.compile(r'([A-Za-z_@][\w.\-]*)=("(?:[^"\\]|\\.)*"|[^\s|]+)')
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KEYLINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_\-. ]{0,30}?)\s*(?:=|:(?!\d\d))\s*(.*)$")


def _norm_key(k):
    return re.sub(r"[^a-z0-9@]+", "_", str(k).strip().lower()).strip("_")


def _naive_utc(ts):
    if ts is None or pd.isna(ts):
        return None
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.to_pydatetime() if hasattr(ts, "to_pydatetime") else ts


def syslog_ts(mon, day, hms):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        t = datetime.strptime(f"{now.year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    if t > now + timedelta(days=1):           # e.g. a December log read in January
        t = t.replace(year=now.year - 1)
    return t


def parse_ts(value):
    """Parse a single timestamp string / number into naive UTC datetime (or None)."""
    if value is None:
        return None
    s = str(value).strip().strip('"')
    if not s:
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", s):
        x = float(s)
        x = x / 1000 if x > 1e11 else x
        return datetime.fromtimestamp(x, timezone.utc).replace(tzinfo=None)
    if CLF_RE.fullmatch(s):
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).replace(tzinfo=None)
    m = SYS_RE.fullmatch(s)
    if m:
        return syslog_ts(*m.groups())
    try:
        t = pd.to_datetime(s.replace(",", ".").replace(" UTC", "Z"), utc=True, errors="coerce")
    except Exception:
        return None
    return None if pd.isna(t) else _naive_utc(t)


def find_ts(text):
    """First timestamp found anywhere in text -> (datetime, (start,end)) or (None,None)."""
    best = None
    for rx in (ISO_RE, CLF_RE):
        m = rx.search(text)
        if m and (best is None or m.start() < best[0].start()):
            best = (m, rx)
    m = SYS_RE.search(text)
    if m and m.group(1) in MONTHS and (best is None or m.start() < best[0].start()):
        best = (m, SYS_RE)
    if not best:
        return None, None
    m = best[0]
    t = parse_ts(m.group(0))
    return (t, m.span()) if t else (None, None)


def kv_pairs(text):
    out = {}
    for k, v in KV_RE.findall(text):
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[_norm_key(k)] = v.rstrip(";,")
    return out


def pick_time(fields):
    for k in TIME_KEYS:
        if k in fields and str(fields[k]).strip():
            t = parse_ts(fields[k])
            if t:
                return t
    for k, v in fields.items():                       # any "...time..." / "...date..." field
        if ("time" in k or "date" in k) and str(v).strip():
            t = parse_ts(v)
            if t:
                return t
    return None


# ---------------------------------------------------------------- line formats
CLF_LINE = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?')
RFC5424 = re.compile(r"^<\d+>\d?\s*(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w./\-]+?)(?:\[(\d+)\])?:\s*(.*)$")
SSH_RE = re.compile(r"(Accepted|Failed)\s+(\w+)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)(?:\s+port\s+(\d+))?")
SUDO_RE = re.compile(r"^\s*(\S+)\s*:\s*.*?COMMAND=(.*)$")


def parse_line(line):
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = CLF_LINE.match(line)
    if m:
        ip, user, ts, method, path, status, size, ref, ua = m.groups()
        t = parse_ts(ts)
        f = {"src_ip": ip, "method": method, "path": path, "status": status, "bytes": size if size != "-" else "0"}
        if user != "-":
            f["user"] = user
        if ua:
            f["user_agent"] = ua
        return {"ts": t, "fields": f, "message": f"{method} {path} -> HTTP {status} ({size} bytes)", "fmt": "web"}
    m = RFC5424.match(line)
    if m:
        ts, host, app, rest = m.groups()
        f = kv_pairs(rest)
        f.update({"host": host, "app": app})
        first = rest.split()[0].lower() if rest.split() else ""
        if first and "=" not in first:
            f["verdict"] = first
        return {"ts": parse_ts(ts), "fields": f, "message": f"{app} {rest}", "fmt": "firewall"}
    m = SYSLOG.match(line)
    if m:
        mon, day, hms, host, proc, pid, msg = m.groups()
        f = {"host": host, "process": proc}
        if pid:
            f["pid"] = pid
        s = SSH_RE.search(msg)
        if s:
            res, method, inv, user, ip, port = s.groups()
            f.update({"auth_result": res.lower(), "auth_method": method, "user": user, "src_ip": ip})
            if inv:
                f["invalid_user"] = "true"
            if port:
                f["port"] = port
        s = SUDO_RE.match(msg) if proc == "sudo" else None
        if s:
            f.update({"user": s.group(1), "command": s.group(2).strip()})
        return {"ts": syslog_ts(mon, day, hms), "fields": f, "message": msg, "fmt": "syslog"}
    f = kv_pairs(line)
    t, span = find_ts(line)
    if len(f) >= 2 or (f and t):
        t = pick_time(f) or t
        msg = f.get("message") or f.get("msg") or ""
        return {"ts": t, "fields": f, "message": msg, "fmt": "keyvalue"}
    if t:
        rest = (line[:span[0]] + " " + line[span[1]:]).strip(" []-:|,;")
        f = {}
        ip = IP_RE.search(rest)
        if ip:
            f["src_ip"] = ip.group(0)
        return {"ts": t, "fields": f, "message": rest, "fmt": "text"}
    return None


# ---------------------------------------------------------------- block formats
def is_keyline(line):
    return bool(KEYLINE_RE.match(line)) and len(KV_RE.findall(line)) <= 1 and "|" not in line


def parse_block(lines):
    f, header = {}, ""
    for ln in lines:
        m = KEYLINE_RE.match(ln)
        if not m:
            continue
        k, v = _norm_key(m.group(1)), m.group(2).strip().lstrip(":").strip()
        if k not in f:
            f[k] = v
        if not header:
            header = v
    t = pick_time(f)
    if not t:
        t, _ = find_ts("\n".join(lines))
    msg = f.get("message", "")
    return {"ts": t, "fields": f, "message": msg, "fmt": "block"}


def split_blocks(text):
    blocks, cur = [], []
    for ln in text.splitlines():
        if ln.strip():
            cur.append(ln)
        elif cur:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    return blocks


def looks_like_blocks(text):
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    key = sum(is_keyline(l) for l in lines)
    return key / len(lines) >= 0.6 and any(sum(is_keyline(l) for l in b) >= 2 for b in split_blocks(text))


# ---------------------------------------------------------------- structured
def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        out[prefix.rstrip(".")] = ", ".join(str(x) for x in obj) if all(not isinstance(x, (dict, list)) for x in obj) else json.dumps(obj)
    else:
        out[prefix.rstrip(".")] = "" if obj is None else str(obj)
    return out


def rec_from_fields(raw_fields, fmt):
    f = {_norm_key(k): str(v).strip() for k, v in raw_fields.items() if v is not None and str(v).strip() != ""}
    return {"ts": pick_time(f), "fields": f, "message": f.get("message") or f.get("msg") or "", "fmt": fmt}


def parse_xml(text):
    root = ET.fromstring(text.lstrip("﻿").strip())

    def strip(tag):
        return tag.split("}", 1)[-1]

    def leaf_fields(el):
        out = dict(el.attrib)
        for c in el.iter():
            if c is el:
                continue
            if len(c) == 0 and (c.text or "").strip():
                out[strip(c.tag)] = c.text.strip()
            out.update({f"{strip(c.tag)}_{a}": v for a, v in c.attrib.items()})
        return out

    kids = [c for c in root if len(c) > 0]
    recs = kids if len(kids) >= 1 and len(kids) == len(list(root)) else [root]
    return [rec_from_fields(leaf_fields(r), "xml") for r in recs]


def parse_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    raise ValueError(f"Line {i} is not valid JSON.")
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list) and v and isinstance(v[0], dict)]
        data = lists[0] if lists else [data]
    if not isinstance(data, list) or not data:
        raise ValueError("No JSON event records found.")
    return [rec_from_fields(flatten(d) if isinstance(d, dict) else {"message": d}, "json") for d in data]


def parse_csv(text, delimiter=None):
    sample = text[:4096]
    if delimiter is None:
        try:
            delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter, skipinitialspace=True)
    if not reader.fieldnames or len(reader.fieldnames) < 2:
        raise ValueError("No columns found. Is this a CSV with a header row?")
    return [rec_from_fields({k: v for k, v in row.items() if k}, "csv") for row in reader]


# ---------------------------------------------------------------- entry point
def decode(raw):
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            continue
    return raw.decode("latin-1")


def parse_records(name, raw):
    ext = os.path.splitext(name.lower())[1]
    text = decode(raw)
    if not text.strip():
        raise ValueError("The file is empty.")
    head = text.lstrip()[:200]
    if ext == ".xml" or head.startswith("<?xml") or (head.startswith("<") and not head.startswith("<1") and re.match(r"<[A-Za-z]", head)):
        try:
            return parse_xml(text)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML: {e}")
    if ext in (".json", ".jsonl", ".ndjson") or head[:1] in "[{" and ext not in (".log", ".txt"):
        return parse_json(text)
    if ext in (".csv", ".tsv"):
        return parse_csv(text, "\t" if ext == ".tsv" else None)
    first = text.lstrip().splitlines()[0]
    if first.count(",") >= 2 and re.search(r"time|date|ts", first, re.I) and "=" not in first and not parse_line(first):
        return parse_csv(text)                      # CSV hiding under .txt/.log
    if looks_like_blocks(text):
        recs = [parse_block(b) for b in split_blocks(text) if sum(is_keyline(l) for l in b) >= 2]
    else:
        recs = [r for r in (parse_line(l) for l in text.splitlines()) if r]
        if not recs:
            raise ValueError("No recognizable log lines (no timestamps found).")
    return recs


# ---------------------------------------------------------------- canonical columns
def first_of(fields, keys):
    for k in keys:
        v = fields.get(k)
        if v:
            return v
    return ""


IP_KEYS = ["src_ip", "source_ip", "src", "sourceaddress", "clientaddress", "client_ip", "remote_ip", "ipaddress", "ip_address", "ip", "source", "remote_addr", "from"]
USER_KEYS = ["user", "username", "user_name", "actor", "subjectusername", "account", "accountname", "principal", "targetusername", "target_user", "uid", "login"]
HOST_KEYS = ["host", "hostname", "computer", "computername", "endpoint", "device", "machine", "database", "node", "server"]
ID_KEYS = ["event_id", "record_id", "log_id", "request_id", "alert_id", "id", "eventrecordid"]
ACTION_KEYS = ["action", "event", "event_name", "eventname", "activity", "operation", "event_type", "type"]
DETAIL_SKIP = set(TIME_KEYS) | {"raw"}


def canonical_row(rec):
    f = rec["fields"]
    ip = first_of(f, IP_KEYS)
    if not IP_RE.fullmatch(ip or ""):
        found = IP_RE.search(rec["message"] or "") or IP_RE.search(" ".join(f.values()))
        ip = found.group(0) if found else ""
    user = first_of(f, USER_KEYS)
    host = first_of(f, HOST_KEYS)
    msg = rec["message"]
    if not msg:
        parts = [f"{k}={v}" for k, v in f.items() if k not in DETAIL_SKIP and k not in ID_KEYS][:14]
        msg = " · ".join(parts)
    elif rec["fmt"] in ("block", "json", "xml", "csv"):
        skip = DETAIL_SKIP | set(ID_KEYS) | {"message", "msg"}
        extra = [f"{k}={v}" for k, v in f.items() if k not in skip][:8]
        if extra:
            msg = msg + " · " + " · ".join(extra)
    elif rec["fmt"] in ("syslog", "firewall", "keyvalue"):
        extra = [f"{k}={v}" for k, v in f.items() if k in ("path", "command", "result", "bytes_out", "action", "rule")
                 and f"{k}={v}" not in msg]
        if extra and rec["fmt"] != "syslog":
            msg = msg + " · " + " · ".join(extra)
    return {
        "timestamp": rec["ts"], "event_type": f.get("event_type", ""),
        "source_ip": ip, "user": user, "action": first_of(f, ACTION_KEYS) if rec["fmt"] in ("csv", "json") else "",
        "details": msg[:600], "host": host, "event_id": first_of(f, ID_KEYS),
        "raw": json.dumps({"format": rec["fmt"], **f}, ensure_ascii=False),
    }


def parse_file(name, raw):
    """Return (DataFrame[OUT_COLS], rows_without_timestamp)."""
    recs = parse_records(name, raw)
    rows = [canonical_row(r) for r in recs]
    df = pd.DataFrame(rows, columns=OUT_COLS)
    missing = int(df["timestamp"].isna().sum())
    return df, missing
